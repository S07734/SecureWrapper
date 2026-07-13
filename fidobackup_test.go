package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"os"
	"testing"
)

// fakeFIDO2Provider mirrors real authenticator hmac-secret behavior: each
// enrolled credential gets a random CredRandom, and Secret returns
// HMAC-SHA256(CredRandom, salt) — exactly what a CTAP2 authenticator
// computes. This validates the full KDF/format path without hardware.
type fakeFIDO2Provider struct {
	creds  map[string][]byte // credID -> CredRandom
	uv     bool
	failed bool // simulate "no device / wrong device"
}

func newFakeFIDO2() *fakeFIDO2Provider {
	return &fakeFIDO2Provider{creds: make(map[string][]byte)}
}

func (f *fakeFIDO2Provider) Enroll(pin string) ([]byte, error) {
	credID := make([]byte, 32)
	credRandom := make([]byte, 32)
	rand.Read(credID)
	rand.Read(credRandom)
	f.creds[string(credID)] = credRandom
	return credID, nil
}

func (f *fakeFIDO2Provider) Secret(credID, salt []byte, pin string) ([]byte, bool, error) {
	if f.failed {
		return nil, false, os.ErrNotExist
	}
	credRandom, ok := f.creds[string(credID)]
	if !ok {
		return nil, false, errFIDO2PINRequired // any error works; unknown cred
	}
	mac := hmac.New(sha256.New, credRandom)
	mac.Write(salt)
	return mac.Sum(nil), f.uv, nil
}

func testVaultWithConns(t *testing.T, passphrase string) *Vault {
	t.Helper()
	os.RemoveAll(vaultPath())
	v, err := CreateVault(passphrase)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	v.AddConnection(Connection{Name: "srv1", Type: ConnSSHPassword, Host: "10.0.0.1", Port: 22, Username: "root", Password: "hunter2"})
	v.AddConnection(Connection{Name: "api1", Type: ConnAPI, BaseURL: "https://x", AuthType: "bearer", AuthValue: "tok"})
	if err := v.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return v
}

const fidoTestPassword = "Correct-Horse-9-Battery!"

func TestFIDOBackup_RoundTrip(t *testing.T) {
	v := testVaultWithConns(t, "Vault-Passphrase-77!x")
	fake := newFakeFIDO2()

	path, err := v.ExportFIDOBackup(fidoTestPassword, "", fake, nil)
	if err != nil {
		t.Fatalf("ExportFIDOBackup: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("backup file missing: %v", err)
	}

	// Simulate total machine loss: vault gone, only backup + key + password.
	os.RemoveAll(vaultPath())

	restored, err := RestoreFIDOBackup(fidoTestPassword, "", fake)
	if err != nil {
		t.Fatalf("RestoreFIDOBackup: %v", err)
	}
	conns := restored.ListConnections()
	if len(conns) != 2 {
		t.Fatalf("expected 2 connections, got %d", len(conns))
	}
	if c := restored.GetConnection("srv1"); c == nil || c.Password != "hunter2" {
		t.Fatal("srv1 not restored intact")
	}

	// Restored vault must reopen with the backup password as passphrase.
	if _, err := OpenVault(fidoTestPassword); err != nil {
		t.Fatalf("restored vault does not open with backup password: %v", err)
	}
}

func TestFIDOBackup_WrongPasswordFails(t *testing.T) {
	v := testVaultWithConns(t, "Vault-Passphrase-77!x")
	fake := newFakeFIDO2()
	if _, err := v.ExportFIDOBackup(fidoTestPassword, "", fake, nil); err != nil {
		t.Fatalf("export: %v", err)
	}
	os.RemoveAll(vaultPath())
	if _, err := RestoreFIDOBackup("Wrong-Password-123!", "", fake); err == nil {
		t.Fatal("restore with wrong password must fail")
	}
}

func TestFIDOBackup_WrongKeyFails(t *testing.T) {
	v := testVaultWithConns(t, "Vault-Passphrase-77!x")
	fake := newFakeFIDO2()
	if _, err := v.ExportFIDOBackup(fidoTestPassword, "", fake, nil); err != nil {
		t.Fatalf("export: %v", err)
	}
	os.RemoveAll(vaultPath())

	// A different security key: same credential ID namespace lookup fails,
	// simulate by swapping the CredRandom under the enrolled credential.
	for id := range fake.creds {
		other := make([]byte, 32)
		rand.Read(other)
		fake.creds[id] = other
	}
	if _, err := RestoreFIDOBackup(fidoTestPassword, "", fake); err == nil {
		t.Fatal("restore with a different security key must fail")
	}
}

func TestFIDOBackup_TamperedHeaderFails(t *testing.T) {
	v := testVaultWithConns(t, "Vault-Passphrase-77!x")
	fake := newFakeFIDO2()
	path, err := v.ExportFIDOBackup(fidoTestPassword, "", fake, nil)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	os.RemoveAll(vaultPath())

	raw, _ := os.ReadFile(path)
	var f FIDOBackupFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Tamper with the stored HMAC salt — AAD binding must reject it even
	// though the ciphertext itself is untouched.
	f.HMACSalt[0] ^= 0xFF
	out, _ := json.Marshal(f)
	os.WriteFile(path, out, 0600)

	if _, err := RestoreFIDOBackup(fidoTestPassword, "", fake); err == nil {
		t.Fatal("tampered hmac salt must fail decryption")
	}
}

func TestFIDOBackup_UVMismatchFails(t *testing.T) {
	v := testVaultWithConns(t, "Vault-Passphrase-77!x")
	fake := newFakeFIDO2()
	fake.uv = false
	if _, err := v.ExportFIDOBackup(fidoTestPassword, "", fake, nil); err != nil {
		t.Fatalf("export: %v", err)
	}
	os.RemoveAll(vaultPath())

	// Different UV state → real authenticators use a different CredRandom.
	// Fake models this by keying the HMAC differently when uv flips.
	for id, cr := range fake.creds {
		mac := hmac.New(sha256.New, cr)
		mac.Write([]byte("uv-variant"))
		fake.creds[id] = mac.Sum(nil)
	}
	fake.uv = true
	if _, err := RestoreFIDOBackup(fidoTestPassword, "", fake); err == nil {
		t.Fatal("UV-mismatched hmac output must fail decryption")
	}
}

func TestFIDOBackup_WeakPasswordRejected(t *testing.T) {
	v := testVaultWithConns(t, "Vault-Passphrase-77!x")
	fake := newFakeFIDO2()
	if _, err := v.ExportFIDOBackup("short", "", fake, nil); err == nil {
		t.Fatal("weak backup password must be rejected by passphrase policy")
	}
}

func TestFIDOBackup_RequiresAdminSession(t *testing.T) {
	testVaultWithConns(t, "Vault-Passphrase-77!x")
	fake := newFakeFIDO2()
	readOnly := &Vault{path: vaultPath()} // no passphrase = operator session
	if _, err := readOnly.ExportFIDOBackup(fidoTestPassword, "", fake, nil); err == nil {
		t.Fatal("export must require an admin (passphrase) session")
	}
}

func TestFIDOBackup_ExistsAndHeader(t *testing.T) {
	v := testVaultWithConns(t, "Vault-Passphrase-77!x")
	fake := newFakeFIDO2()
	os.Remove(fidoBackupPath())
	if FIDOBackupExists() {
		t.Fatal("no backup should exist yet")
	}
	if _, err := v.ExportFIDOBackup(fidoTestPassword, "", fake, nil); err != nil {
		t.Fatalf("export: %v", err)
	}
	if !FIDOBackupExists() {
		t.Fatal("backup should exist after export")
	}
	h := ReadFIDOBackupHeader()
	if h == nil {
		t.Fatal("header unreadable")
	}
	if h.ConnectionCount != 2 {
		t.Fatalf("header connection count = %d, want 2", h.ConnectionCount)
	}
	if h.BinaryFP != "fido2" {
		t.Fatalf("header binary fp = %q, want fido2", h.BinaryFP)
	}
}

func TestDeriveFIDOBackupKey_BothFactorsRequired(t *testing.T) {
	kdfSalt := make([]byte, 32)
	hmacOut := make([]byte, 32)
	rand.Read(kdfSalt)
	rand.Read(hmacOut)

	base := deriveFIDOBackupKey("password-A", hmacOut, kdfSalt)

	// Different password → different key.
	if k := deriveFIDOBackupKey("password-B", hmacOut, kdfSalt); string(k) == string(base) {
		t.Fatal("key must depend on password")
	}
	// One flipped bit in the hmac output → different key.
	hmacOut[0] ^= 0x01
	if k := deriveFIDOBackupKey("password-A", hmacOut, kdfSalt); string(k) == string(base) {
		t.Fatal("key must depend on hmac-secret output")
	}
}
