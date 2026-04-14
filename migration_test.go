package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// migrationTestEnv sets up an isolated HOME and binary dir so tests never
// touch the real vault or write migration files into the Go build cache.
// Also stubs TrustedTime to a fixed value for deterministic fuse checks.
func migrationTestEnv(t *testing.T, now time.Time) {
	t.Helper()

	tmp := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmp)

	origDir := hwMigrationDir
	hwMigrationDir = func() string { return tmp }

	origTime := trustedTimeFn
	trustedTimeFn = func() (time.Time, error) { return now, nil }

	t.Cleanup(func() {
		os.Setenv("HOME", origHome)
		hwMigrationDir = origDir
		trustedTimeFn = origTime
	})
}

func TestGenerateMigrationCode_LengthAndAlphabet(t *testing.T) {
	for i := 0; i < 50; i++ {
		code, err := generateMigrationCode()
		if err != nil {
			t.Fatalf("generateMigrationCode: %v", err)
		}
		if len(code) != migrationCodeLen {
			t.Fatalf("expected length %d, got %d", migrationCodeLen, len(code))
		}
		for _, r := range code {
			if !strings.ContainsRune(migrationAlphabet, r) {
				t.Fatalf("unexpected character %q in code %q", r, code)
			}
		}
	}
}

func TestGenerateMigrationCode_Distinctness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		code, err := generateMigrationCode()
		if err != nil {
			t.Fatalf("generateMigrationCode: %v", err)
		}
		if seen[code] {
			t.Fatalf("duplicate code within 100 draws: %q (entropy bug?)", code)
		}
		seen[code] = true
	}
}

func TestFormatMigrationCode(t *testing.T) {
	got := formatMigrationCode("ABCDEFGHJ")
	want := "ABC-DEF-GHJ"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNormalizeMigrationCode(t *testing.T) {
	tests := []struct {
		in   string
		want string
		err  bool
	}{
		{"ABC-DEF-GHJ", "ABCDEFGHJ", false},
		{"abc-def-ghj", "ABCDEFGHJ", false},
		{"ABC DEF GHJ", "ABCDEFGHJ", false},
		{"ABCDEFGHJ", "ABCDEFGHJ", false},
		{"ABC-DEF", "", true},       // too short
		{"ABC-DEF-GHJK", "", true},  // too long
		{"ABC-DEF-GH0", "", true},   // 0 excluded from alphabet
		{"ABC-DEF-GHI", "", true},   // I excluded
	}
	for _, tc := range tests {
		got, err := normalizeMigrationCode(tc.in)
		if tc.err {
			if err == nil {
				t.Errorf("%q: expected error, got %q", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%q: got %q, want %q", tc.in, got, tc.want)
		}
	}
}

// testVaultWithConnections builds a live vault (saved to disk under the test
// HOME) containing the given connections, so export has something real to work with.
func testVaultWithConnections(t *testing.T, passphrase string, conns ...Connection) *Vault {
	t.Helper()
	v, err := CreateVault(passphrase)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	for _, c := range conns {
		v.AddConnection(c)
	}
	if err := v.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return v
}

func TestExportImport_Roundtrip(t *testing.T) {
	now := time.Now().UTC()
	migrationTestEnv(t, now)

	v := testVaultWithConnections(t, "source-pass",
		Connection{Name: "web", Type: ConnSSHPassword, Host: "10.0.0.1", Port: 22, Username: "u", Password: "p"},
		Connection{Name: "api", Type: ConnAPI, BaseURL: "https://api.example.com", AuthType: "key", AuthHeader: "X-K", AuthValue: "v"},
	)

	code, path, err := v.ExportHardwareMigration()
	if err != nil {
		t.Fatalf("ExportHardwareMigration: %v", err)
	}
	if len(code) != migrationCodeLen {
		t.Fatalf("export code length = %d, want %d", len(code), migrationCodeLen)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("migration file missing after export: %v", err)
	}

	// Simulate arrival at the destination machine: no vault exists there.
	os.Remove(vaultPath())

	imported, err := ImportHardwareMigration("source-pass", formatMigrationCode(code), "dest-pass")
	if err != nil {
		t.Fatalf("ImportHardwareMigration: %v", err)
	}
	conns := imported.ListConnections()
	if len(conns) != 2 {
		t.Fatalf("expected 2 connections, got %d", len(conns))
	}
	if imported.GetConnection("web").Password != "p" {
		t.Fatal("web password mismatch after roundtrip")
	}
	if imported.GetConnection("api").AuthValue != "v" {
		t.Fatal("api auth value mismatch after roundtrip")
	}

	// Migration file removed after successful import.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("migration file should be removed after import, stat err = %v", err)
	}

	// Re-open with the *new* passphrase on this machine.
	os.Remove(vaultPath())                 // force a clean reopen path
	if err := imported.Save(); err != nil { // write back under dest-pass
		t.Fatalf("save after import: %v", err)
	}
	if _, err := OpenVault("dest-pass"); err != nil {
		t.Fatalf("cannot reopen with new passphrase: %v", err)
	}
}

func TestImport_WrongCode(t *testing.T) {
	now := time.Now().UTC()
	migrationTestEnv(t, now)

	v := testVaultWithConnections(t, "pass",
		Connection{Name: "a", Type: ConnSSHPassword, Host: "h", Port: 22, Username: "u", Password: "p"},
	)
	_, _, err := v.ExportHardwareMigration()
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	os.Remove(vaultPath())

	_, err = ImportHardwareMigration("pass", "AAA-BBB-CCC", "")
	if err == nil {
		t.Fatal("import with wrong code should fail")
	}
	if !strings.Contains(err.Error(), "decryption failed") {
		t.Fatalf("expected decryption failure, got %v", err)
	}
}

func TestImport_WrongPassphrase(t *testing.T) {
	now := time.Now().UTC()
	migrationTestEnv(t, now)

	v := testVaultWithConnections(t, "right-pass",
		Connection{Name: "a", Type: ConnSSHPassword, Host: "h", Port: 22, Username: "u", Password: "p"},
	)
	code, _, err := v.ExportHardwareMigration()
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	os.Remove(vaultPath())

	_, err = ImportHardwareMigration("wrong-pass", code, "")
	if err == nil {
		t.Fatal("import with wrong passphrase should fail")
	}
}

func TestImport_TamperedExpiry(t *testing.T) {
	now := time.Now().UTC()
	migrationTestEnv(t, now)

	v := testVaultWithConnections(t, "pass",
		Connection{Name: "a", Type: ConnSSHPassword, Host: "h", Port: 22, Username: "u", Password: "p"},
	)
	code, path, err := v.ExportHardwareMigration()
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	os.Remove(vaultPath())

	// Extend the expiry on-disk — AAD binding should make this fail.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration file: %v", err)
	}
	var file HWMigrationFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	file.Expiry += 365 * 24 * 3600 // push out a year
	out, _ := json.Marshal(file)
	if err := os.WriteFile(path, out, 0600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	_, err = ImportHardwareMigration("pass", code, "")
	if err == nil {
		t.Fatal("tampered expiry should fail decryption")
	}
	if !strings.Contains(err.Error(), "decryption failed") {
		t.Fatalf("expected GCM auth failure, got %v", err)
	}
}

func TestImport_Expired(t *testing.T) {
	// Export at T0, attempt import at T0 + 25 hours.
	exportTime := time.Now().UTC()
	migrationTestEnv(t, exportTime)

	v := testVaultWithConnections(t, "pass",
		Connection{Name: "a", Type: ConnSSHPassword, Host: "h", Port: 22, Username: "u", Password: "p"},
	)
	code, _, err := v.ExportHardwareMigration()
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	os.Remove(vaultPath())

	// Fast-forward the trusted clock past the 24h fuse.
	trustedTimeFn = func() (time.Time, error) {
		return exportTime.Add(25 * time.Hour), nil
	}

	_, err = ImportHardwareMigration("pass", code, "")
	if err == nil {
		t.Fatal("expired migration should fail")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expiry error, got %v", err)
	}
}

func TestImport_UntrustedTime(t *testing.T) {
	migrationTestEnv(t, time.Now().UTC())

	v := testVaultWithConnections(t, "pass",
		Connection{Name: "a", Type: ConnSSHPassword, Host: "h", Port: 22, Username: "u", Password: "p"},
	)
	code, _, err := v.ExportHardwareMigration()
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	os.Remove(vaultPath())

	// Simulate no trusted time source.
	trustedTimeFn = func() (time.Time, error) {
		return time.Time{}, &timeErr{"simulated network failure"}
	}

	_, err = ImportHardwareMigration("pass", code, "")
	if err == nil {
		t.Fatal("missing trusted time should block import")
	}
	if !strings.Contains(err.Error(), "verify current time") {
		t.Fatalf("expected time-verification error, got %v", err)
	}
}

func TestImport_ExistingVaultBlocks(t *testing.T) {
	migrationTestEnv(t, time.Now().UTC())

	v := testVaultWithConnections(t, "pass",
		Connection{Name: "a", Type: ConnSSHPassword, Host: "h", Port: 22, Username: "u", Password: "p"},
	)
	code, _, err := v.ExportHardwareMigration()
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	// Intentionally leave vault.enc in place.

	_, err = ImportHardwareMigration("pass", code, "")
	if err == nil {
		t.Fatal("import onto existing vault should be refused")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected existing-vault error, got %v", err)
	}
}

func TestHardwareMigrationExists(t *testing.T) {
	migrationTestEnv(t, time.Now().UTC())

	if HardwareMigrationExists() {
		t.Fatal("no file yet — should be false")
	}

	// Drop a dummy file at the expected location.
	path := hwMigrationPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if !HardwareMigrationExists() {
		t.Fatal("file exists — should be true")
	}
}

type timeErr struct{ s string }

func (e *timeErr) Error() string { return e.s }
