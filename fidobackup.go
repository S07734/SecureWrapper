package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// FIDO2-protected backup: AES-256-GCM where the key is derived from BOTH a
// password (Argon2id-stretched) and the hmac-secret output of a hardware
// security key (full-entropy, needs no stretching), combined via
// HKDF-SHA256. Neither factor alone can decrypt. No machine fingerprint and
// no binary hash — this is the disaster-recovery format: it must survive
// machine death, so the physical key IS the hardware factor.

const (
	fidoBackupFileName = "vault.fido2.backup"
	fidoBackupMagic    = "SWFIDO1"
	fidoBackupVersion  = uint8(1)
	fidoKDFInfo        = "securewrapper/fido2-backup/v1"
)

// FIDOBackupFile is the on-disk format. Every field except Data is bound
// into the AES-GCM AAD — tampering with any of them fails authentication.
type FIDOBackupFile struct {
	Magic        string      `json:"magic"`
	Version      uint8       `json:"version"`
	Header       VaultHeader `json:"header"`        // display metadata; BinaryFP = "fido2"
	RPID         string      `json:"rp_id"`         // relying party ID used at enrollment
	CredentialID []byte      `json:"credential_id"` // non-resident credential (public, wraps key material)
	HMACSalt     []byte      `json:"hmac_salt"`     // salt sent to the authenticator's hmac-secret
	KDFSalt      []byte      `json:"kdf_salt"`      // Argon2id + HKDF salt
	UV           bool        `json:"uv"`            // whether user verification was performed at export
	Data         []byte      `json:"data"`          // nonce-prefixed AES-GCM ciphertext
}

type fidoBackupPayload struct {
	ExportedAt string    `json:"exported_at"`
	VaultData  VaultData `json:"vault_data"`
}

func fidoBackupPath() string {
	return filepath.Join(vaultDirPath(), fidoBackupFileName)
}

// FIDOBackupExists reports whether a FIDO2 backup is present in the vault dir.
func FIDOBackupExists() bool {
	_, err := os.Stat(fidoBackupPath())
	return err == nil
}

// ReadFIDOBackupHeader returns the display header, or nil if none/corrupt.
func ReadFIDOBackupHeader() *VaultHeader {
	f, err := loadFIDOBackup()
	if err != nil {
		return nil
	}
	return &f.Header
}

func loadFIDOBackup() (*FIDOBackupFile, error) {
	raw, err := os.ReadFile(fidoBackupPath())
	if err != nil {
		return nil, fmt.Errorf("cannot read FIDO2 backup: %w", err)
	}
	var f FIDOBackupFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("FIDO2 backup corrupted: %w", err)
	}
	if f.Magic != fidoBackupMagic {
		return nil, fmt.Errorf("not a FIDO2 backup file (magic=%q)", f.Magic)
	}
	if f.Version != fidoBackupVersion {
		return nil, fmt.Errorf("unsupported FIDO2 backup version %d", f.Version)
	}
	return &f, nil
}

// deriveFIDOBackupKey combines the password and the authenticator's
// hmac-secret output into the AES key. The password is the low-entropy
// factor and gets the same Argon2id stretching as the vault; the hmac
// output is full-entropy. HKDF binds the two with domain separation.
func deriveFIDOBackupKey(password string, hmacOut, kdfSalt []byte) []byte {
	kpw := argon2.IDKey([]byte(password), kdfSalt, 3, 64*1024, 4, 32)
	ikm := make([]byte, 0, len(kpw)+len(hmacOut))
	ikm = append(ikm, kpw...)
	ikm = append(ikm, hmacOut...)
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, kdfSalt, []byte(fidoKDFInfo)), key); err != nil {
		// hkdf.Reader for 32 bytes cannot fail; guard anyway.
		panic("hkdf: " + err.Error())
	}
	zeroBytes(kpw)
	zeroBytes(ikm)
	return key
}

// fidoBackupAAD binds every header field into the GCM AAD. The file struct
// with Data stripped marshals deterministically (Go encodes struct fields
// in declaration order), giving a canonical byte encoding of the header.
func fidoBackupAAD(f FIDOBackupFile) []byte {
	f.Data = nil
	aad, err := json.Marshal(f)
	if err != nil {
		panic("marshal AAD: " + err.Error()) // struct of plain types cannot fail
	}
	return aad
}

// ExportFIDOBackup enrolls a fresh credential on the connected security key
// and writes an encrypted backup of the full vault (connections + auth
// keys). Requires two touches: one for enrollment, one for the assertion
// that produces the encryption secret. progress (optional) receives
// human-readable step updates for the TUI.
//
// The password becomes the vault passphrase on restore, so it must satisfy
// the same policy.
func (v *Vault) ExportFIDOBackup(password, pin string, prov fido2Provider, progress func(string)) (string, error) {
	if v.passphrase == "" {
		return "", fmt.Errorf("FIDO2 backup export requires an admin (passphrase) session")
	}
	if err := ValidatePassphrase(password); err != nil {
		return "", fmt.Errorf("backup password: %w", err)
	}
	note := func(s string) {
		if progress != nil {
			progress(s)
		}
	}

	note("Touch your security key to enroll a backup credential...")
	credID, err := prov.Enroll(pin)
	if err != nil {
		return "", fmt.Errorf("enroll credential: %w", err)
	}

	hmacSalt := make([]byte, 32)
	kdfSalt := make([]byte, saltSize)
	if _, err := rand.Read(hmacSalt); err != nil {
		return "", err
	}
	if _, err := rand.Read(kdfSalt); err != nil {
		return "", err
	}

	note("Touch your security key again to derive the backup secret...")
	hmacOut, uv, err := prov.Secret(credID, hmacSalt, pin)
	if err != nil {
		return "", fmt.Errorf("hmac-secret assertion: %w", err)
	}
	if len(hmacOut) < 32 {
		return "", fmt.Errorf("authenticator returned a short hmac-secret output (%d bytes)", len(hmacOut))
	}

	payload := fidoBackupPayload{
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
		VaultData:  v.data,
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	f := FIDOBackupFile{
		Magic:   fidoBackupMagic,
		Version: fidoBackupVersion,
		Header: VaultHeader{
			Version:         version,
			BinaryFP:        "fido2",
			MachineFP:       ShortFingerprint(),
			CreatedAt:       v.createdAt,
			LastSaved:       time.Now().Format("2006-01-02 15:04:05"),
			ConnectionCount: len(v.data.Connections),
			AuthKeyCount:    len(v.data.AuthKeys),
		},
		RPID:         fidoRPID,
		CredentialID: credID,
		HMACSalt:     hmacSalt,
		KDFSalt:      kdfSalt,
		UV:           uv,
	}

	key := deriveFIDOBackupKey(password, hmacOut, kdfSalt)
	ciphertext, err := encryptWithAAD(plaintext, key, fidoBackupAAD(f))
	zeroBytes(key)
	zeroBytes(hmacOut)
	zeroBytes(plaintext)
	if err != nil {
		return "", err
	}
	f.Data = ciphertext

	out, err := json.Marshal(f)
	if err != nil {
		return "", err
	}
	path := fidoBackupPath()
	if err := os.WriteFile(path, out, 0600); err != nil {
		return "", fmt.Errorf("write FIDO2 backup: %w", err)
	}
	return path, nil
}

// RestoreFIDOBackup decrypts the FIDO2 backup using the password + the
// enrolled security key, then saves it as the active vault re-keyed to the
// CURRENT machine + binary. The backup password becomes the vault
// passphrase. Overwrites any existing vault — callers confirm first.
//
// Auth keys are restored but their derived entries are bound to the machine
// fingerprint at creation time — on different hardware they must be
// regenerated.
func RestoreFIDOBackup(password, pin string, prov fido2Provider) (*Vault, error) {
	f, err := loadFIDOBackup()
	if err != nil {
		return nil, err
	}

	hmacOut, _, err := prov.Secret(f.CredentialID, f.HMACSalt, pin)
	if err != nil {
		return nil, fmt.Errorf("hmac-secret assertion (is the enrolled security key connected?): %w", err)
	}

	key := deriveFIDOBackupKey(password, hmacOut, f.KDFSalt)
	plaintext, err := decryptWithAAD(f.Data, key, fidoBackupAAD(*f))
	zeroBytes(key)
	zeroBytes(hmacOut)
	if err != nil {
		return nil, fmt.Errorf("decryption failed — wrong password, wrong security key, or tampered backup")
	}

	var payload fidoBackupPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		zeroBytes(plaintext)
		return nil, fmt.Errorf("backup payload corrupted: %w", err)
	}
	zeroBytes(plaintext)

	fp, err := MachineFingerprint()
	if err != nil {
		return nil, fmt.Errorf("cannot generate machine fingerprint: %w", err)
	}
	data := payload.VaultData
	data.Fingerprint = fp

	// Safety net: keep a raw copy of any live vault before overwriting it,
	// mirroring the hardware-migration import path.
	if VaultExists() {
		if err := BackupVault(); err != nil {
			return nil, fmt.Errorf("cannot back up existing vault before restore: %w", err)
		}
	}

	vault := &Vault{
		path:       vaultPath(),
		passphrase: password,
		data:       data,
		createdAt:  f.Header.CreatedAt,
	}
	if err := vault.Save(); err != nil {
		return nil, fmt.Errorf("save restored vault: %w", err)
	}
	return vault, nil
}
