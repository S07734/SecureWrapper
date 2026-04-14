package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// Hardware migration is a cross-machine vault transfer — passphrase-only at
// the crypto level, but protected by a one-time code displayed at export time
// and a 24-hour NTP-verified expiry fuse. Auth keys are NOT migrated: their
// vault entries are machine-bound, and moving plain tokens would weaken the
// threat model. Admin must regenerate auth keys on the target machine.

const (
	hwMigrationFileName = "vault.hwmigration"
	hwMigrationMagic    = "SWHWM1"
	hwMigrationVersion  = uint8(1)
	hwMigrationLifespan = 24 * time.Hour

	// Unambiguous alphabet — omits 0/O, 1/I/L to reduce transcription errors.
	// 31^9 ≈ 2.6×10^13 entropy, ample as a second factor to a passphrase.
	migrationAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
	migrationCodeLen  = 9
)

// HWMigrationFile is the on-disk format. Header fields (magic, version,
// expiry, salt) are bound into the AES-GCM AAD — tampering with any of them
// causes decryption to fail authentication.
type HWMigrationFile struct {
	Magic   string `json:"magic"`
	Version uint8  `json:"version"`
	Expiry  int64  `json:"expiry"` // Unix seconds
	Salt    []byte `json:"salt"`
	Data    []byte `json:"data"` // nonce-prefixed AES-GCM ciphertext
}

// hwMigrationPayload is what gets encrypted. Connections only — auth keys
// and machine-bound DerivedKey/VaultSalt fields are omitted.
type hwMigrationPayload struct {
	ExportedAt  string       `json:"exported_at"`
	Connections []Connection `json:"connections"`
}

// hwMigrationDir is the overridable directory used to locate the migration
// file. In production it resolves to the running binary's directory so the
// file travels with the binary. Tests swap this for a temp directory.
var hwMigrationDir = binaryDir

func binaryDir() string {
	exe, err := os.Executable()
	if err != nil {
		return vaultDirPath()
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err == nil {
		exe = resolved
	}
	return filepath.Dir(exe)
}

// hwMigrationPath returns the path next to the running binary, not the user's
// home dir. Rationale: hardware migration implies moving the binary between
// machines — the file should travel with it.
func hwMigrationPath() string {
	return filepath.Join(hwMigrationDir(), hwMigrationFileName)
}

// HardwareMigrationExists reports whether a migration file sits next to the
// running binary. Used by the launch flow to offer import on a fresh machine.
func HardwareMigrationExists() bool {
	_, err := os.Stat(hwMigrationPath())
	return err == nil
}

// generateMigrationCode returns a fresh one-time code drawn uniformly from
// migrationAlphabet. Uses crypto/rand via big.Int to avoid modulo bias.
func generateMigrationCode() (string, error) {
	max := big.NewInt(int64(len(migrationAlphabet)))
	out := make([]byte, migrationCodeLen)
	for i := range out {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = migrationAlphabet[n.Int64()]
	}
	return string(out), nil
}

// formatMigrationCode inserts dashes every 3 chars: "ABC-DEF-GHJ". Input must
// be exactly migrationCodeLen chars.
func formatMigrationCode(code string) string {
	if len(code) != migrationCodeLen {
		return code
	}
	return fmt.Sprintf("%s-%s-%s", code[0:3], code[3:6], code[6:9])
}

// normalizeMigrationCode strips dashes/spaces, uppercases, and validates the
// result. Returns the canonical 9-char form or an error if the input can't
// be a valid code (wrong length or contains characters outside the alphabet).
func normalizeMigrationCode(input string) (string, error) {
	cleaned := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(input))
	if len(cleaned) != migrationCodeLen {
		return "", fmt.Errorf("code must be %d characters (got %d after removing dashes)", migrationCodeLen, len(cleaned))
	}
	for _, r := range cleaned {
		if !strings.ContainsRune(migrationAlphabet, r) {
			return "", fmt.Errorf("invalid character %q — codes use only %s", r, migrationAlphabet)
		}
	}
	return cleaned, nil
}

// deriveMigrationKey derives the AES key from passphrase + one-time code.
// No machine fingerprint, no binary hash — migration MUST survive both.
func deriveMigrationKey(passphrase, code string, salt []byte) []byte {
	combined := passphrase + "|" + code + "|hwmigration"
	return argon2.IDKey([]byte(combined), salt, 3, 64*1024, 4, 32)
}

// migrationAAD returns the additional-authenticated-data bound into AES-GCM.
// Any tampering with magic, version, or expiry on disk causes Open() to fail.
func migrationAAD(magic string, version uint8, expiry int64, salt []byte) []byte {
	// Fixed-width binary encoding for deterministic reproduction on import.
	aad := make([]byte, 0, len(magic)+1+8+len(salt))
	aad = append(aad, []byte(magic)...)
	aad = append(aad, version)
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(expiry))
	aad = append(aad, b...)
	aad = append(aad, salt...)
	return aad
}

func encryptWithAAD(plaintext, key, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func decryptWithAAD(ciphertext, key, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := ciphertext[:nonceSize]
	body := ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, body, aad)
}

// ExportHardwareMigration writes a passphrase+code encrypted migration file
// next to the running binary and returns the freshly generated one-time code.
// The caller MUST display the code to the admin — it is not stored anywhere
// and cannot be recovered.
func (v *Vault) ExportHardwareMigration() (code string, path string, err error) {
	if v.passphrase == "" {
		return "", "", fmt.Errorf("hardware migration export requires an admin (passphrase) session")
	}

	code, err = generateMigrationCode()
	if err != nil {
		return "", "", fmt.Errorf("generate code: %w", err)
	}

	payload := hwMigrationPayload{
		ExportedAt:  time.Now().UTC().Format(time.RFC3339),
		Connections: v.data.Connections,
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", "", err
	}

	expiry := time.Now().UTC().Add(hwMigrationLifespan).Unix()
	key := deriveMigrationKey(v.passphrase, code, salt)
	aad := migrationAAD(hwMigrationMagic, hwMigrationVersion, expiry, salt)
	ciphertext, err := encryptWithAAD(plaintext, key, aad)
	zeroBytes(key)
	zeroBytes(plaintext)
	if err != nil {
		return "", "", err
	}

	file := HWMigrationFile{
		Magic:   hwMigrationMagic,
		Version: hwMigrationVersion,
		Expiry:  expiry,
		Salt:    salt,
		Data:    ciphertext,
	}
	out, err := json.Marshal(file)
	if err != nil {
		return "", "", err
	}

	path = hwMigrationPath()
	if err := os.WriteFile(path, out, 0600); err != nil {
		return "", "", fmt.Errorf("write migration file: %w", err)
	}
	return code, path, nil
}

// loadHWMigration reads and validates the header of a migration file.
func loadHWMigration(path string) (*HWMigrationFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read migration file: %w", err)
	}
	var f HWMigrationFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("migration file corrupted: %w", err)
	}
	if f.Magic != hwMigrationMagic {
		return nil, fmt.Errorf("not a hardware migration file (magic=%q)", f.Magic)
	}
	if f.Version != hwMigrationVersion {
		return nil, fmt.Errorf("unsupported migration file version %d", f.Version)
	}
	return &f, nil
}

// ReadHWMigrationExpiry returns the expiry timestamp of the migration file
// next to the binary, or zero if none / unreadable. Used by the TUI to show
// the admin how long they have.
func ReadHWMigrationExpiry() time.Time {
	f, err := loadHWMigration(hwMigrationPath())
	if err != nil {
		return time.Time{}
	}
	return time.Unix(f.Expiry, 0).UTC()
}

// ImportHardwareMigration decrypts the migration file using passphrase+code,
// verifies the expiry against network-trusted time, creates a fresh vault
// with the migrated connections, and removes the migration file on success.
// Auth keys are NOT carried over — admin must regenerate.
func ImportHardwareMigration(passphrase, codeInput, newPassphrase string) (*Vault, error) {
	if VaultExists() {
		return nil, fmt.Errorf("a vault already exists on this machine — hardware migration imports only onto fresh machines")
	}

	code, err := normalizeMigrationCode(codeInput)
	if err != nil {
		return nil, err
	}

	path := hwMigrationPath()
	f, err := loadHWMigration(path)
	if err != nil {
		return nil, err
	}

	now, err := TrustedTime()
	if err != nil {
		return nil, fmt.Errorf("cannot verify current time — import refused for safety: %w", err)
	}

	expiry := time.Unix(f.Expiry, 0).UTC()
	if now.After(expiry) {
		return nil, fmt.Errorf("migration file expired %s ago (expired at %s). Export a fresh one on the source machine.",
			now.Sub(expiry).Round(time.Minute), expiry.Format(time.RFC1123))
	}

	key := deriveMigrationKey(passphrase, code, f.Salt)
	aad := migrationAAD(f.Magic, f.Version, f.Expiry, f.Salt)
	plaintext, err := decryptWithAAD(f.Data, key, aad)
	zeroBytes(key)
	if err != nil {
		return nil, fmt.Errorf("decryption failed — wrong passphrase, wrong one-time code, or migration file tampered")
	}

	var payload hwMigrationPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		zeroBytes(plaintext)
		return nil, fmt.Errorf("migration payload corrupted: %w", err)
	}
	zeroBytes(plaintext)

	effectivePassphrase := newPassphrase
	if effectivePassphrase == "" {
		effectivePassphrase = passphrase
	}
	vault, err := CreateVault(effectivePassphrase)
	if err != nil {
		return nil, fmt.Errorf("create local vault: %w", err)
	}
	vault.data.Connections = payload.Connections
	if err := vault.Save(); err != nil {
		return nil, fmt.Errorf("save migrated vault: %w", err)
	}

	// Zero-fill then delete the migration file — the one-time code is now
	// single-use in practice (re-import would need a fresh file anyway since
	// VaultExists() will block it).
	wipeAndRemove(path)
	return vault, nil
}

// wipeAndRemove overwrites a file with zeros before deleting. SSD trim may
// short-circuit this but it costs nothing and defends against spinning-rust
// or filesystem-layer recovery.
func wipeAndRemove(path string) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		zeros := make([]byte, info.Size())
		f.Write(zeros)
		f.Sync()
		f.Close()
	}
	os.Remove(path)
}
