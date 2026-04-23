package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	vaultDir  = ".secure-wrapper"
	vaultFile = "vault.enc"
	saltSize  = 32
	nonceSize = 12 // AES-GCM standard nonce size
)

type ConnectionType string

const (
	ConnSSHPassword ConnectionType = "ssh-password"
	ConnSSHKey      ConnectionType = "ssh-key"
	ConnAPI         ConnectionType = "api"
	ConnFTP         ConnectionType = "ftp"
	ConnDBPostgres  ConnectionType = "db-postgres"
	ConnDBMySQL     ConnectionType = "db-mysql"
	ConnDBMSSQL     ConnectionType = "db-mssql"
	ConnWinRM       ConnectionType = "winrm"
)

type Connection struct {
	Name     string         `json:"name"`
	Type     ConnectionType `json:"type"`
	Host     string         `json:"host"`
	Port     int            `json:"port"`
	Username string         `json:"username,omitempty"`
	Password string         `json:"password,omitempty"`
	KeyPath  string         `json:"key_path,omitempty"`
	KeyPass  string         `json:"key_passphrase,omitempty"`

	// API-specific
	BaseURL    string            `json:"base_url,omitempty"`
	AuthType   string            `json:"auth_type,omitempty"` // key, bearer, basic
	AuthHeader string            `json:"auth_header,omitempty"`
	AuthValue  string            `json:"auth_value,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Insecure   bool              `json:"insecure,omitempty"` // skip TLS verify
	TOTPSecret string            `json:"totp_secret,omitempty"`
	ExtraField string            `json:"extra_field,omitempty"` // generic extra data (e.g., diagnostic extension ID)

	// Database-specific (postgres/mysql/mssql)
	Database string `json:"database,omitempty"`  // default DB name
	SSLMode  string `json:"ssl_mode,omitempty"`  // postgres: disable/require/verify-ca/verify-full; mysql: skip-verify/preferred/true/false; mssql: disable/false/true/strict

	// WinRM-specific
	UseHTTPS bool `json:"use_https,omitempty"` // WinRM over 5986 vs plain 5985

	// Tunneling — names another connection in the vault (must be SSH type).
	// When set, DB and WinRM executors dial SSH to the tunnel host, open a
	// local port-forward to this connection's Host:Port, and talk to
	// 127.0.0.1:<ephemeral> instead. Empty = direct connection.
	TunnelVia string `json:"tunnel_via,omitempty"`
}

type AuthKey struct {
	Name         string   `json:"name"`
	Hash         []byte   `json:"hash"`
	Salt         []byte   `json:"salt"`
	CreatedAt    string   `json:"created_at"`
	LastUsed     string   `json:"last_used,omitempty"`
	DerivedKey   []byte   `json:"derived_key,omitempty"`
	VaultSalt    []byte   `json:"vault_salt,omitempty"`
	AllowedConns []string `json:"allowed_conns,omitempty"` // nil/empty = all connections; otherwise only these names
}

type VaultData struct {
	Fingerprint string       `json:"fingerprint"`
	Connections []Connection `json:"connections"`
	AuthKeys    []AuthKey    `json:"auth_keys"`
}

// AuthKeyVaultEntry stores a copy of connection data encrypted with a specific auth key.
// This allows the auth key to open the vault for connection use without the passphrase.
type AuthKeyVaultEntry struct {
	KeyName       string `json:"key_name"`
	EncryptedData []byte `json:"encrypted_data"` // AES-GCM encrypted connections JSON
	Salt          []byte `json:"salt"`
}

// VaultFile is the on-disk format: main encrypted vault + auth key encrypted copies.
// The Header is unencrypted and readable without the passphrase — used to detect binary/version mismatches.
type VaultFile struct {
	Header       *VaultHeader        `json:"header,omitempty"`
	MainSalt     []byte              `json:"main_salt"`
	MainData     []byte              `json:"main_data"` // AES-GCM encrypted VaultData
	AuthKeyVault []AuthKeyVaultEntry `json:"auth_key_vault"`
}

// VaultHeader is stored unencrypted — allows detecting wrong binary without attempting decryption.
type VaultHeader struct {
	Version          string `json:"version"`           // SecureWrapper version that created/last saved this vault
	BinaryFP         string `json:"binary_fp"`         // Binary fingerprint at save time
	MachineFP        string `json:"machine_fp"`        // Machine fingerprint at save time
	CreatedAt        string `json:"created_at"`        // When vault was first created
	LastSaved        string `json:"last_saved"`        // When vault was last saved
	ConnectionCount  int    `json:"connection_count"`  // Number of connections stored
	AuthKeyCount     int    `json:"auth_key_count"`    // Number of auth keys stored
}

type Vault struct {
	path                 string
	passphrase           string
	data                 VaultData
	pendingAuthKeyVault  []AuthKeyVaultEntry
	createdAt            string
}

func vaultPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, vaultDir, vaultFile)
}

func vaultDirPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, vaultDir)
}

func VaultExists() bool {
	_, err := os.Stat(vaultPath())
	return err == nil
}

// ReadVaultHeader reads the unencrypted header from an existing vault without decrypting.
// Returns nil if vault doesn't exist or has no header.
func ReadVaultHeader() *VaultHeader {
	vf, err := loadVaultFile(vaultPath())
	if err != nil {
		return nil
	}
	return vf.Header
}

// CheckVaultCompatibility checks if the current binary can decrypt the vault.
// Returns: compatible (bool), reason (string)
func CheckVaultCompatibility() (bool, string) {
	header := ReadVaultHeader()
	if header == nil {
		return true, "" // No header — old vault format, try anyway
	}

	currentBinaryFP := BinaryKeyFingerprint()
	currentMachineFP := ShortFingerprint()

	if header.MachineFP != currentMachineFP {
		return false, fmt.Sprintf("vault was created on a different machine (vault: %s, this: %s)", header.MachineFP, currentMachineFP)
	}

	if header.BinaryFP != currentBinaryFP {
		return false, fmt.Sprintf("vault was created with a different binary (vault: %s v%s, this: %s v%s). Use the correct binary or upgrade from within the vault.",
			header.BinaryFP, header.Version, currentBinaryFP, version)
	}

	return true, ""
}

// BackupVault creates two backups:
// 1. Raw copy of vault.enc → vault.enc.backup (for same-binary restore)
// 2. A 2-factor encrypted export → vault.backup (passphrase + machine only, no binary key)
//    This can be restored by ANY binary on the same machine.
func BackupVault() error {
	if !VaultExists() {
		return nil
	}
	// Raw copy for same-binary restore
	return copyFile(vaultPath(), vaultPath()+".backup")
}

// BackupVaultWithPassphrase creates a 2-factor backup that can be restored by any binary.
// Must be called while the vault is open (passphrase known).
func (v *Vault) BackupVaultWithPassphrase() error {
	fp, err := MachineFingerprint()
	if err != nil {
		return err
	}

	data, err := json.Marshal(v.data)
	if err != nil {
		return err
	}

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}

	// 2-factor key: passphrase + machine fingerprint, NO binary hash
	combined := v.passphrase + "|" + fp + "|backup"
	key := argon2.IDKey([]byte(combined), salt, 3, 64*1024, 4, 32)

	ciphertext, err := encrypt(data, key)
	zeroBytes(key)
	if err != nil {
		return err
	}

	header := VaultHeader{
		Version:         version,
		BinaryFP:        "portable", // marks this as a portable backup
		MachineFP:       ShortFingerprint(),
		CreatedAt:       v.createdAt,
		LastSaved:       time.Now().Format("2006-01-02 15:04:05"),
		ConnectionCount: len(v.data.Connections),
		AuthKeyCount:    len(v.data.AuthKeys),
	}

	backupFile := struct {
		Header VaultHeader `json:"header"`
		Salt   []byte      `json:"salt"`
		Data   []byte      `json:"data"`
	}{
		Header: header,
		Salt:   salt,
		Data:   ciphertext,
	}

	out, err := json.Marshal(backupFile)
	if err != nil {
		return err
	}

	backupPath := filepath.Join(filepath.Dir(vaultPath()), "vault.portable.backup")
	return os.WriteFile(backupPath, out, 0600)
}

// WipeVault removes the vault and attempts file but preserves backups and known_hosts.
func WipeVault() {
	os.Remove(vaultPath())                                                     // vault.enc
	os.Remove(attemptsFilePath())                                              // attempts
	os.Remove(filepath.Join(filepath.Dir(vaultPath()), "vault.migration"))     // migration file
	os.Remove(filepath.Join(filepath.Dir(vaultPath()), "key_usage.json"))      // key usage
	// Preserve: vault.enc.backup, known_hosts
}

// BackupExists checks if a vault backup file exists.
func BackupExists() bool {
	_, err := os.Stat(vaultPath() + ".backup")
	return err == nil
}

// RestoreVault decrypts a portable backup with the passphrase + machine fingerprint,
// then re-encrypts for the current binary and saves as the active vault.
func RestoreVault(passphrase string) (*Vault, error) {
	portablePath := filepath.Join(filepath.Dir(vaultPath()), "vault.portable.backup")
	if _, err := os.Stat(portablePath); err != nil {
		return nil, fmt.Errorf("no portable backup found — backups must be made from within the vault using [b]")
	}

	raw, err := os.ReadFile(portablePath)
	if err != nil {
		return nil, fmt.Errorf("cannot read backup: %w", err)
	}

	var backupFile struct {
		Header VaultHeader `json:"header"`
		Salt   []byte      `json:"salt"`
		Data   []byte      `json:"data"`
	}
	if err := json.Unmarshal(raw, &backupFile); err != nil {
		return nil, fmt.Errorf("backup file corrupted: %w", err)
	}

	fp, err := MachineFingerprint()
	if err != nil {
		return nil, fmt.Errorf("cannot generate fingerprint: %w", err)
	}

	// Decrypt with 2-factor key (passphrase + machine fingerprint)
	combined := passphrase + "|" + fp + "|backup"
	key := argon2.IDKey([]byte(combined), backupFile.Salt, 3, 64*1024, 4, 32)

	plaintext, err := decrypt(backupFile.Data, key)
	zeroBytes(key)
	if err != nil {
		return nil, fmt.Errorf("wrong passphrase or backup from a different machine")
	}

	var data VaultData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, fmt.Errorf("backup data corrupted: %w", err)
	}

	data.Fingerprint = fp

	vault := &Vault{
		path:       vaultPath(),
		passphrase: passphrase,
		data:       data,
		createdAt:  backupFile.Header.CreatedAt,
	}

	if err := vault.Save(); err != nil {
		return nil, fmt.Errorf("cannot save restored vault: %w", err)
	}

	return vault, nil
}

// PortableBackupExists checks if a portable backup exists.
func PortableBackupExists() bool {
	portablePath := filepath.Join(filepath.Dir(vaultPath()), "vault.portable.backup")
	_, err := os.Stat(portablePath)
	return err == nil
}

// ReadPortableBackupHeader reads the header from a portable backup.
func ReadPortableBackupHeader() *VaultHeader {
	portablePath := filepath.Join(filepath.Dir(vaultPath()), "vault.portable.backup")
	raw, err := os.ReadFile(portablePath)
	if err != nil {
		return nil
	}
	var backupFile struct {
		Header VaultHeader `json:"header"`
	}
	if err := json.Unmarshal(raw, &backupFile); err != nil {
		return nil
	}
	return &backupFile.Header
}

func deriveKey(passphrase string, salt []byte, fingerprint string) []byte {
	// Three-factor key derivation for main vault:
	// 1. Passphrase — something the user provides
	// 2. Machine fingerprint — binds to this specific hardware
	// 3. Binary key — binds to this specific compiled binary
	binaryKey := GetBinaryKey()
	combined := passphrase + "|" + fingerprint + "|" + fmt.Sprintf("%x", binaryKey)
	// Argon2id: 3 iterations, 64MB memory, 4 threads, 32-byte key
	return argon2.IDKey([]byte(combined), salt, 3, 64*1024, 4, 32)
}

func deriveAuthKeyVaultKey(authKey string, salt []byte, fingerprint string) []byte {
	// Two-factor key derivation for auth key vault entries:
	// 1. Auth key — the caller's secret
	// 2. Machine fingerprint — binds to this specific hardware
	// No binary hash — so auth keys survive binary upgrades
	combined := authKey + "|" + fingerprint + "|authvault"
	return argon2.IDKey([]byte(combined), salt, 3, 64*1024, 4, 32)
}

func encrypt(plaintext, key []byte) ([]byte, error) {
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

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func decrypt(ciphertext, key []byte) ([]byte, error) {
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
	ciphertext = ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed — wrong passphrase or corrupted vault")
	}

	return plaintext, nil
}

func CreateVault(passphrase string) (*Vault, error) {
	fp, err := MachineFingerprint()
	if err != nil {
		return nil, fmt.Errorf("cannot generate machine fingerprint: %w", err)
	}

	v := &Vault{
		path:       vaultPath(),
		passphrase: passphrase,
		createdAt:  time.Now().Format("2006-01-02 15:04:05"),
		data: VaultData{
			Fingerprint: fp,
			Connections: []Connection{},
			AuthKeys:    []AuthKey{},
		},
	}

	if err := v.Save(); err != nil {
		return nil, err
	}

	return v, nil
}

func loadVaultFile(path string) (*VaultFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read vault: %w", err)
	}

	var vf VaultFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		return nil, fmt.Errorf("vault file corrupted: %w", err)
	}

	return &vf, nil
}

func OpenVault(passphrase string) (*Vault, error) {
	path := vaultPath()

	vf, err := loadVaultFile(path)
	if err != nil {
		return nil, err
	}

	fp, err := MachineFingerprint()
	if err != nil {
		return nil, fmt.Errorf("cannot generate machine fingerprint: %w", err)
	}

	key := deriveKey(passphrase, vf.MainSalt, fp)
	plaintext, err := decrypt(vf.MainData, key)
	zeroBytes(key)
	if err != nil {
		return nil, err
	}

	var data VaultData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, fmt.Errorf("vault data corrupted: %w", err)
	}

	if data.Fingerprint != fp {
		return nil, fmt.Errorf("vault was created on a different machine")
	}

	return &Vault{
		path:       path,
		passphrase: passphrase,
		data:       data,
	}, nil
}

// OpenVaultWithAuthKey opens the vault using an auth key (connection access only, no vault management).
func OpenVaultWithAuthKey(authKey string) (*Vault, error) {
	path := vaultPath()

	vf, err := loadVaultFile(path)
	if err != nil {
		return nil, err
	}

	fp, err := MachineFingerprint()
	if err != nil {
		return nil, fmt.Errorf("cannot generate machine fingerprint: %w", err)
	}

	// Try each auth key vault entry
	for _, entry := range vf.AuthKeyVault {
		key := deriveAuthKeyVaultKey(authKey, entry.Salt, fp)
		plaintext, err := decrypt(entry.EncryptedData, key)
		zeroBytes(key)
		if err != nil {
			continue // Wrong key for this entry
		}

		var conns []Connection
		if err := json.Unmarshal(plaintext, &conns); err != nil {
			continue
		}

		// Track last-used timestamp for this auth key
		updateKeyUsage(entry.KeyName)

		// Build a read-only vault with just connections
		return &Vault{
			path: path,
			data: VaultData{
				Fingerprint: fp,
				Connections: conns,
			},
		}, nil
	}

	return nil, fmt.Errorf("invalid auth key")
}

func (v *Vault) Save() error {
	dir := filepath.Dir(v.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("cannot create vault directory: %w", err)
	}

	// Encrypt main vault data with passphrase
	plaintext, err := json.Marshal(v.data)
	if err != nil {
		return err
	}

	mainSalt := make([]byte, saltSize)
	if _, err := rand.Read(mainSalt); err != nil {
		return err
	}

	mainKey := deriveKey(v.passphrase, mainSalt, v.data.Fingerprint)
	mainData, err := encrypt(plaintext, mainKey)
	zeroBytes(mainKey)
	if err != nil {
		return err
	}

	// Re-encrypt auth key vault entries using stored derived keys.
	// This ensures new/edited connections are always available to auth key holders.
	var authKeyVault []AuthKeyVaultEntry

	if v.passphrase != "" {
		// Passphrase path — re-encrypt entries with filtered connections per key
		for _, ak := range v.data.AuthKeys {
			if len(ak.DerivedKey) > 0 {
				conns := v.connectionsForAuthKey(ak)
				connJSON, err := json.Marshal(conns)
				if err != nil {
					continue
				}
				encryptedConns, err := encrypt(connJSON, ak.DerivedKey)
				if err != nil {
					continue
				}
				authKeyVault = append(authKeyVault, AuthKeyVaultEntry{
					KeyName:       ak.Name,
					EncryptedData: encryptedConns,
					Salt:          ak.VaultSalt,
				})
			}
		}
	} else {
		// Auth key path (read-only) — preserve existing entries
		if existing, err := loadVaultFile(v.path); err == nil {
			authKeyVault = existing.AuthKeyVault
		}
	}

	// Add pending entries from newly created auth keys
	if v.pendingAuthKeyVault != nil {
		authKeyVault = append(authKeyVault, v.pendingAuthKeyVault...)
		v.pendingAuthKeyVault = nil
	}

	// Remove entries for revoked keys
	var activeEntries []AuthKeyVaultEntry
	for _, entry := range authKeyVault {
		found := false
		for _, ak := range v.data.AuthKeys {
			if ak.Name == entry.KeyName {
				found = true
				break
			}
		}
		if found {
			activeEntries = append(activeEntries, entry)
		}
	}

	// Build unencrypted header for binary/version detection
	createdAt := v.createdAt
	if createdAt == "" {
		// Preserve from existing vault if available
		if existing, err := loadVaultFile(v.path); err == nil && existing.Header != nil {
			createdAt = existing.Header.CreatedAt
		}
		if createdAt == "" {
			createdAt = time.Now().Format("2006-01-02 15:04:05")
		}
	}

	vf := VaultFile{
		Header: &VaultHeader{
			Version:         version,
			BinaryFP:        BinaryKeyFingerprint(),
			MachineFP:       ShortFingerprint(),
			CreatedAt:       createdAt,
			LastSaved:       time.Now().Format("2006-01-02 15:04:05"),
			ConnectionCount: len(v.data.Connections),
			AuthKeyCount:    len(v.data.AuthKeys),
		},
		MainSalt:     mainSalt,
		MainData:     mainData,
		AuthKeyVault: activeEntries,
	}

	out, err := json.Marshal(vf)
	if err != nil {
		return err
	}

	if err := os.WriteFile(v.path, out, 0600); err != nil {
		return fmt.Errorf("cannot write vault: %w", err)
	}

	return nil
}

// Connection management

func (v *Vault) AddConnection(conn Connection) {
	v.data.Connections = append(v.data.Connections, conn)
}

func (v *Vault) GetConnection(name string) *Connection {
	for i := range v.data.Connections {
		if v.data.Connections[i].Name == name {
			return &v.data.Connections[i]
		}
	}
	return nil
}

func (v *Vault) ListConnections() []Connection {
	return v.data.Connections
}

func (v *Vault) RemoveConnection(name string) bool {
	for i, conn := range v.data.Connections {
		if conn.Name == name {
			v.data.Connections = append(v.data.Connections[:i], v.data.Connections[i+1:]...)
			return true
		}
	}
	return false
}

// Auth key management

// connectionsForAuthKey returns the connections an auth key is allowed to access.
func (v *Vault) connectionsForAuthKey(ak AuthKey) []Connection {
	if len(ak.AllowedConns) == 0 {
		return v.data.Connections // all connections
	}
	allowed := make(map[string]bool)
	for _, name := range ak.AllowedConns {
		allowed[name] = true
	}
	var filtered []Connection
	for _, conn := range v.data.Connections {
		if allowed[conn.Name] {
			filtered = append(filtered, conn)
		}
	}
	return filtered
}

// AddAuthKeyWithAccess creates an auth key with optional connection restrictions.
// If allowedConns is nil or empty, the key has access to all connections.
func (v *Vault) AddAuthKey(name string, allowedConns ...string) (string, error) {
	// Generate random key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", err
	}

	// Format as swk_ + hex
	plainKey := "swk_" + fmt.Sprintf("%x", keyBytes)

	// Hash with Argon2id for storage (for validation)
	hashSalt := make([]byte, 16)
	if _, err := rand.Read(hashSalt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(plainKey), hashSalt, 3, 64*1024, 4, 32)

	// Create encrypted copy of connections for this auth key
	fp, err := MachineFingerprint()
	if err != nil {
		return "", fmt.Errorf("cannot generate fingerprint: %w", err)
	}

	entrySalt := make([]byte, saltSize)
	if _, err := rand.Read(entrySalt); err != nil {
		return "", err
	}

	entryKey := deriveAuthKeyVaultKey(plainKey, entrySalt, fp)
	storedKey := make([]byte, len(entryKey))
	copy(storedKey, entryKey)

	newKey := AuthKey{
		Name:       name,
		Hash:       hash,
		Salt:       hashSalt,
		CreatedAt:  time.Now().Format("2006-01-02 15:04:05"),
		DerivedKey: storedKey,
		VaultSalt:  entrySalt,
	}
	if len(allowedConns) > 0 {
		newKey.AllowedConns = allowedConns
	}

	v.data.AuthKeys = append(v.data.AuthKeys, newKey)

	// Only encrypt the connections this key is allowed to access
	conns := v.connectionsForAuthKey(newKey)
	connJSON, err := json.Marshal(conns)
	if err != nil {
		return "", err
	}

	encryptedConns, err := encrypt(connJSON, entryKey)
	zeroBytes(entryKey)
	if err != nil {
		return "", err
	}

	v.pendingAuthKeyVault = append(v.pendingAuthKeyVault, AuthKeyVaultEntry{
		KeyName:       name,
		EncryptedData: encryptedConns,
		Salt:          entrySalt,
	})

	return plainKey, nil
}

func (v *Vault) ValidateAuthKey(key string) bool {
	if len(v.data.AuthKeys) == 0 {
		return false // No keys configured — deny by default
	}

	for i := range v.data.AuthKeys {
		hash := argon2.IDKey([]byte(key), v.data.AuthKeys[i].Salt, 3, 64*1024, 4, 32)
		if sha256Equal(hash, v.data.AuthKeys[i].Hash) {
			v.data.AuthKeys[i].LastUsed = time.Now().Format("2006-01-02 15:04:05")
			return true
		}
	}
	return false
}

func (v *Vault) ListAuthKeys() []AuthKey {
	return v.data.AuthKeys
}

func (v *Vault) RevokeAuthKey(name string) bool {
	for i, key := range v.data.AuthKeys {
		if key.Name == name {
			v.data.AuthKeys = append(v.data.AuthKeys[:i], v.data.AuthKeys[i+1:]...)
			return true
		}
	}
	return false
}

func (v *Vault) HasAuthKeys() bool {
	return len(v.data.AuthKeys) > 0
}

// keyUsagePath returns the path to the key usage tracking file.
func keyUsagePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, vaultDir, "key_usage.json")
}

// updateKeyUsage stores the last-used timestamp for an auth key in an unencrypted file.
func updateKeyUsage(keyName string) {
	usage := LoadKeyUsage()
	usage[keyName] = time.Now().Format("2006-01-02 15:04:05")

	if data, err := json.Marshal(usage); err == nil {
		os.WriteFile(keyUsagePath(), data, 0600)
	}
}

// LoadKeyUsage returns the auth-key-name → last-used-timestamp map written by
// OpenVaultWithAuthKey on every successful operator-mode open. The admin TUI
// reads this rather than AuthKey.LastUsed in the vault, because the vault is
// rarely re-saved after an auth-key use (which would be the only way to
// persist the LastUsed field in the encrypted vault).
func LoadKeyUsage() map[string]string {
	usage := make(map[string]string)
	if data, err := os.ReadFile(keyUsagePath()); err == nil {
		json.Unmarshal(data, &usage)
	}
	return usage
}

func sha256Equal(a, b []byte) bool {
	ha := sha256.Sum256(a)
	hb := sha256.Sum256(b)
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

// zeroBytes overwrites a byte slice with zeros.
// TODO: Migrate passphrase from string to []byte for full zeroing support.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
