package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	githubRepo     = "S07734/SecureWrapper"
	migrationFile  = "vault.migration"
)

type GitHubRelease struct {
	TagName string        `json:"tag_name"`
	Name    string        `json:"name"`
	Body    string        `json:"body"`
	Assets  []GitHubAsset `json:"assets"`
}

type GitHubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

func upgradeScreen(vault *Vault) {
	clearScreen()
	fmt.Println(titleStyle.Render("\n  ── Check for Updates ──\n"))
	fmt.Printf("  Current version: %s\n", connNameStyle.Render("v"+version))
	fmt.Printf("  Build date:      %s\n", dimStyle.Render(buildDate))
	fmt.Println()
	fmt.Print(dimStyle.Render("  Checking GitHub... "))

	release, err := getLatestRelease()
	if err != nil {
		fmt.Println()
		printError(fmt.Sprintf("Failed to check: %v", err))
		fmt.Println()
		fmt.Println(dimStyle.Render("  TLS Diagnostic:"))
		fmt.Print(dimStyle.Render(TLSDiagnostic()))
		pause()
		return
	}

	latestVersion := strings.TrimPrefix(release.TagName, "v")
	currentVersion := version

	if latestVersion == currentVersion {
		printSuccess("You're on the latest version.")
		pause()
		return
	}

	fmt.Println()
	fmt.Println()
	fmt.Printf("  New version available: %s\n", successStyle.Render("v"+latestVersion))
	fmt.Println()

	// Show release notes
	if release.Body != "" {
		lines := strings.Split(release.Body, "\n")
		for _, line := range lines {
			if len(line) > 0 {
				fmt.Printf("  %s\n", dimStyle.Render(line))
			}
		}
		fmt.Println()
	}

	// Find the right binary for this platform
	assetName := getAssetName()
	var downloadURL string
	var assetSize int64

	for _, asset := range release.Assets {
		if asset.Name == assetName {
			downloadURL = asset.BrowserDownloadURL
			assetSize = asset.Size
			break
		}
	}

	if downloadURL == "" {
		printError(fmt.Sprintf("No binary found for %s/%s (%s)", runtime.GOOS, runtime.GOARCH, assetName))
		pause()
		return
	}

	fmt.Printf("  Binary: %s (%s)\n", connNameStyle.Render(assetName), dimStyle.Render(formatSize(assetSize)))
	fmt.Println()

	confirm := printPrompt("Download and upgrade? (yes/no):")
	if confirm != "yes" {
		return
	}

	// Step 0: Backup the vault file before doing anything
	fmt.Println()
	fmt.Print(dimStyle.Render("  Backing up vault... "))
	backupPath := vaultPath() + ".backup"
	if _, err := os.Stat(vaultPath()); err == nil {
		if err := copyFile(vaultPath(), backupPath); err != nil {
			fmt.Println()
			printWarn(fmt.Sprintf("Backup failed: %v (continuing anyway)", err))
		} else {
			printSuccess(fmt.Sprintf("Saved to %s", backupPath))
		}
	} else {
		printSuccess("No existing vault to backup")
	}

	// Step 0b: Create portable backup (2-factor, survives any binary change)
	fmt.Print(dimStyle.Render("  Creating portable backup... "))
	if err := vault.BackupVaultWithPassphrase(); err != nil {
		fmt.Println()
		printWarn(fmt.Sprintf("Portable backup failed: %v (continuing)", err))
	} else {
		printSuccess("OK")
	}

	// Step 1: Export vault to migration file (2-factor: passphrase + machine fingerprint, no binary hash)
	fmt.Print(dimStyle.Render("  Preparing vault migration... "))

	if err := exportMigration(vault); err != nil {
		fmt.Println()
		printError(fmt.Sprintf("Migration export failed: %v", err))
		pause()
		return
	}
	printSuccess("OK")

	// Step 2: Download new binary
	fmt.Print(dimStyle.Render("  Downloading new binary... "))

	exePath, err := os.Executable()
	if err != nil {
		printError(fmt.Sprintf("Cannot find executable path: %v", err))
		cleanupMigration()
		pause()
		return
	}

	newBinaryPath := exePath + ".new"
	if err := downloadBinary(downloadURL, newBinaryPath); err != nil {
		fmt.Println()
		printError(fmt.Sprintf("Download failed: %v", err))
		cleanupMigration()
		pause()
		return
	}
	printSuccess("OK")

	// Verify checksum
	fmt.Print(dimStyle.Render("  Verifying checksum... "))
	checksumURL := ""
	for _, asset := range release.Assets {
		if asset.Name == "SHA256SUMS" {
			checksumURL = asset.BrowserDownloadURL
			break
		}
	}

	if checksumURL != "" {
		if err := verifyChecksum(checksumURL, newBinaryPath, assetName); err != nil {
			fmt.Println()
			printError(fmt.Sprintf("Checksum verification failed: %v", err))
			os.Remove(newBinaryPath)
			cleanupMigration()
			pause()
			return
		}
		printSuccess("OK")
	} else {
		fmt.Println()
		printWarn("No SHA256SUMS file in release — skipping checksum verification.")
		confirm := printPrompt("Continue without checksum verification? (yes/no):")
		if confirm != "yes" {
			os.Remove(newBinaryPath)
			cleanupMigration()
			return
		}
	}

	// Step 3: Replace binary
	fmt.Print(dimStyle.Render("  Replacing binary... "))

	oldBinaryPath := exePath + ".old"
	if err := os.Rename(exePath, oldBinaryPath); err != nil {
		printError(fmt.Sprintf("Cannot backup old binary: %v", err))
		os.Remove(newBinaryPath)
		cleanupMigration()
		pause()
		return
	}

	if err := os.Rename(newBinaryPath, exePath); err != nil {
		// Rollback
		os.Rename(oldBinaryPath, exePath)
		printError(fmt.Sprintf("Cannot replace binary: %v", err))
		cleanupMigration()
		pause()
		return
	}

	// Make executable — owner-only for security
	os.Chmod(exePath, 0700)

	// macOS: remove quarantine attribute so Gatekeeper doesn't block the new binary
	if runtime.GOOS == "darwin" {
		exec.Command("xattr", "-d", "com.apple.quarantine", exePath).Run()
	}

	// Keep old binary until migration is confirmed (cleaned up in ImportMigration)

	printSuccess("OK")
	fmt.Println()
	printSuccess(fmt.Sprintf("Upgraded to v%s", latestVersion))
	printWarn("Restart the wrapper to complete migration.")
	fmt.Println()
	fmt.Println(dimStyle.Render("  The vault will be automatically migrated on next launch."))
	pause()

	os.Exit(0)
}

func getHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: getTLSConfig(),
		},
	}
}

func getLatestRelease() (*GitHubRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", githubRepo)

	client := getHTTPClient()
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("cannot reach GitHub: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("no releases found")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("cannot parse release: %w", err)
	}

	return &release, nil
}

func getAssetName() string {
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	return fmt.Sprintf("wrapper-%s-%s%s", runtime.GOOS, runtime.GOARCH, ext)
}

func downloadBinary(url, destPath string) error {
	client := &http.Client{
		Timeout:   120 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: getTLSConfig(),
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("download returned %d", resp.StatusCode)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// exportMigration encrypts the vault data with 2 factors (passphrase + machine fingerprint)
// so the new binary can import it without needing the old binary's hash.
func exportMigration(vault *Vault) error {
	fp, err := MachineFingerprint()
	if err != nil {
		return err
	}

	// Serialize all vault data
	data, err := json.Marshal(vault.data)
	if err != nil {
		return err
	}

	// Derive key from passphrase + fingerprint only (no binary hash)
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return err
	}

	combined := vault.passphrase + "|" + fp + "|migration"
	key := argon2.IDKey([]byte(combined), salt, 3, 64*1024, 4, 32)

	// Encrypt
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	// Write: salt + ciphertext
	migrationPath := filepath.Join(filepath.Dir(vaultPath()), migrationFile)
	out := append(salt, ciphertext...)
	return os.WriteFile(migrationPath, out, 0600)
}

// ImportMigration attempts to import a migration file using the provided passphrase.
// Called by the new binary on startup if a migration file exists.
func ImportMigration(passphrase string) (*Vault, error) {
	migrationPath := filepath.Join(filepath.Dir(vaultPath()), migrationFile)

	raw, err := os.ReadFile(migrationPath)
	if err != nil {
		return nil, err
	}

	if len(raw) < 32 {
		return nil, fmt.Errorf("migration file corrupted")
	}

	salt := raw[:32]
	ciphertext := raw[32:]

	fp, err := MachineFingerprint()
	if err != nil {
		return nil, err
	}

	// Derive key with same 2-factor method
	combined := passphrase + "|" + fp + "|migration"
	key := argon2.IDKey([]byte(combined), salt, 3, 64*1024, 4, 32)

	// Decrypt
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("migration file corrupted")
	}

	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("migration decryption failed — wrong passphrase")
	}

	var data VaultData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, fmt.Errorf("migration data corrupted")
	}

	// Update fingerprint to current machine (should match since it was part of the key)
	data.Fingerprint = fp

	// Create new vault with the new binary's key derivation
	vault := &Vault{
		path:       vaultPath(),
		passphrase: passphrase,
		data:       data,
	}

	if err := vault.Save(); err != nil {
		return nil, fmt.Errorf("cannot save migrated vault: %w", err)
	}

	// Securely delete migration file (contains encrypted vault data)
	secureDelete(migrationPath)

	// Clean up old binary from upgrade (Fix 17: kept until migration confirmed)
	exePath, err := os.Executable()
	if err == nil {
		oldBinaryPath := exePath + ".old"
		if _, statErr := os.Stat(oldBinaryPath); statErr == nil {
			os.Remove(oldBinaryPath)
		}
	}

	return vault, nil
}

// MigrationPending checks if a migration file exists.
func MigrationPending() bool {
	migrationPath := filepath.Join(filepath.Dir(vaultPath()), migrationFile)
	_, err := os.Stat(migrationPath)
	return err == nil
}

// MigrationTooOld checks if the migration file is older than 10 minutes.
func MigrationTooOld() bool {
	migrationPath := filepath.Join(filepath.Dir(vaultPath()), migrationFile)
	info, err := os.Stat(migrationPath)
	if err != nil {
		return false
	}
	return time.Since(info.ModTime()) > 10*time.Minute
}

func cleanupMigration() {
	migrationPath := filepath.Join(filepath.Dir(vaultPath()), migrationFile)
	secureDelete(migrationPath)
}

// verifyChecksum downloads SHA256SUMS and verifies the binary's hash.
func verifyChecksum(checksumURL, binaryPath, assetName string) error {
	client := getHTTPClient()
	resp, err := client.Get(checksumURL)
	if err != nil {
		return fmt.Errorf("cannot download checksums: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("checksums download returned %d", resp.StatusCode)
	}

	// Parse SHA256SUMS file for the expected hash
	var expectedHash string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) == 2 && parts[1] == assetName {
			expectedHash = parts[0]
			break
		}
	}

	if expectedHash == "" {
		return fmt.Errorf("no checksum found for %s in SHA256SUMS", assetName)
	}

	// Compute actual hash
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		return fmt.Errorf("cannot read downloaded binary: %w", err)
	}

	actualHash := sha256.Sum256(data)
	actualHex := hex.EncodeToString(actualHash[:])

	if actualHex != expectedHash {
		return fmt.Errorf("hash mismatch: expected %s, got %s", expectedHash, actualHex)
	}

	return nil
}

// secureDelete overwrites a file with zeros before removing it.
func secureDelete(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	// Overwrite with zeros
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		// If we can't open for writing, just remove
		return os.Remove(path)
	}

	zeros := make([]byte, 4096)
	remaining := info.Size()
	for remaining > 0 {
		n := int64(len(zeros))
		if n > remaining {
			n = remaining
		}
		written, err := f.Write(zeros[:n])
		if err != nil {
			f.Close()
			return os.Remove(path)
		}
		remaining -= int64(written)
	}
	f.Sync()
	f.Close()

	return os.Remove(path)
}

// copyFile creates a byte-for-byte copy of a file.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0600)
}

func formatSize(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%dB", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%.1fKB", float64(bytes)/1024)
	}
	return fmt.Sprintf("%.1fMB", float64(bytes)/(1024*1024))
}
