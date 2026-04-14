package connections

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

var (
	hostKeyCallback ssh.HostKeyCallback
	hostKeyOnce     sync.Once
	hostKeyErr      error
)

// knownHostsPath returns the path to the known_hosts file.
func knownHostsPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".secure-wrapper", "known_hosts")
}

// GetHostKeyCallback returns a TOFU (Trust On First Use) host key callback.
// On first connection, the host key is stored. On subsequent connections,
// the stored key is verified. If the key changes, the connection is rejected.
func GetHostKeyCallback() (ssh.HostKeyCallback, error) {
	hostKeyOnce.Do(func() {
		// Ensure directory exists
		dir := filepath.Dir(knownHostsPath())
		if err := os.MkdirAll(dir, 0700); err != nil {
			hostKeyErr = fmt.Errorf("cannot create known_hosts directory: %w", err)
			return
		}

		// Create file if it doesn't exist
		if _, err := os.Stat(knownHostsPath()); os.IsNotExist(err) {
			if err := os.WriteFile(knownHostsPath(), []byte{}, 0600); err != nil {
				hostKeyErr = fmt.Errorf("cannot create known_hosts file: %w", err)
				return
			}
		}

		hostKeyCallback = tofuCallback
	})

	if hostKeyErr != nil {
		return nil, hostKeyErr
	}
	return hostKeyCallback, nil
}

// tofuCallback implements Trust On First Use host key verification.
func tofuCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	// Normalize hostname to host:port format
	host := hostname
	if !strings.Contains(host, ":") {
		host = host + ":22"
	}

	keyType := key.Type()
	keyFingerprint := fingerprintKey(key)
	keyLine := fmt.Sprintf("%s %s %s", host, keyType, keyFingerprint)

	// Read existing known hosts
	data, err := os.ReadFile(knownHostsPath())
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cannot read known_hosts: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, " ", 3)
		if len(parts) != 3 {
			continue
		}

		storedHost := parts[0]
		storedType := parts[1]
		storedFingerprint := parts[2]

		if storedHost == host && storedType == keyType {
			// Found existing entry — verify
			if storedFingerprint == keyFingerprint {
				return nil // Key matches
			}
			return fmt.Errorf(
				"HOST KEY VERIFICATION FAILED for %s\n"+
					"  Expected: %s %s\n"+
					"  Got:      %s %s\n"+
					"  The host key has changed. This could indicate a man-in-the-middle attack.\n"+
					"  If the host key was legitimately changed, remove the old entry from:\n"+
					"  %s",
				host, storedType, storedFingerprint, keyType, keyFingerprint, knownHostsPath(),
			)
		}
	}

	// TOFU: first connection to this host — store the key
	f, err := os.OpenFile(knownHostsPath(), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("cannot write to known_hosts: %w", err)
	}
	defer f.Close()

	if _, err := fmt.Fprintln(f, keyLine); err != nil {
		return fmt.Errorf("cannot write host key: %w", err)
	}

	fmt.Fprintf(os.Stderr, "TOFU: Stored host key for %s (%s)\n", host, keyType)
	return nil
}

// fingerprintKey returns the SHA-256 fingerprint of a public key.
func fingerprintKey(key ssh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	return hex.EncodeToString(hash[:])
}
