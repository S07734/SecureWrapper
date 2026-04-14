package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// binaryKey is computed once from the binary's own content.
// If the binary is modified in any way, the key changes and existing vaults won't decrypt.
var (
	binaryKey     []byte
	binaryKeyOnce sync.Once
	binaryKeyErr  error
)

// GetBinaryKey derives the encryption key from the binary's own SHA-256 hash.
// This means:
//   - No key is stored in the binary — it's computed at runtime
//   - If the binary is patched/modified, the hash changes and vaults break
//   - Each unique build produces a unique key (different compiler output = different hash)
func GetBinaryKey() []byte {
	binaryKeyOnce.Do(func() {
		exePath, err := os.Executable()
		if err != nil {
			binaryKeyErr = fmt.Errorf("cannot find executable path: %w", err)
			return
		}

		// Resolve symlinks to get the actual binary
		exePath, err = filepath.EvalSymlinks(exePath)
		if err != nil {
			binaryKeyErr = fmt.Errorf("cannot resolve executable path: %w", err)
			return
		}

		data, err := os.ReadFile(exePath)
		if err != nil {
			binaryKeyErr = fmt.Errorf("cannot read executable: %w", err)
			return
		}

		hash := sha256.Sum256(data)
		binaryKey = hash[:]
	})

	if binaryKeyErr != nil {
		// Fatal — can't derive key, vault operations will fail
		fmt.Fprintf(os.Stderr, "Fatal: %v\n", binaryKeyErr)
		os.Exit(1)
	}

	return binaryKey
}

// BinaryKeyFingerprint returns a short hash for display (not the actual key).
func BinaryKeyFingerprint() string {
	key := GetBinaryKey()
	fp := sha256.Sum256(key)
	return fmt.Sprintf("%x", fp[:8])
}
