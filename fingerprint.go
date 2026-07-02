package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"
)

// MachineFingerprint generates a stable fingerprint from hardware/OS identifiers.
// Uses platform-specific stable sources only (machine-id, CPU, disk serial,
// architecture). Network interfaces are intentionally excluded — they change
// whenever a phone, dock, or USB dongle is connected and are not a reliable
// hardware identity signal.
// This always reflects real hardware — no env var overrides apply here.
// For auth-key operations that support Docker fingerprint override, use
// authKeyMachineFingerprint() instead.
func MachineFingerprint() (string, error) {
	var parts []string

	// Platform-specific identifiers (machine-id, CPU, disk serial)
	parts = append(parts, platformFingerprint()...)

	// Cross-platform: architecture
	parts = append(parts, "arch:"+runtime.GOARCH)

	if len(parts) < 2 {
		return "", fmt.Errorf("insufficient hardware identifiers for fingerprint (got %d, need at least 2)", len(parts))
	}

	combined := strings.Join(parts, "|")
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:]), nil
}

// ShortFingerprint returns the first 16 chars of the real hardware fingerprint for display.
func ShortFingerprint() string {
	fp, err := MachineFingerprint()
	if err != nil {
		return "unknown"
	}
	return fp[:16]
}

// authKeyMachineFingerprint returns the fingerprint used for auth-key vault
// operations. If WRAPPER_MACHINE_FP is set, that value is used instead of the
// real hardware fingerprint — this allows Docker containers to authenticate
// against a vault stored on the host machine.
//
// This override applies ONLY to auth-key access (2-factor: key + fingerprint).
// Passphrase access always uses the real hardware fingerprint and is unaffected.
func authKeyMachineFingerprint() (string, error) {
	if fp := os.Getenv("WRAPPER_MACHINE_FP"); fp != "" {
		fmt.Fprintf(os.Stderr, "[wrapper] WARNING: WRAPPER_MACHINE_FP override active — auth-key fingerprint bypassed\n")
		return fp, nil
	}
	return MachineFingerprint()
}

// shortAuthKeyFingerprint returns the first 16 chars of the auth-key fingerprint
// (includes WRAPPER_MACHINE_FP override if set). Used for compatibility checks
// in connection mode where the override must be honoured.
func shortAuthKeyFingerprint() string {
	fp, err := authKeyMachineFingerprint()
	if err != nil {
		return "unknown"
	}
	if len(fp) < 16 {
		return fp
	}
	return fp[:16]
}
