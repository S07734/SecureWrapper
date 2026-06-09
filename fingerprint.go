package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
)

// MachineFingerprint generates a stable fingerprint from hardware/OS identifiers.
// Uses platform-specific sources plus cross-platform network/hostname info.
// If WRAPPER_MACHINE_FP is set, its value is returned directly — hardware
// binding is bypassed. Intended for Docker containers that need to use the
// host's fingerprint. A warning is printed to stderr when the override is active.
func MachineFingerprint() (string, error) {
	if fp := os.Getenv("WRAPPER_MACHINE_FP"); fp != "" {
		fmt.Fprintf(os.Stderr, "[wrapper] WARNING: WRAPPER_MACHINE_FP override active — hardware binding bypassed\n")
		return fp, nil
	}

	var parts []string

	// Platform-specific identifiers (machine-id, CPU, disk serial)
	parts = append(parts, platformFingerprint()...)

	// Cross-platform: architecture
	parts = append(parts, "arch:"+runtime.GOARCH)

	// Cross-platform: MAC addresses (sorted, excluding loopback, virtual, and
	// platform-detected external adapters such as USB-C dock Ethernet ports).
	ifaces, err := net.Interfaces()
	if err == nil {
		excluded := make(map[string]bool)
		for _, name := range platformExcludedInterfaces() {
			excluded[name] = true
		}
		var macs []string
		for _, iface := range ifaces {
			if iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			if excluded[iface.Name] {
				continue
			}
			mac := iface.HardwareAddr.String()
			if mac != "" && !strings.HasPrefix(iface.Name, "veth") &&
				!strings.HasPrefix(iface.Name, "docker") &&
				!strings.HasPrefix(iface.Name, "br-") &&
				!strings.HasPrefix(iface.Name, "virbr") &&
				!strings.HasPrefix(iface.Name, "vmnet") &&
				!strings.HasPrefix(iface.Name, "tap") &&
				!strings.HasPrefix(iface.Name, "tun") &&
				!strings.HasPrefix(iface.Name, "wg") &&
				!strings.HasPrefix(iface.Name, "vnet") {
				macs = append(macs, mac)
			}
		}
		sort.Strings(macs)
		for _, mac := range macs {
			parts = append(parts, "mac:"+mac)
		}
	}

	// Hostname intentionally excluded — changes too easily and destabilizes fingerprint

	if len(parts) < 2 {
		return "", fmt.Errorf("insufficient hardware identifiers for fingerprint (got %d, need at least 2)", len(parts))
	}

	combined := strings.Join(parts, "|")
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:]), nil
}

// ShortFingerprint returns the first 16 chars of the fingerprint for display.
func ShortFingerprint() string {
	fp, err := MachineFingerprint()
	if err != nil {
		return "unknown"
	}
	return fp[:16]
}
