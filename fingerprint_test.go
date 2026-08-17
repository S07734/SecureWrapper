package main

import (
	"strings"
	"testing"
)

// Disk serial was removed from the machine fingerprint (v0.1.45): the selector
// picked the first block device with a serial, so adding/swapping/rebuilding a
// disk changed the fingerprint and locked the passphrase path — the same
// instability that got MAC addresses removed. Guard against reintroduction.
func TestPlatformFingerprint_NoDiskSerial(t *testing.T) {
	for _, p := range platformFingerprint() {
		if strings.HasPrefix(p, "disk:") {
			t.Fatalf("fingerprint must not include a disk serial (removed v0.1.45), got %q", p)
		}
	}
}

// The composed fingerprint must still derive, be non-empty, and be stable
// across repeated calls on the same machine.
func TestMachineFingerprint_StableAndNonEmpty(t *testing.T) {
	fp1, err := MachineFingerprint()
	if err != nil {
		t.Fatalf("MachineFingerprint: %v", err)
	}
	if fp1 == "" {
		t.Fatal("empty fingerprint")
	}
	if fp2, _ := MachineFingerprint(); fp1 != fp2 {
		t.Fatalf("fingerprint not stable across calls: %q vs %q", fp1, fp2)
	}
}
