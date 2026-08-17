//go:build linux

package main

import (
	"os"
	"strings"
)

func platformFingerprint() []string {
	var parts []string

	// /etc/machine-id
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		parts = append(parts, "machine-id:"+strings.TrimSpace(string(data)))
	}

	// CPU model from /proc/cpuinfo
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "model name") {
				parts = append(parts, "cpu:"+strings.TrimSpace(strings.SplitN(line, ":", 2)[1]))
				break
			}
		}
	}

	// NOTE: disk serial was intentionally removed (v0.1.45). It broke the
	// fingerprint whenever a disk was added/swapped/rebuilt (the selector
	// picked the first /sys/block device with a serial, so even adding an
	// NVMe to an sda-keyed box changed it) — the same class of instability
	// that got MAC addresses removed. machine-id + CPU + arch are stable
	// across a disk replacement.

	return parts
}
