//go:build windows

package main

import (
	"os"
	"os/exec"
	"strings"
)

func platformFingerprint() []string {
	var parts []string

	// MachineGuid from registry
	if out, err := exec.Command("reg", "query",
		`HKLM\SOFTWARE\Microsoft\Cryptography`,
		"/v", "MachineGuid").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "MachineGuid") {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					parts = append(parts, "machine-id:"+fields[len(fields)-1])
				}
				break
			}
		}
	}

	// Processor identifier from environment
	if cpu := os.Getenv("PROCESSOR_IDENTIFIER"); cpu != "" {
		parts = append(parts, "cpu:"+cpu)
	}

	// NOTE: disk serial was intentionally removed (v0.1.45) — it broke the
	// fingerprint on disk replacement/rebuild, and `wmic` is deprecated on
	// newer Windows 11 builds (returned empty there anyway). MachineGuid +
	// CPU + computer name remain.

	// Computer name
	if name := os.Getenv("COMPUTERNAME"); name != "" {
		parts = append(parts, "computername:"+name)
	}

	return parts
}
