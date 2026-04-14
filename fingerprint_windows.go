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

	// Disk serial via wmic
	if out, err := exec.Command("wmic", "diskdrive", "get", "SerialNumber").Output(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.Contains(strings.ToLower(line), "serialnumber") {
				parts = append(parts, "disk:"+line)
				break
			}
		}
	}

	// Computer name
	if name := os.Getenv("COMPUTERNAME"); name != "" {
		parts = append(parts, "computername:"+name)
	}

	return parts
}
