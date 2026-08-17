//go:build darwin

package main

import (
	"os/exec"
	"strings"
)

func platformFingerprint() []string {
	var parts []string

	// IOPlatformUUID — unique hardware identifier
	if out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "IOPlatformUUID") {
				if idx := strings.Index(line, "\""); idx >= 0 {
					uuid := strings.Trim(line[idx:], "\" ")
					// Extract just the UUID value after the = sign
					if eqIdx := strings.LastIndex(uuid, "\""); eqIdx > 0 {
						uuid = strings.Trim(uuid[eqIdx:], "\" ")
					}
					parts = append(parts, "machine-id:"+uuid)
				}
				break
			}
		}
	}

	// CPU model via sysctl
	if out, err := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output(); err == nil {
		parts = append(parts, "cpu:"+strings.TrimSpace(string(out)))
	}

	// Hardware model
	if out, err := exec.Command("sysctl", "-n", "hw.model").Output(); err == nil {
		parts = append(parts, "hw:"+strings.TrimSpace(string(out)))
	}

	// NOTE: disk serial was intentionally removed (v0.1.45) — it broke the
	// fingerprint on disk replacement/rebuild. IOPlatformUUID is hardware-
	// derived and stable across a disk swap or OS reinstall, so the macOS
	// fingerprint survives a rebuild with the same hardware.

	return parts
}
