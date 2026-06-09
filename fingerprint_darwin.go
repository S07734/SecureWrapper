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

	// Boot disk serial
	if out, err := exec.Command("system_profiler", "SPNVMeDataType").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "Serial Number") {
				serial := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
				if serial != "" {
					parts = append(parts, "disk:"+serial)
					break
				}
			}
		}
	}

	return parts
}

// platformExcludedInterfaces returns interface names that belong to removable
// external devices (USB-C docks, USB Ethernet adapters) and should be excluded
// from MAC fingerprinting. Uses networksetup to detect interfaces whose
// Hardware Port description contains "USB" — built-in ports never report this.
func platformExcludedInterfaces() []string {
	out, err := exec.Command("networksetup", "-listallhardwareports").Output()
	if err != nil {
		return nil
	}
	var excluded []string
	var portType string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Hardware Port:") {
			portType = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "Hardware Port:")))
		} else if strings.HasPrefix(line, "Device:") {
			device := strings.TrimSpace(strings.TrimPrefix(line, "Device:"))
			if strings.Contains(portType, "usb") && device != "" {
				excluded = append(excluded, device)
			}
			portType = ""
		}
	}
	return excluded
}
