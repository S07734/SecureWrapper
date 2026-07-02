//go:build linux

package main

import (
	"fmt"
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

	// Disk serial from /sys/block
	if entries, err := os.ReadDir("/sys/block"); err == nil {
		for _, entry := range entries {
			serialPath := fmt.Sprintf("/sys/block/%s/device/serial", entry.Name())
			if data, err := os.ReadFile(serialPath); err == nil {
				serial := strings.TrimSpace(string(data))
				if serial != "" {
					parts = append(parts, "disk:"+serial)
					break
				}
			}
		}
	}

	return parts
}
