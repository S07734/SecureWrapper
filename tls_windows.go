//go:build windows

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os/exec"
)

func getTLSConfig() *tls.Config {
	pool := x509.NewCertPool()
	loaded := false

	// Method 1: certutil
	if out, err := exec.Command("certutil", "-store", "Root").Output(); err == nil {
		rest := out
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					pool.AddCert(cert)
					loaded = true
				}
			}
		}
	}

	// Method 2: PowerShell
	if !loaded {
		psCmd := `Get-ChildItem Cert:\LocalMachine\Root | ForEach-Object {
"-----BEGIN CERTIFICATE-----"
[Convert]::ToBase64String($_.RawData, 'InsertLineBreaks')
"-----END CERTIFICATE-----"
}`
		if out, err := exec.Command("powershell", "-NoProfile", "-Command", psCmd).Output(); err == nil {
			rest := out
			for {
				var block *pem.Block
				block, rest = pem.Decode(rest)
				if block == nil {
					break
				}
				if block.Type == "CERTIFICATE" {
					if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
						pool.AddCert(cert)
						loaded = true
					}
				}
			}
		}
	}

	if loaded {
		return &tls.Config{RootCAs: pool}
	}

	// Don't fall back to InsecureSkipVerify — return nil and let it fail
	// with a clear error the user can act on
	return nil
}

// TLSDiagnostic returns info about why TLS might be failing on this machine.
func TLSDiagnostic() string {
	var diag string

	// Check certutil
	out, err := exec.Command("certutil", "-store", "Root").Output()
	if err != nil {
		diag += fmt.Sprintf("  certutil failed: %v\n", err)
	} else {
		count := 0
		rest := out
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				count++
			}
		}
		diag += fmt.Sprintf("  certutil: found %d root certificates\n", count)
	}

	// Check PowerShell
	psOut, err := exec.Command("powershell", "-NoProfile", "-Command",
		`(Get-ChildItem Cert:\LocalMachine\Root).Count`).Output()
	if err != nil {
		diag += fmt.Sprintf("  PowerShell cert check failed: %v\n", err)
	} else {
		diag += fmt.Sprintf("  PowerShell: %s root certificates in store\n", string(psOut))
	}

	return diag
}
