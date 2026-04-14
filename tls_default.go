//go:build !windows

package main

import "crypto/tls"

func getTLSConfig() *tls.Config {
	return nil
}

func TLSDiagnostic() string {
	return "  TLS uses system certificate pool (Linux/macOS)\n"
}
