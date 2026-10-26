//go:build !linux && !darwin

package main

import (
	"fmt"
	"os"
)

// Connection sharing needs setsid + flock; elsewhere every call dials directly.

func enableMux(conn Connection) {}

func runMuxMaster() {
	fmt.Fprintln(os.Stderr, "Error: connection sharing is not supported on this platform")
	os.Exit(1)
}

func muxControl(conn Connection, op string) {
	fmt.Fprintln(os.Stderr, "Error: connection sharing is not supported on this platform")
	os.Exit(1)
}
