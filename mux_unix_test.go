//go:build linux || darwin

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMuxDirUsesPrivateRuntimeDir(t *testing.T) {
	rt := t.TempDir()
	os.Chmod(rt, 0700)
	t.Setenv("XDG_RUNTIME_DIR", rt)
	if got, want := muxDir(), filepath.Join(rt, "securewrapper"); got != want {
		t.Fatalf("muxDir = %q, want %q", got, want)
	}
	if strings.HasPrefix(muxDir(), vaultDirPath()) {
		t.Fatal("sockets inside the vault directory; copies of it would carry them")
	}
}

func TestMuxDirRejectsSharedRuntimeDir(t *testing.T) {
	rt := t.TempDir()
	os.Chmod(rt, 0777)
	t.Setenv("XDG_RUNTIME_DIR", rt)
	if got := muxDir(); got != legacyMuxDir() {
		t.Fatalf("world-writable runtime dir accepted: %q", got)
	}
}

func TestMuxDirFallsBackWithoutRuntimeDir(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")
	if got := muxDir(); got != legacyMuxDir() {
		t.Fatalf("muxDir = %q, want fallback %q", got, legacyMuxDir())
	}
}

func TestCleanLegacyMuxDirKeepsLiveMasters(t *testing.T) {
	dir := legacyMuxDir()
	os.MkdirAll(dir, 0700)
	t.Cleanup(func() { os.RemoveAll(dir) })
	os.WriteFile(filepath.Join(dir, "dead.sock.lock"), nil, 0600)
	os.WriteFile(filepath.Join(dir, "live.sock"), nil, 0600)
	os.WriteFile(filepath.Join(dir, "live.sock.lock"), nil, 0600)

	cleanLegacyMuxDir()
	if _, err := os.Stat(filepath.Join(dir, "dead.sock.lock")); !os.IsNotExist(err) {
		t.Fatal("stale lock kept")
	}
	if _, err := os.Stat(filepath.Join(dir, "live.sock.lock")); err != nil {
		t.Fatal("running master's lock removed")
	}

	os.Remove(filepath.Join(dir, "live.sock"))
	cleanLegacyMuxDir()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("empty legacy dir not removed")
	}
}
