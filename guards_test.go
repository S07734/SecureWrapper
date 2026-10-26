package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSudoVaultOwner(t *testing.T) {
	home := t.TempDir()
	theirs := filepath.Join(home, vaultDir, vaultFile)
	os.MkdirAll(filepath.Dir(theirs), 0700)
	os.WriteFile(theirs, []byte("{}"), 0600)
	homeOf := func(string) (string, error) { return home, nil }

	cases := []struct {
		name     string
		euid     int
		sudoUser string
		ownVault bool
		homeOf   func(string) (string, error)
		want     string
	}{
		{"sudo misses the user's vault", 0, "alice", false, homeOf, theirs},
		{"not root", 1000, "alice", false, homeOf, ""},
		{"root login, no sudo", 0, "", false, homeOf, ""},
		{"sudo from root", 0, "root", false, homeOf, ""},
		{"root has its own vault", 0, "alice", true, homeOf, ""},
		{"unknown user", 0, "alice", false, func(string) (string, error) { return "", errors.New("no such user") }, ""},
		{"user has no vault", 0, "alice", false, func(string) (string, error) { return t.TempDir(), nil }, ""},
	}
	for _, c := range cases {
		if got := sudoVaultOwner(c.euid, c.sudoUser, c.ownVault, c.homeOf); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestCheckUpgradeWritable(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "wrapper")
	os.WriteFile(exe, []byte("bin"), 0700)
	if err := checkUpgradeWritable(exe); err != nil {
		t.Fatalf("writable dir rejected: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("check left files behind: %v", entries)
	}

	// A symlink in a read-only dir pointing at a writable one is fine: the
	// updater replaces the real file.
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		linkDir := t.TempDir()
		link := filepath.Join(linkDir, "wrapper")
		os.Symlink(exe, link)
		os.Chmod(linkDir, 0500)
		defer os.Chmod(linkDir, 0700)
		if err := checkUpgradeWritable(link); err != nil {
			t.Fatalf("symlink to writable binary rejected: %v", err)
		}

		os.Chmod(dir, 0500)
		defer os.Chmod(dir, 0700)
		if err := checkUpgradeWritable(exe); err == nil {
			t.Fatal("read-only dir accepted")
		}
	}
}
