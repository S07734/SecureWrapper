package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// freshVault creates a vault in the sandboxed HOME, written by this binary.
func freshVault(t *testing.T) {
	t.Helper()
	os.RemoveAll(vaultDirPath())
	if _, err := CreateVault("test-passphrase-123"); err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
}

// setHeaderBinaryFP rewrites vault.enc's header as if another build wrote it.
func setHeaderBinaryFP(t *testing.T, fp string) {
	t.Helper()
	raw, err := os.ReadFile(vaultPath())
	if err != nil {
		t.Fatal(err)
	}
	var vf map[string]any
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatal(err)
	}
	vf["header"].(map[string]any)["binary_fp"] = fp
	out, _ := json.Marshal(vf)
	if err := os.WriteFile(vaultPath(), out, 0600); err != nil {
		t.Fatal(err)
	}
}

func writeFakeBinary(t *testing.T, name, content string) (string, string) {
	t.Helper()
	p := filepath.Join(vaultDirPath(), name)
	if err := os.WriteFile(p, []byte(content), 0700); err != nil {
		t.Fatal(err)
	}
	fp, err := binaryFileFingerprint(p)
	if err != nil {
		t.Fatal(err)
	}
	return p, fp
}

func TestBackupVaultSavesRunningBinary(t *testing.T) {
	freshVault(t)
	older, _ := writeFakeBinary(t, "wrapper-v0.0.1-1111111111111111.backup", "older build")

	if err := BackupVault(); err != nil {
		t.Fatalf("BackupVault: %v", err)
	}
	if _, err := os.Stat(vaultPath() + ".backup"); err != nil {
		t.Fatalf("vault.enc.backup missing: %v", err)
	}

	saved := backupBinaryPath(version, BinaryKeyFingerprint())
	fp, err := binaryFileFingerprint(saved)
	if err != nil {
		t.Fatalf("saved binary missing: %v", err)
	}
	if fp != BinaryKeyFingerprint() || fp != ReadVaultHeader().BinaryFP {
		t.Fatalf("saved binary fp %s, running %s, header %s", fp, BinaryKeyFingerprint(), ReadVaultHeader().BinaryFP)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(saved); fi.Mode().Perm() != 0700 {
			t.Fatalf("saved binary perms = %v, want 0700 (runnable for restore)", fi.Mode().Perm())
		}
	}
	if _, err := os.Stat(older); err != nil {
		t.Fatal("an older saved binary was removed; other vault copies may need it")
	}
}

func TestBackupVaultDoesNotDuplicateSavedBinary(t *testing.T) {
	freshVault(t)
	for i := 0; i < 3; i++ {
		if err := BackupVault(); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(backupBinaries()); n != 1 {
		t.Fatalf("%d saved binaries after repeated backups, want 1", n)
	}
}

func TestBackupVaultLeavesSavedBinariesForForeignVault(t *testing.T) {
	freshVault(t)
	a, _ := writeFakeBinary(t, "wrapper-v0.0.9-aaaaaaaaaaaaaaaa.backup", "some build")
	b, _ := writeFakeBinary(t, "wrapper-v0.0.8-bbbbbbbbbbbbbbbb.backup", "another build")
	setHeaderBinaryFP(t, "0000000000000000")

	if err := BackupVault(); err != nil {
		t.Fatalf("BackupVault: %v", err)
	}
	for _, p := range []string{a, b} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s removed", filepath.Base(p))
		}
	}
	if _, err := os.Stat(backupBinaryPath(version, BinaryKeyFingerprint())); !os.IsNotExist(err) {
		t.Fatal("running binary saved for a vault it cannot open")
	}
}

func TestWipeVaultPreservesSavedBinaries(t *testing.T) {
	freshVault(t)
	if err := BackupVault(); err != nil {
		t.Fatal(err)
	}
	WipeVault()
	if len(backupBinaries()) != 1 {
		t.Fatal("wipe removed a saved binary")
	}
}

// Config → Backup writes only the portable backup, but the vault directory it
// leaves behind still needs the binary that opens vault.enc.
func TestPortableBackupSavesRunningBinary(t *testing.T) {
	os.RemoveAll(vaultDirPath())
	v, err := CreateVault("test-passphrase-123")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	if err := v.BackupVaultWithPassphrase(); err != nil {
		t.Fatalf("BackupVaultWithPassphrase: %v", err)
	}
	if _, err := os.Stat(backupBinaryPath(version, BinaryKeyFingerprint())); err != nil {
		t.Fatalf("running binary not saved: %v", err)
	}
	if _, err := os.Stat(vaultPath() + ".backup"); !os.IsNotExist(err) {
		t.Fatal("portable backup overwrote vault.enc.backup (the pre-upgrade raw copy)")
	}
}
