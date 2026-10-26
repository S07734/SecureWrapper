package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
)

// sudoVaultOwner returns the invoking user's vault path when this is a sudo
// run that would miss it. sudo switches HOME to root's, so the wrapper would
// look in /root/.secure-wrapper and report "no vault" (or offer to create
// one) while the real vault sits in the invoking user's home. Returns ""
// when this is not a sudo run, or root has a vault of its own.
func sudoVaultOwner(euid int, sudoUser string, ownVault bool, homeOf func(string) (string, error)) string {
	if euid != 0 || sudoUser == "" || sudoUser == "root" || ownVault {
		return ""
	}
	home, err := homeOf(sudoUser)
	if err != nil {
		return ""
	}
	theirs := filepath.Join(home, vaultDir, vaultFile)
	if _, err := os.Stat(theirs); err != nil {
		return ""
	}
	return theirs
}

func lookupHome(name string) (string, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return "", err
	}
	return u.HomeDir, nil
}

// checkNotSudo exits with an explanation instead of letting a sudo run fall
// through to the wrong (empty) vault location.
func checkNotSudo() {
	sudoUser := os.Getenv("SUDO_USER")
	theirs := sudoVaultOwner(os.Geteuid(), sudoUser, VaultExists(), lookupHome)
	if theirs == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "Error: running under sudo. The vault belongs to %s (%s),\n", sudoUser, theirs)
	fmt.Fprintln(os.Stderr, "but sudo switched to root's home folder, which has no vault.")
	fmt.Fprintln(os.Stderr, "Run wrapper without sudo. If updating needs sudo to replace the binary,")
	fmt.Fprintln(os.Stderr, "install the binary in a folder you own instead (e.g. ~/.local/bin).")
	os.Exit(1)
}

// checkUpgradeWritable reports whether the in-app updater can replace the
// binary at exePath. It downloads beside the binary and renames into place,
// so it needs write access to that folder, not just to the file.
func checkUpgradeWritable(exePath string) error {
	if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
		exePath = resolved
	}
	dir := filepath.Dir(exePath)
	f, err := os.CreateTemp(dir, ".wrapper-update-check-*")
	if err != nil {
		return fmt.Errorf("%s is not writable by you, so the update cannot replace the binary there", dir)
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return nil
}
