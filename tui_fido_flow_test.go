package main

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// Drives the exact TUI message chain for Config → Restore from FIDO2 Backup:
// menu activate → confirm screen → Y → fidoRestoreRequestMsg → App flag.
func TestConfigMenu_FIDORestoreFlow(t *testing.T) {
	v := testVaultWithConns(t, "Vault-Passphrase-77!x")
	fake := newFakeFIDO2()
	if _, err := v.ExportFIDOBackup(fidoTestPassword, "", fake, nil); err != nil {
		t.Fatalf("export: %v", err)
	}

	// Find and activate the fidorestore item.
	cm := NewConfigMenu(v)
	found := false
	for i, item := range cm.items {
		if item.key == "fidorestore" {
			cm.cursor = i
			found = true
			break
		}
	}
	if !found {
		t.Fatal("config menu has no fidorestore item")
	}

	_, cmd := cm.activate()
	if cmd == nil {
		t.Fatal("fidorestore item produced no command (FIDOBackupExists false?)")
	}
	msg := cmd()
	sw, ok := msg.(switchScreenMsg)
	if !ok {
		t.Fatalf("expected switchScreenMsg, got %T", msg)
	}
	confirm, ok := sw.model.(Confirm)
	if !ok {
		t.Fatalf("expected Confirm screen, got %T", sw.model)
	}

	// Press Y on the confirm dialog.
	_, cmd = confirm.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	if cmd == nil {
		t.Fatal("confirm Y produced no command")
	}
	msg = cmd()
	if _, ok := msg.(fidoRestoreRequestMsg); !ok {
		t.Fatalf("expected fidoRestoreRequestMsg from confirm, got %T: %v", msg, msg)
	}

	// App must set the fidoRestore flag and quit.
	app := NewApp(v)
	model, quitCmd := app.Update(fidoRestoreRequestMsg{})
	a, ok := model.(App)
	if !ok {
		t.Fatalf("expected App, got %T", model)
	}
	if !a.fidoRestore {
		t.Fatal("App did not set fidoRestore flag")
	}
	if quitCmd == nil {
		t.Fatal("App did not quit on fidoRestoreRequestMsg")
	}
}
