package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// configItem represents a menu item in the config submenu.
type configItem struct {
	key   string
	label string
}

// ConfigMenu is the config submenu screen.
type ConfigMenu struct {
	vault  *Vault
	cursor int
	status string
	items  []configItem
}

func NewConfigMenu(vault *Vault) ConfigMenu {
	return ConfigMenu{
		vault:  vault,
		cursor: 0,
		items: []configItem{
			{key: "authkeys", label: "Auth Keys"},
			{key: "passphrase", label: "Change Passphrase"},
			{key: "backup", label: "Backup Vault"},
			{key: "restore", label: "Restore Vault"},
			{key: "hwexport", label: "Export for Hardware Migration"},
			{key: "updates", label: "Check for Updates"},
		},
	}
}

func (cm ConfigMenu) Init() tea.Cmd {
	return nil
}

func (cm ConfigMenu) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case statusMsg:
		cm.status = string(msg)
		return cm, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "up":
			if cm.cursor > 0 {
				cm.cursor--
			}
		case "down":
			if cm.cursor < len(cm.items)-1 {
				cm.cursor++
			}
		case "enter":
			return cm.activate()
		case "esc", "b", "B":
			return cm, func() tea.Msg {
				return switchScreenMsg{
					screen: ScreenConnectionList,
					model:  NewConnectionList(cm.vault),
				}
			}
		case "q", "Q":
			return cm, tea.Quit
		}
	}

	return cm, nil
}

func (cm ConfigMenu) activate() (tea.Model, tea.Cmd) {
	item := cm.items[cm.cursor]

	switch item.key {
	case "authkeys":
		return cm, func() tea.Msg {
			return switchScreenMsg{
				screen: ScreenAuthKeys,
				model:  NewAuthKeyList(cm.vault),
			}
		}

	case "passphrase":
		return cm, func() tea.Msg {
			return switchScreenMsg{
				screen: ScreenPassphrase,
				model:  NewPassphraseScreen(cm.vault),
			}
		}

	case "backup":
		cm.status = dimStyle.Render("Backing up vault...")
		return cm, func() tea.Msg {
			err := cm.vault.BackupVaultWithPassphrase()
			if err != nil {
				return statusMsg(errorStyle.Render(fmt.Sprintf("Backup failed: %v", err)))
			}
			return statusMsg(successStyle.Render("Portable vault backup created"))
		}

	case "restore":
		if !PortableBackupExists() {
			cm.status = warnStyle.Render("No portable backup found. Create one first via Backup.")
			return cm, nil
		}
		header := ReadPortableBackupHeader()
		info := ""
		if header != nil {
			info = fmt.Sprintf(" (%d connections, %d keys, saved %s)",
				header.ConnectionCount, header.AuthKeyCount, header.LastSaved)
		}
		return cm, func() tea.Msg {
			return switchScreenMsg{
				screen: ScreenConfirm,
				model: NewConfirm(
					fmt.Sprintf("Restore vault from backup%s? This will overwrite the current vault.", info),
					func() tea.Msg {
						return restoreCompleteMsg{}
					},
					func() tea.Msg {
						return switchScreenMsg{
							screen: ScreenConfig,
							model:  NewConfigMenu(cm.vault),
						}
					},
				),
			}
		}

	case "hwexport":
		return cm, func() tea.Msg {
			return switchScreenMsg{
				screen: ScreenHWExport,
				model:  NewHWMigrationExport(cm.vault),
			}
		}

	case "updates":
		return cm, func() tea.Msg {
			return upgradeRequestMsg{}
		}
	}

	return cm, nil
}

func (cm ConfigMenu) View() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("\n  -- Config --\n"))
	b.WriteString("\n")

	for i, item := range cm.items {
		if i == cm.cursor {
			row := fmt.Sprintf("  %s", highlightStyle.Render(padRight(item.label, 30)))
			b.WriteString(cursorStyle.Render(">") + row + "\n")
		} else {
			b.WriteString(fmt.Sprintf("   %s\n", connTargetStyle.Render(padRight(item.label, 30))))
		}
	}

	b.WriteString("\n")
	b.WriteString(separatorStyle.Render("  "+strings.Repeat("-", 40)) + "\n")
	b.WriteString(fmt.Sprintf("  %s  %s\n",
		dimStyle.Render("Up/Down=navigate  Enter=select"),
		menuKeyStyle.Render("[B]")+" "+menuDescStyle.Render("Back"),
	))

	if cm.status != "" {
		b.WriteString("\n  " + cm.status + "\n")
	}

	return b.String()
}
