package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// authKeyMode tracks the sub-mode of the auth key screen.
type authKeyMode int

const (
	authKeyModeList authKeyMode = iota
	authKeyModeGenerateName
	authKeyModeGenerateChecklist
	authKeyModeShowKey
	authKeyModeEditAccess
)

// AuthKeyList is the auth key management screen.
type AuthKeyList struct {
	vault       *Vault
	cursor      int
	mode        authKeyMode
	input       textinput.Model
	newKeyName  string
	generatedKey string
	status      string
	err         string
	checklist   *Checklist
}

func NewAuthKeyList(vault *Vault) AuthKeyList {
	ti := textinput.New()
	ti.Prompt = promptStyle.Render("  ") + " "
	ti.CharLimit = 128

	return AuthKeyList{
		vault: vault,
		input: ti,
	}
}

func (akl AuthKeyList) Init() tea.Cmd {
	return nil
}

func (akl AuthKeyList) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// If checklist is active, delegate to it
	if akl.mode == authKeyModeGenerateChecklist || akl.mode == authKeyModeEditAccess {
		if akl.checklist != nil {
			switch msg := msg.(type) {
			case checklistResultMsg:
				if akl.mode == authKeyModeGenerateChecklist {
					return akl.finishGenerate(msg)
				}
				return akl.finishEditAccess(msg)
			default:
				var cmd tea.Cmd
				newCL, cmd := akl.checklist.Update(msg)
				cl := newCL.(Checklist)
				akl.checklist = &cl
				return akl, cmd
			}
		}
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Handle generate name mode
		if akl.mode == authKeyModeGenerateName {
			switch msg.String() {
			case "esc":
				akl.mode = authKeyModeList
				akl.input.Blur()
				return akl, nil
			case "enter":
				name := strings.TrimSpace(akl.input.Value())
				if name == "" {
					akl.err = "Name is required."
					return akl, nil
				}
				akl.newKeyName = name
				akl.input.SetValue("")
				akl.input.Blur()

				// Open checklist for connection selection
				conns := akl.vault.ListConnections()
				if len(conns) == 0 {
					// No connections, generate with all access
					return akl.generateKey(nil)
				}
				items := make([]string, len(conns))
				for i, c := range conns {
					items[i] = c.Name
				}
				selected := make([]bool, len(conns))
				cl := NewChecklist("Restrict to connections (Enter=all, Space=toggle):", items, selected)
				akl.checklist = &cl
				akl.mode = authKeyModeGenerateChecklist
				return akl, nil
			}

			var cmd tea.Cmd
			akl.input, cmd = akl.input.Update(msg)
			return akl, cmd
		}

		// Handle show key mode
		if akl.mode == authKeyModeShowKey {
			if msg.String() == "enter" || msg.String() == "esc" {
				akl.mode = authKeyModeList
				akl.generatedKey = ""
				akl.status = ""
				return akl, nil
			}
			return akl, nil
		}

		// List mode
		keys := akl.vault.ListAuthKeys()
		switch msg.String() {
		case "up", "k":
			if akl.cursor > 0 {
				akl.cursor--
			}
		case "down", "j":
			if akl.cursor < len(keys)-1 {
				akl.cursor++
			}
		case "g", "G":
			akl.mode = authKeyModeGenerateName
			akl.input.Focus()
			akl.err = ""
			return akl, textinput.Blink
		case "e", "E":
			if len(keys) > 0 {
				key := keys[akl.cursor]
				conns := akl.vault.ListConnections()
				items := make([]string, len(conns))
				selected := make([]bool, len(conns))
				allowedMap := make(map[string]bool)
				for _, name := range key.AllowedConns {
					allowedMap[name] = true
				}
				for i, c := range conns {
					items[i] = c.Name
					if len(key.AllowedConns) == 0 || allowedMap[c.Name] {
						selected[i] = true
					}
				}
				cl := NewChecklist(fmt.Sprintf("Edit access for \"%s\":", key.Name), items, selected)
				akl.checklist = &cl
				akl.mode = authKeyModeEditAccess
				return akl, nil
			}
		case "r", "R":
			if len(keys) > 0 {
				key := keys[akl.cursor]
				return akl, func() tea.Msg {
					return switchScreenMsg{
						screen: ScreenConfirm,
						model: NewConfirm(
							fmt.Sprintf("Revoke auth key \"%s\"?", key.Name),
							func() tea.Msg {
								akl.vault.RevokeAuthKey(key.Name)
								akl.vault.Save()
								return switchScreenMsg{
									screen: ScreenAuthKeys,
									model:  NewAuthKeyList(akl.vault),
								}
							},
							func() tea.Msg {
								return switchScreenMsg{
									screen: ScreenAuthKeys,
									model:  NewAuthKeyList(akl.vault),
								}
							},
						),
					}
				}
			}
		case "b", "B", "esc":
			return akl, func() tea.Msg {
				return switchScreenMsg{
					screen: ScreenConfig,
					model:  NewConfigMenu(akl.vault),
				}
			}
		}
	}

	return akl, nil
}

func (akl AuthKeyList) finishGenerate(result checklistResultMsg) (tea.Model, tea.Cmd) {
	if result.cancelled {
		akl.mode = authKeyModeList
		akl.checklist = nil
		return akl, nil
	}

	var allowedConns []string
	allSelected := true
	for i, sel := range result.selected {
		if !sel {
			allSelected = false
		}
		if sel {
			allowedConns = append(allowedConns, result.items[i])
		}
	}

	// If all selected or none selected, grant all access
	if allSelected || len(allowedConns) == 0 {
		allowedConns = nil
	}

	akl.checklist = nil
	return akl.generateKey(allowedConns)
}

func (akl AuthKeyList) generateKey(allowedConns []string) (tea.Model, tea.Cmd) {
	key, err := akl.vault.AddAuthKey(akl.newKeyName, allowedConns...)
	if err != nil {
		akl.err = fmt.Sprintf("Error: %v", err)
		akl.mode = authKeyModeList
		return akl, nil
	}
	if err := akl.vault.Save(); err != nil {
		akl.err = fmt.Sprintf("Error saving: %v", err)
		akl.mode = authKeyModeList
		return akl, nil
	}

	akl.generatedKey = key
	akl.status = successStyle.Render("Auth key generated. Copy now -- it will NOT be shown again.")
	akl.mode = authKeyModeShowKey
	return akl, nil
}

func (akl AuthKeyList) finishEditAccess(result checklistResultMsg) (tea.Model, tea.Cmd) {
	akl.checklist = nil
	if result.cancelled {
		akl.mode = authKeyModeList
		return akl, nil
	}

	keys := akl.vault.ListAuthKeys()
	if akl.cursor >= len(keys) {
		akl.mode = authKeyModeList
		return akl, nil
	}

	var allowedConns []string
	allSelected := true
	for i, sel := range result.selected {
		if !sel {
			allSelected = false
		}
		if sel {
			allowedConns = append(allowedConns, result.items[i])
		}
	}

	if allSelected || len(allowedConns) == 0 {
		akl.vault.ListAuthKeys()[akl.cursor].AllowedConns = nil
	} else {
		akl.vault.ListAuthKeys()[akl.cursor].AllowedConns = allowedConns
	}

	if err := akl.vault.Save(); err != nil {
		akl.err = fmt.Sprintf("Error saving: %v", err)
	} else {
		akl.status = successStyle.Render("Access updated.")
	}
	akl.mode = authKeyModeList
	return akl, nil
}

func (akl AuthKeyList) View() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("\n  -- Auth Keys --\n"))
	b.WriteString("\n")

	// Show key mode
	if akl.mode == authKeyModeShowKey {
		b.WriteString("  " + successStyle.Render("Auth key generated:") + "\n\n")
		b.WriteString("  " + connNameStyle.Render(akl.generatedKey) + "\n\n")
		b.WriteString("  " + warnStyle.Render("Copy this now -- it will NOT be shown again.") + "\n\n")
		b.WriteString("  " + dimStyle.Render("Press enter to continue...") + "\n")
		return b.String()
	}

	// Generate name mode
	if akl.mode == authKeyModeGenerateName {
		b.WriteString("  Key name:\n")
		b.WriteString("  " + akl.input.View() + "\n")
		if akl.err != "" {
			b.WriteString("\n  " + errorStyle.Render(akl.err) + "\n")
		}
		b.WriteString("\n  " + dimStyle.Render("Esc to cancel") + "\n")
		return b.String()
	}

	// Checklist modes
	if (akl.mode == authKeyModeGenerateChecklist || akl.mode == authKeyModeEditAccess) && akl.checklist != nil {
		b.WriteString(akl.checklist.View())
		return b.String()
	}

	// Key list
	keys := akl.vault.ListAuthKeys()
	if len(keys) == 0 {
		b.WriteString(warnStyle.Render("  No auth keys configured -- all local callers allowed.\n"))
	} else {
		b.WriteString(fmt.Sprintf("  %s  %s  %s  %s\n",
			headerStyle.Render(padRight("NAME", 18)),
			headerStyle.Render(padRight("CREATED", 20)),
			headerStyle.Render(padRight("LAST USED", 20)),
			headerStyle.Render("ACCESS"),
		))
		b.WriteString(separatorStyle.Render("  "+strings.Repeat("-", 70)) + "\n")

		// Real operator-use timestamps live in the unencrypted key_usage.json
		// (written by OpenVaultWithAuthKey). The vault's AuthKey.LastUsed is a
		// stale fallback — rarely updated because we don't re-save the encrypted
		// vault on every auth-key use.
		usage := LoadKeyUsage()
		for i, k := range keys {
			lastUsed := usage[k.Name]
			if lastUsed == "" {
				lastUsed = k.LastUsed
			}
			if lastUsed == "" {
				lastUsed = dimStyle.Render("never")
			}
			access := connTypeStyle.Render("all")
			if len(k.AllowedConns) > 0 {
				access = dimStyle.Render(strings.Join(k.AllowedConns, ", "))
			}

			nameCol := padRight(k.Name, 18)
			createdCol := padRight(k.CreatedAt, 20)
			lastUsedCol := padRight(lastUsed, 20)

			if i == akl.cursor {
				row := fmt.Sprintf("  %s  %s  %s  %s",
					highlightStyle.Render(nameCol),
					highlightStyle.Render(createdCol),
					highlightStyle.Render(lastUsedCol),
					access,
				)
				b.WriteString(cursorStyle.Render(">") + row + "\n")
			} else {
				b.WriteString(fmt.Sprintf("   %s  %s  %s  %s\n",
					connNameStyle.Render(nameCol),
					connTargetStyle.Render(createdCol),
					connTargetStyle.Render(lastUsedCol),
					access,
				))
			}
		}
	}

	b.WriteString("\n")
	b.WriteString(separatorStyle.Render("  "+strings.Repeat("-", 70)) + "\n")
	b.WriteString(fmt.Sprintf("  %s %s  %s %s  %s %s  %s %s\n",
		menuKeyStyle.Render("[G]"), menuDescStyle.Render("Generate"),
		menuKeyStyle.Render("[E]"), menuDescStyle.Render("Edit access"),
		menuKeyStyle.Render("[R]"), menuDescStyle.Render("Revoke"),
		menuKeyStyle.Render("[B]"), menuDescStyle.Render("Back"),
	))

	if akl.err != "" {
		b.WriteString("\n  " + errorStyle.Render(akl.err) + "\n")
	}
	if akl.status != "" {
		b.WriteString("\n  " + akl.status + "\n")
	}

	return b.String()
}
