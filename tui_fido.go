package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type fidoExportStep int

const (
	fidoStepIntro fidoExportStep = iota
	fidoStepPassword
	fidoStepConfirm
	fidoStepPIN
	fidoStepRunning
	fidoStepDone
	fidoStepError
)

type fidoExportResultMsg struct {
	path string
	err  error
}

// FIDOExport is the Config-submenu screen that creates a security-key
// protected backup: password + hmac-secret from a FIDO2 key (YubiKey etc.).
// The device calls run in a tea.Cmd goroutine; the key blinks for two
// touches while the Running view explains what to do.
type FIDOExport struct {
	vault    *Vault
	step     fidoExportStep
	input    textinput.Model
	password string
	pin      string
	path     string
	err      string
}

func NewFIDOExport(vault *Vault) FIDOExport {
	ti := textinput.New()
	ti.Focus()
	ti.Prompt = promptStyle.Render("  ") + " "
	ti.EchoMode = textinput.EchoPassword
	ti.CharLimit = 256

	return FIDOExport{vault: vault, step: fidoStepIntro, input: ti}
}

func (m FIDOExport) Init() tea.Cmd { return textinput.Blink }

func (m FIDOExport) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case fidoExportResultMsg:
		if msg.err != nil {
			if errors.Is(msg.err, errFIDO2PINRequired) {
				m.step = fidoStepPIN
				m.err = "This security key requires its PIN."
				m.input.SetValue("")
				return m, nil
			}
			m.step = fidoStepError
			m.err = msg.err.Error()
			return m, nil
		}
		m.step = fidoStepDone
		m.path = msg.path
		return m, nil

	case tea.KeyMsg:
		switch m.step {
		case fidoStepIntro:
			switch msg.String() {
			case "y", "Y", "enter":
				m.step = fidoStepPassword
				return m, nil
			case "n", "N", "esc", "b", "B":
				return m, backToConfig(m.vault)
			}
			return m, nil

		case fidoStepPassword, fidoStepConfirm, fidoStepPIN:
			switch msg.String() {
			case "esc":
				return m, backToConfig(m.vault)
			case "enter":
				return m.advance()
			}

		case fidoStepRunning:
			return m, nil // ignore keys while the device call is in flight

		case fidoStepDone, fidoStepError:
			return m, backToConfig(m.vault)
		}
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m FIDOExport) advance() (tea.Model, tea.Cmd) {
	val := m.input.Value()
	m.input.SetValue("")
	m.err = ""

	switch m.step {
	case fidoStepPassword:
		if err := ValidatePassphrase(val); err != nil {
			m.err = err.Error()
			return m, nil
		}
		m.password = val
		m.step = fidoStepConfirm
		return m, nil

	case fidoStepConfirm:
		if val != m.password {
			m.err = "Passwords do not match."
			m.step = fidoStepPassword
			m.password = ""
			return m, nil
		}
		m.step = fidoStepPIN
		return m, nil

	case fidoStepPIN:
		m.pin = val
		m.step = fidoStepRunning
		return m, m.runExport()
	}
	return m, nil
}

func (m FIDOExport) runExport() tea.Cmd {
	vault, password, pin := m.vault, m.password, m.pin
	return func() tea.Msg {
		path, err := vault.ExportFIDOBackup(password, pin, newFIDO2Provider(), nil)
		return fidoExportResultMsg{path: path, err: err}
	}
}

func (m FIDOExport) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("\n  -- FIDO2 Security Key Backup --\n"))
	b.WriteString("\n")

	switch m.step {
	case fidoStepIntro:
		b.WriteString("  " + warnStyle.Render("Creates a backup that needs BOTH a password AND your security key.") + "\n\n")
		b.WriteString("  " + dimStyle.Render("• Works on any machine — survives hardware death (unlike portable backup)") + "\n")
		b.WriteString("  " + dimStyle.Render("• Restoring requires: this file + the password + the physical key") + "\n")
		b.WriteString("  " + dimStyle.Render("• The key must support FIDO2 hmac-secret (YubiKey 5+, most CTAP2 keys)") + "\n")
		b.WriteString("  " + dimStyle.Render("• You will touch the key twice during export") + "\n")
		b.WriteString("  " + dimStyle.Render("• Losing the key OR the password makes the backup undecryptable") + "\n")
		b.WriteString("\n")
		b.WriteString("  Plug in your security key, then proceed. " + menuKeyStyle.Render("[Y]") + "es  " + menuKeyStyle.Render("[N]") + "o\n")

	case fidoStepPassword:
		b.WriteString("  Backup password " + dimStyle.Render("(becomes the vault passphrase on restore)") + "\n")
		b.WriteString("  " + dimStyle.Render("Policy: 12+ chars, upper, lower, digit, special.") + "\n\n")
		b.WriteString(m.input.View() + "\n")

	case fidoStepConfirm:
		b.WriteString("  Confirm backup password:\n\n")
		b.WriteString(m.input.View() + "\n")

	case fidoStepPIN:
		b.WriteString("  Security key PIN " + dimStyle.Render("(press Enter if the key has no PIN)") + "\n\n")
		b.WriteString(m.input.View() + "\n")

	case fidoStepRunning:
		b.WriteString("  " + warnStyle.Render("Touch your security key when it blinks — TWICE:") + "\n\n")
		b.WriteString("  " + dimStyle.Render("1st touch: enrolls the backup credential") + "\n")
		b.WriteString("  " + dimStyle.Render("2nd touch: derives the backup encryption secret") + "\n")

	case fidoStepDone:
		b.WriteString("  " + successStyle.Render("FIDO2 backup created:") + "\n")
		b.WriteString("  " + dimStyle.Render(m.path) + "\n\n")
		b.WriteString("  " + warnStyle.Render("Store a copy off this machine (it is useless without key + password).") + "\n")
		b.WriteString("  " + dimStyle.Render("Restore needs: file + password + THIS security key.") + "\n\n")
		b.WriteString("  " + dimStyle.Render("Press any key to return to Config") + "\n")

	case fidoStepError:
		b.WriteString("  " + errorStyle.Render("Backup failed: "+m.err) + "\n\n")
		b.WriteString("  " + dimStyle.Render("Press any key to return to Config") + "\n")
	}

	if m.err != "" && m.step != fidoStepError {
		b.WriteString("\n  " + errorStyle.Render(m.err) + "\n")
	}
	if m.step >= fidoStepPassword && m.step <= fidoStepPIN {
		b.WriteString("\n  " + dimStyle.Render("Enter=next  Esc=cancel") + "\n")
	}
	b.WriteString("\n")
	return b.String()
}

// fidoRestoreInfo renders the one-line summary of the existing FIDO2 backup
// shown in prompts.
func fidoRestoreInfo() string {
	header := ReadFIDOBackupHeader()
	if header == nil {
		return ""
	}
	return fmt.Sprintf(" (%d connections, %d keys, saved %s)",
		header.ConnectionCount, header.AuthKeyCount, header.LastSaved)
}
