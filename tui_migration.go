package main

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type hwExportStep int

const (
	hwExportStepConfirm hwExportStep = iota
	hwExportStepShow
	hwExportStepError
)

// HWMigrationExport is the Config-submenu screen that generates a cross-machine
// migration file and displays the one-time code. The code is shown exactly once.
// The ACK gate is rendered on the same screen as the code so the admin
// confirms while looking at the code, not after it has already vanished.
type HWMigrationExport struct {
	vault *Vault
	step  hwExportStep
	code  string
	path  string
	err   string
	ack   string // user types ACK to confirm they've recorded the code
}

func NewHWMigrationExport(vault *Vault) HWMigrationExport {
	return HWMigrationExport{vault: vault, step: hwExportStepConfirm}
}

func (m HWMigrationExport) Init() tea.Cmd { return nil }

func (m HWMigrationExport) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch m.step {
		case hwExportStepConfirm:
			switch msg.String() {
			case "y", "Y", "enter":
				return m.performExport()
			case "n", "N", "esc", "b", "B":
				return m, backToConfig(m.vault)
			}

		case hwExportStepShow:
			switch msg.String() {
			case "enter":
				if strings.ToUpper(strings.TrimSpace(m.ack)) == "ACK" {
					return m, backToConfig(m.vault)
				}
				m.err = "Type ACK to confirm you've recorded the code."
				return m, nil
			case "backspace":
				if len(m.ack) > 0 {
					m.ack = m.ack[:len(m.ack)-1]
					m.err = ""
				}
				return m, nil
			case "esc":
				// Require the admin to ack before leaving — prevents accidental
				// dismissal with the code unrecorded.
				m.err = "Type ACK to confirm you've recorded the code, then press Enter."
				return m, nil
			default:
				if len(msg.String()) == 1 {
					m.ack += msg.String()
					m.err = ""
				}
				return m, nil
			}

		case hwExportStepError:
			return m, backToConfig(m.vault)
		}
	}
	return m, nil
}

func (m HWMigrationExport) performExport() (tea.Model, tea.Cmd) {
	code, path, err := m.vault.ExportHardwareMigration()
	if err != nil {
		m.step = hwExportStepError
		m.err = err.Error()
		return m, nil
	}
	m.code = code
	m.path = path
	m.step = hwExportStepShow
	return m, nil
}

func (m HWMigrationExport) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("\n  -- Hardware Migration Export --\n"))
	b.WriteString("\n")

	switch m.step {
	case hwExportStepConfirm:
		b.WriteString("  " + warnStyle.Render("Creates a cross-machine export of your connections.") + "\n")
		b.WriteString("\n")
		b.WriteString("  " + dimStyle.Render("• Encrypted with passphrase + a fresh one-time code") + "\n")
		b.WriteString("  " + dimStyle.Render("• Valid for 24 hours (network-time verified)") + "\n")
		b.WriteString("  " + dimStyle.Render("• Saved next to the wrapper binary for easy transport") + "\n")
		b.WriteString("  " + dimStyle.Render("• Auth keys are NOT migrated — regenerate on target machine") + "\n")
		b.WriteString("\n")
		b.WriteString("  Proceed? " + menuKeyStyle.Render("[Y]") + "es  " + menuKeyStyle.Render("[N]") + "o\n")

	case hwExportStepShow:
		b.WriteString("  " + successStyle.Render("Migration file written to:") + "\n")
		b.WriteString("  " + dimStyle.Render(m.path) + "\n")
		b.WriteString("\n")
		b.WriteString("  " + warnStyle.Render("ONE-TIME CODE — shown exactly once:") + "\n\n")
		b.WriteString(renderBigCode(m.code) + "\n\n")
		b.WriteString("  " + errorStyle.Render("Write it down now. It cannot be recovered.") + "\n")
		b.WriteString("  " + dimStyle.Render("This code is required on the destination machine to import.") + "\n")
		b.WriteString("  " + dimStyle.Render(fmt.Sprintf("Expires at %s", time.Now().Add(hwMigrationLifespan).Format(time.RFC1123))) + "\n")
		b.WriteString("\n")
		b.WriteString("  " + warnStyle.Render("Type ACK and press Enter to confirm you've recorded the code:") + "\n")
		b.WriteString("  > " + m.ack + cursorStyle.Render("_") + "\n")
		if m.err != "" {
			b.WriteString("\n  " + errorStyle.Render(m.err) + "\n")
		}

	case hwExportStepError:
		b.WriteString("  " + errorStyle.Render("Export failed: "+m.err) + "\n\n")
		b.WriteString("  " + dimStyle.Render("Press any key to return to Config") + "\n")
	}

	b.WriteString("\n")
	return b.String()
}

// renderBigCode displays the XXX-XXX-XXX code in a large, bold, bordered box
// so the admin can't miss it. MarginLeft (rather than a raw "  " prefix)
// indents every line of the multi-line box render — prefixing only indents
// the first line and skews the right/bottom edges.
func renderBigCode(code string) string {
	formatted := formatMigrationCode(code)
	return lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(yellow).
		Foreground(yellow).
		Bold(true).
		Padding(1, 4).
		MarginLeft(2).
		Align(lipgloss.Center).
		Render(formatted)
}

func backToConfig(vault *Vault) tea.Cmd {
	return func() tea.Msg {
		return switchScreenMsg{screen: ScreenConfig, model: NewConfigMenu(vault)}
	}
}
