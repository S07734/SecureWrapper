package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type passphraseStep int

const (
	passphraseStepNew passphraseStep = iota
	passphraseStepConfirm
	passphraseStepDone
)

// PassphraseScreen handles changing the vault passphrase. Enforces the
// project passphrase policy (see passphrase.go) and shows a live strength
// meter as the admin types.
type PassphraseScreen struct {
	vault   *Vault
	input   textinput.Model
	step    passphraseStep
	newPass string
	err     string
	status  string
}

func NewPassphraseScreen(vault *Vault) PassphraseScreen {
	ti := textinput.New()
	ti.Focus()
	ti.Prompt = promptStyle.Render("  ") + " "
	ti.EchoMode = textinput.EchoPassword
	ti.CharLimit = 256

	return PassphraseScreen{
		vault: vault,
		input: ti,
		step:  passphraseStepNew,
	}
}

func (ps PassphraseScreen) Init() tea.Cmd {
	return textinput.Blink
}

func (ps PassphraseScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			return ps, func() tea.Msg {
				return switchScreenMsg{
					screen: ScreenConfig,
					model:  NewConfigMenu(ps.vault),
				}
			}
		case "enter":
			return ps.advance()
		}
	}

	var cmd tea.Cmd
	ps.input, cmd = ps.input.Update(msg)
	return ps, cmd
}

func (ps PassphraseScreen) advance() (tea.Model, tea.Cmd) {
	val := ps.input.Value()
	ps.input.SetValue("")
	ps.err = ""

	switch ps.step {
	case passphraseStepNew:
		if err := ValidatePassphrase(val); err != nil {
			ps.err = err.Error()
			return ps, nil
		}
		ps.newPass = val
		ps.step = passphraseStepConfirm
		return ps, nil

	case passphraseStepConfirm:
		if val != ps.newPass {
			ps.err = "Passphrases don't match."
			ps.step = passphraseStepNew
			ps.newPass = ""
			return ps, nil
		}
		ps.vault.passphrase = ps.newPass
		if err := ps.vault.Save(); err != nil {
			ps.err = "Error saving: " + err.Error()
			return ps, nil
		}
		ps.status = successStyle.Render("Vault passphrase rotated.")
		ps.step = passphraseStepDone
		return ps, nil

	case passphraseStepDone:
		return ps, func() tea.Msg {
			return switchScreenMsg{
				screen: ScreenConnectionList,
				model:  NewConnectionList(ps.vault),
			}
		}
	}

	return ps, nil
}

func (ps PassphraseScreen) View() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("\n  -- Change Passphrase --\n"))
	b.WriteString("\n")

	switch ps.step {
	case passphraseStepNew:
		b.WriteString("  " + dimStyle.Render("Requirements: 12+ chars, upper, lower, digit, special, not common.") + "\n\n")
		b.WriteString("  New vault passphrase:\n")
		b.WriteString("  " + ps.input.View() + "\n\n")
		b.WriteString(renderStrengthMeter(ps.input.Value()))
	case passphraseStepConfirm:
		b.WriteString("  Confirm passphrase:\n")
		b.WriteString("  " + ps.input.View() + "\n")
	case passphraseStepDone:
		b.WriteString("  " + dimStyle.Render("Press enter to continue...") + "\n")
	}

	if ps.err != "" {
		b.WriteString("\n  " + errorStyle.Render(ps.err) + "\n")
	}
	if ps.status != "" {
		b.WriteString("\n  " + ps.status + "\n")
	}

	b.WriteString("\n  " + dimStyle.Render("Esc to cancel") + "\n")

	return b.String()
}

// renderStrengthMeter returns a two-line block: a filled/empty bar plus a
// label. Rendered during passphrase entry so admins see the advisory score
// update live (EchoNone hides the actual characters, not the length).
func renderStrengthMeter(pass string) string {
	if pass == "" {
		return "  " + dimStyle.Render(fmt.Sprintf("Length: 0  (min %d)", minPassphraseLen)) + "\n"
	}
	score, label := PassphraseStrength(pass)

	const cells = 20
	filled := (score * cells) / 4
	if filled > cells {
		filled = cells
	}

	var color lipgloss.Color
	switch score {
	case 4:
		color = green
	case 3:
		color = cyan
	case 2:
		color = yellow
	case 1:
		color = lipgloss.Color("#FFA500") // orange
	default:
		color = red
	}

	bar := lipgloss.NewStyle().Foreground(color).Bold(true).Render(strings.Repeat("█", filled)) +
		dimStyle.Render(strings.Repeat("░", cells-filled))

	meta := dimStyle.Render(fmt.Sprintf("length %d", len(pass)))
	labelStyled := lipgloss.NewStyle().Foreground(color).Bold(true).Render(label)

	return fmt.Sprintf("  %s  %s  %s\n", bar, labelStyled, meta)
}
