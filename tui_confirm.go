package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// confirmResultMsg is sent when the confirm dialog is answered.
type confirmResultMsg struct {
	confirmed bool
}

// Confirm is a reusable Y/N confirmation dialog.
type Confirm struct {
	message   string
	onConfirm func() tea.Msg
	onCancel  func() tea.Msg
}

func NewConfirm(message string, onConfirm func() tea.Msg, onCancel func() tea.Msg) Confirm {
	return Confirm{
		message:   message,
		onConfirm: onConfirm,
		onCancel:  onCancel,
	}
}

func (c Confirm) Init() tea.Cmd {
	return nil
}

func (c Confirm) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "y", "Y":
			if c.onConfirm != nil {
				return c, func() tea.Msg { return c.onConfirm() }
			}
			return c, nil
		case "n", "N", "esc":
			if c.onCancel != nil {
				return c, func() tea.Msg { return c.onCancel() }
			}
			return c, nil
		}
	}

	return c, nil
}

func (c Confirm) View() string {
	var b strings.Builder

	b.WriteString("\n\n")
	b.WriteString(fmt.Sprintf("  %s\n\n", warnStyle.Render(c.message)))
	b.WriteString(fmt.Sprintf("  %s %s  %s %s\n",
		menuKeyStyle.Render("[Y]"), menuDescStyle.Render("Yes"),
		menuKeyStyle.Render("[N]"), menuDescStyle.Render("No"),
	))

	return b.String()
}
