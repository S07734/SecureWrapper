package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// addTypeOption maps a menu entry to a connection type.
type addTypeOption struct {
	label string
	ct    ConnectionType
}

var addTypeOptions = []addTypeOption{
	{"SSH (password)", ConnSSHPassword},
	{"SSH (key)", ConnSSHKey},
	{"API (REST)", ConnAPI},
	{"FTP / SFTP", ConnFTP},
	{"Database (PostgreSQL)", ConnDBPostgres},
	{"Database (MySQL / MariaDB)", ConnDBMySQL},
	{"Database (SQL Server)", ConnDBMSSQL},
	{"WinRM / PowerShell", ConnWinRM},
}

// AddConnection is the type-selector that precedes the unified field-picker
// form. Navigation matches the Config submenu (up/down + Enter) for
// consistency across the TUI.
type AddConnection struct {
	vault  *Vault
	cursor int
}

func NewAddConnection(vault *Vault) AddConnection {
	return AddConnection{vault: vault}
}

func (ac AddConnection) Init() tea.Cmd { return nil }

func (ac AddConnection) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up":
			if ac.cursor > 0 {
				ac.cursor--
			}
		case "down":
			if ac.cursor < len(addTypeOptions)-1 {
				ac.cursor++
			}
		case "enter":
			chosen := addTypeOptions[ac.cursor].ct
			vault := ac.vault
			return ac, func() tea.Msg {
				return switchScreenMsg{
					screen: ScreenEditConnection,
					model:  NewAddConnectionForm(vault, chosen),
				}
			}
		case "esc", "b", "B":
			return ac, func() tea.Msg {
				return switchScreenMsg{screen: ScreenConnectionList, model: NewConnectionList(ac.vault)}
			}
		case "q", "Q":
			return ac, tea.Quit
		}
	}
	return ac, nil
}

func (ac AddConnection) View() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("\n  -- Add Connection --\n"))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("  Choose a connection type. The next screen lets you fill in fields in any order.") + "\n\n")

	for i, opt := range addTypeOptions {
		if i == ac.cursor {
			row := fmt.Sprintf("  %s", highlightStyle.Render(padRight(opt.label, 30)))
			b.WriteString(cursorStyle.Render(">") + row + "\n")
		} else {
			b.WriteString(fmt.Sprintf("   %s\n", connTargetStyle.Render(padRight(opt.label, 30))))
		}
	}

	b.WriteString("\n")
	b.WriteString(separatorStyle.Render("  "+strings.Repeat("-", 40)) + "\n")
	b.WriteString(fmt.Sprintf("  %s  %s\n",
		dimStyle.Render("Up/Down=navigate  Enter=select"),
		menuKeyStyle.Render("[B]")+" "+menuDescStyle.Render("Back"),
	))
	return b.String()
}
