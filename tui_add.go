package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// addTypeOption maps a numeric key choice to a connection type.
type addTypeOption struct {
	key   string
	label string
	ct    ConnectionType
}

var addTypeOptions = []addTypeOption{
	{"1", "SSH (password)", ConnSSHPassword},
	{"2", "SSH (key)", ConnSSHKey},
	{"3", "API (REST)", ConnAPI},
	{"4", "FTP / SFTP", ConnFTP},
	{"5", "Database (PostgreSQL)", ConnDBPostgres},
	{"6", "Database (MySQL / MariaDB)", ConnDBMySQL},
	{"7", "Database (SQL Server)", ConnDBMSSQL},
	{"8", "WinRM / PowerShell", ConnWinRM},
}

// AddConnection is now a thin type-selector. Once a type is picked it hands
// off to the unified field-picker form (see EditConnection) in add mode.
type AddConnection struct {
	vault *Vault
	err   string
}

func NewAddConnection(vault *Vault) AddConnection {
	return AddConnection{vault: vault}
}

func (ac AddConnection) Init() tea.Cmd { return nil }

func (ac AddConnection) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "esc" {
			return ac, func() tea.Msg {
				return switchScreenMsg{screen: ScreenConnectionList, model: NewConnectionList(ac.vault)}
			}
		}
		for _, opt := range addTypeOptions {
			if msg.String() == opt.key {
				chosen := opt.ct
				vault := ac.vault
				return ac, func() tea.Msg {
					return switchScreenMsg{
						screen: ScreenEditConnection,
						model:  NewAddConnectionForm(vault, chosen),
					}
				}
			}
		}
		ac.err = "Enter 1-8."
		return ac, nil
	}
	return ac, nil
}

func (ac AddConnection) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("\n  -- Add Connection --\n"))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("  Choose a connection type to begin. The next screen lets you fill in fields in any order.") + "\n\n")
	for _, opt := range addTypeOptions {
		b.WriteString(fmt.Sprintf("  %s %s\n", menuKeyStyle.Render("["+opt.key+"]"), opt.label))
	}
	b.WriteString("\n")
	b.WriteString(separatorStyle.Render("  "+strings.Repeat("-", 40)) + "\n")
	b.WriteString("  " + dimStyle.Render("Press a number to select  •  Esc to cancel") + "\n")
	if ac.err != "" {
		b.WriteString("\n  " + errorStyle.Render(ac.err) + "\n")
	}
	return b.String()
}
