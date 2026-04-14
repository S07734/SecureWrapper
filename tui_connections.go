package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// ConnectionList is the main screen showing all connections.
type ConnectionList struct {
	vault  *Vault
	cursor int
	status string
}

func NewConnectionList(vault *Vault) ConnectionList {
	return ConnectionList{
		vault:  vault,
		cursor: 0,
	}
}

func (cl ConnectionList) Init() tea.Cmd {
	return nil
}

func (cl ConnectionList) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case statusMsg:
		cl.status = string(msg)
		return cl, nil

	case testResultMsg:
		if msg.err != nil {
			cl.status = errorStyle.Render(fmt.Sprintf("Test %s FAILED: %v", msg.name, msg.err))
		} else {
			cl.status = successStyle.Render(fmt.Sprintf("Test %s: Connected", msg.name))
		}
		return cl, nil

	case tea.KeyMsg:
		conns := cl.vault.ListConnections()

		switch msg.String() {
		case "up":
			if cl.cursor > 0 {
				cl.cursor--
			}
		case "down":
			if cl.cursor < len(conns)-1 {
				cl.cursor++
			}
		case "a", "A":
			return cl, func() tea.Msg {
				return switchScreenMsg{
					screen: ScreenAddConnection,
					model:  NewAddConnection(cl.vault),
				}
			}
		case "e", "E":
			if len(conns) > 0 {
				conn := conns[cl.cursor]
				return cl, func() tea.Msg {
					return switchScreenMsg{
						screen: ScreenEditConnection,
						model:  NewEditConnection(cl.vault, conn.Name),
					}
				}
			}
		case "enter":
			if len(conns) > 0 {
				conn := conns[cl.cursor]
				return cl, func() tea.Msg {
					return switchScreenMsg{
						screen: ScreenDetail,
						model:  NewDetailView(cl.vault, conn.Name),
					}
				}
			}
		case "t", "T":
			if len(conns) > 0 {
				conn := conns[cl.cursor]
				cl.status = dimStyle.Render(fmt.Sprintf("Testing %s...", conn.Name))
				return cl, func() tea.Msg {
					err := testConn(conn)
					return testResultMsg{name: conn.Name, err: err}
				}
			}
		case "d", "D":
			if len(conns) > 0 {
				conn := conns[cl.cursor]
				return cl, func() tea.Msg {
					return switchScreenMsg{
						screen: ScreenConfirm,
						model: NewConfirm(
							fmt.Sprintf("Delete connection \"%s\"?", conn.Name),
							func() tea.Msg {
								cl.vault.RemoveConnection(conn.Name)
								if err := cl.vault.Save(); err != nil {
									return statusMsg(errorStyle.Render(fmt.Sprintf("Error saving: %v", err)))
								}
								return switchScreenMsg{
									screen: ScreenConnectionList,
									model:  NewConnectionList(cl.vault),
								}
							},
							func() tea.Msg {
								return switchScreenMsg{
									screen: ScreenConnectionList,
									model:  NewConnectionList(cl.vault),
								}
							},
						),
					}
				}
			}
		case "c", "C":
			return cl, func() tea.Msg {
				return switchScreenMsg{
					screen: ScreenConfig,
					model:  NewConfigMenu(cl.vault),
				}
			}
		case "?":
			return cl, func() tea.Msg {
				return switchScreenMsg{
					screen: ScreenHelp,
					model:  NewHelpScreen(),
				}
			}
		case "q", "Q":
			return cl, tea.Quit
		}
	}

	return cl, nil
}

func (cl ConnectionList) View() string {
	var b strings.Builder

	// Logo
	b.WriteString(renderLogo())
	b.WriteString("\n")

	// Status bar
	connCount := len(cl.vault.ListConnections())
	keyCount := len(cl.vault.ListAuthKeys())
	fp := ShortFingerprint()

	statusLeft := fmt.Sprintf(" v%s", version)
	statusMid := fmt.Sprintf("Connections: %d  |  Auth Keys: %d", connCount, keyCount)
	statusRight := fmt.Sprintf("Machine: %s ", fp)

	statusBar := fmt.Sprintf("  %s  %s  %s",
		dimStyle.Render(statusLeft),
		connTargetStyle.Render(statusMid),
		dimStyle.Render(statusRight),
	)
	b.WriteString(statusBar)
	b.WriteString("\n\n")

	// Connection list
	conns := cl.vault.ListConnections()
	if len(conns) == 0 {
		b.WriteString(dimStyle.Render("  No connections configured. Press A to add one.\n"))
	} else {
		// Column headers
		b.WriteString(fmt.Sprintf("  %s  %s  %s\n",
			headerStyle.Render(padRight("NAME", 20)),
			headerStyle.Render(padRight("TYPE", 14)),
			headerStyle.Render("TARGET"),
		))
		b.WriteString(separatorStyle.Render("  "+strings.Repeat("-", 60)) + "\n")

		for i, c := range conns {
			target := connectionTarget(c)
			typeName := connectionTypeName(c)

			nameCol := padRight(c.Name, 20)
			typeCol := padRight(typeName, 14)

			if i == cl.cursor {
				// Highlighted row
				row := fmt.Sprintf("  %s  %s  %s",
					highlightStyle.Render(nameCol),
					highlightStyle.Render(typeCol),
					highlightStyle.Render(target),
				)
				b.WriteString(cursorStyle.Render(">") + row + "\n")
			} else {
				b.WriteString(fmt.Sprintf("   %s  %s  %s\n",
					connNameStyle.Render(nameCol),
					connTypeStyle.Render(typeCol),
					connTargetStyle.Render(target),
				))
			}
		}
	}

	b.WriteString("\n")

	// Footer key bindings
	b.WriteString(separatorStyle.Render("  "+strings.Repeat("-", 60)) + "\n")

	row1 := fmt.Sprintf("  %s %s  %s %s  %s %s  %s %s  %s %s  %s %s  %s %s",
		menuKeyStyle.Render("[A]"), menuDescStyle.Render("Add"),
		menuKeyStyle.Render("[E]"), menuDescStyle.Render("Edit"),
		menuKeyStyle.Render("[T]"), menuDescStyle.Render("Test"),
		menuKeyStyle.Render("[D]"), menuDescStyle.Render("Delete"),
		menuKeyStyle.Render("[C]"), menuDescStyle.Render("Config"),
		menuKeyStyle.Render("[?]"), menuDescStyle.Render("Help"),
		menuKeyStyle.Render("[Q]"), menuDescStyle.Render("Quit"),
	)
	row2 := fmt.Sprintf("  %s", dimStyle.Render("Up/Down=navigate  Enter=details"))

	b.WriteString(row1 + "\n")
	b.WriteString(row2 + "\n")

	// Status message
	if cl.status != "" {
		b.WriteString("\n  " + cl.status + "\n")
	}

	return b.String()
}

// Helper functions for connection display

func connectionTarget(c Connection) string {
	switch c.Type {
	case ConnSSHPassword, ConnSSHKey:
		return fmt.Sprintf("%s@%s:%d", c.Username, c.Host, c.Port)
	case ConnAPI:
		return c.BaseURL
	case ConnFTP:
		return fmt.Sprintf("%s@%s:%d", c.Username, c.Host, c.Port)
	case ConnDBPostgres, ConnDBMySQL, ConnDBMSSQL:
		if c.Database != "" {
			return fmt.Sprintf("%s@%s:%d/%s", c.Username, c.Host, c.Port, c.Database)
		}
		return fmt.Sprintf("%s@%s:%d", c.Username, c.Host, c.Port)
	case ConnWinRM:
		scheme := "http"
		if c.UseHTTPS {
			scheme = "https"
		}
		return fmt.Sprintf("%s://%s@%s:%d", scheme, c.Username, c.Host, c.Port)
	default:
		return ""
	}
}

func connectionTypeName(c Connection) string {
	switch c.Type {
	case ConnSSHPassword:
		return "SSH (pass)"
	case ConnSSHKey:
		return "SSH (key)"
	case ConnAPI:
		return "API"
	case ConnFTP:
		return "SFTP"
	case ConnDBPostgres:
		return "DB (pg)"
	case ConnDBMySQL:
		return "DB (mysql)"
	case ConnDBMSSQL:
		return "DB (mssql)"
	case ConnWinRM:
		return "WinRM"
	default:
		return string(c.Type)
	}
}
