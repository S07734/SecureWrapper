package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// DetailView shows a read-only view of a connection.
type DetailView struct {
	vault    *Vault
	connName string
	status   string
}

func NewDetailView(vault *Vault, connName string) DetailView {
	return DetailView{
		vault:    vault,
		connName: connName,
	}
}

func (dv DetailView) Init() tea.Cmd {
	return nil
}

func (dv DetailView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case testResultMsg:
		if msg.err != nil {
			dv.status = errorStyle.Render(fmt.Sprintf("FAILED: %v", msg.err))
		} else {
			dv.status = successStyle.Render("Connected")
		}
		return dv, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "b", "B", "esc":
			return dv, func() tea.Msg {
				return switchScreenMsg{
					screen: ScreenConnectionList,
					model:  NewConnectionList(dv.vault),
				}
			}
		case "e", "E":
			return dv, func() tea.Msg {
				return switchScreenMsg{
					screen: ScreenEditConnection,
					model:  NewEditConnection(dv.vault, dv.connName),
				}
			}
		case "t", "T":
			conn := dv.vault.GetConnection(dv.connName)
			if conn != nil {
				dv.status = dimStyle.Render("Testing...")
				c := *conn
				vault := dv.vault
				return dv, func() tea.Msg {
					err := testConn(vault, c)
					return testResultMsg{name: c.Name, err: err}
				}
			}
		}
	}

	return dv, nil
}

func (dv DetailView) View() string {
	var b strings.Builder

	conn := dv.vault.GetConnection(dv.connName)
	if conn == nil {
		b.WriteString(errorStyle.Render("  Connection not found."))
		return b.String()
	}

	b.WriteString(titleStyle.Render(fmt.Sprintf("\n  -- %s --\n", conn.Name)))
	b.WriteString("\n")

	b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("Type:"), connTypeStyle.Render(connectionTypeLabel(conn.Type))))

	switch conn.Type {
	case ConnSSHPassword:
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("Host:"), connTargetStyle.Render(conn.Host)))
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("Port:"), connTargetStyle.Render(fmt.Sprintf("%d", conn.Port))))
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("User:"), connTargetStyle.Render(conn.Username)))
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("Pass:"), dimStyle.Render("********")))

	case ConnSSHKey:
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("Host:"), connTargetStyle.Render(conn.Host)))
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("Port:"), connTargetStyle.Render(fmt.Sprintf("%d", conn.Port))))
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("User:"), connTargetStyle.Render(conn.Username)))
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("Key:"), connTargetStyle.Render(conn.KeyPath)))
		if conn.KeyPass != "" {
			b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("Key passphrase:"), dimStyle.Render("********")))
		}

	case ConnAPI:
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("URL:"), connTargetStyle.Render(conn.BaseURL)))
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("Auth:"), connTargetStyle.Render(conn.AuthType)))
		if conn.AuthHeader != "" {
			b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("Header:"), connTargetStyle.Render(conn.AuthHeader)))
		}
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("Value:"), dimStyle.Render("********")))
		if conn.TOTPSecret != "" {
			b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("TOTP:"), dimStyle.Render("********")))
		}
		if conn.ExtraField != "" {
			b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("Extra:"), connTargetStyle.Render(conn.ExtraField)))
		}
		insecureLabel := "No"
		if conn.Insecure {
			insecureLabel = warnStyle.Render("Yes")
		}
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("Insecure:"), connTargetStyle.Render(insecureLabel)))

	case ConnFTP:
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("Host:"), connTargetStyle.Render(conn.Host)))
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("Port:"), connTargetStyle.Render(fmt.Sprintf("%d", conn.Port))))
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("User:"), connTargetStyle.Render(conn.Username)))
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("Pass:"), dimStyle.Render("********")))

	case ConnDBPostgres, ConnDBMySQL, ConnDBMSSQL:
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("Host:"), connTargetStyle.Render(conn.Host)))
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("Port:"), connTargetStyle.Render(fmt.Sprintf("%d", conn.Port))))
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("User:"), connTargetStyle.Render(conn.Username)))
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("Pass:"), dimStyle.Render("********")))
		if conn.Database != "" {
			b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("DB:"), connTargetStyle.Render(conn.Database)))
		}
		if conn.SSLMode != "" {
			b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("SSL:"), connTargetStyle.Render(conn.SSLMode)))
		}
		if conn.TunnelVia != "" {
			b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("Tunnel:"), connTargetStyle.Render("via "+conn.TunnelVia)))
		}

	case ConnWinRM:
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("Host:"), connTargetStyle.Render(conn.Host)))
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("Port:"), connTargetStyle.Render(fmt.Sprintf("%d", conn.Port))))
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("User:"), connTargetStyle.Render(conn.Username)))
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("Pass:"), dimStyle.Render("********")))
		httpsLabel := "No"
		if conn.UseHTTPS {
			httpsLabel = "Yes"
		}
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("HTTPS:"), connTargetStyle.Render(httpsLabel)))
		insecureLabel := "No"
		if conn.Insecure {
			insecureLabel = warnStyle.Render("Yes")
		}
		b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("Insecure:"), connTargetStyle.Render(insecureLabel)))
		if conn.TunnelVia != "" {
			b.WriteString(fmt.Sprintf("  %s  %s\n", headerStyle.Render("Tunnel:"), connTargetStyle.Render("via "+conn.TunnelVia)))
		}
	}

	b.WriteString("\n")
	b.WriteString(separatorStyle.Render("  "+strings.Repeat("-", 50)) + "\n")
	b.WriteString(fmt.Sprintf("  %s %s  %s %s  %s %s\n",
		menuKeyStyle.Render("[B]"), menuDescStyle.Render("Back"),
		menuKeyStyle.Render("[E]"), menuDescStyle.Render("Edit"),
		menuKeyStyle.Render("[T]"), menuDescStyle.Render("Test"),
	))

	if dv.status != "" {
		b.WriteString("\n  " + dv.status + "\n")
	}

	return b.String()
}
