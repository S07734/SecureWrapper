package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// editField represents an editable field in the connection form.
type editField struct {
	key    string
	label  string
	value  string
	masked bool
}

// editMode tracks whether we're picking a field or editing one.
type editMode int

const (
	editModePicker editMode = iota
	editModeInput
	editModeTestPrompt
	editModeTesting
	editModeDone
)

// EditConnection is the unified connection form: same field-picker UX for
// add and edit. An empty origName signals add mode — the working Connection
// starts from the type chosen in the add type selector. In edit mode the
// working Connection is a copy of the existing vault entry; if Name changes,
// Save handles the rename.
type EditConnection struct {
	vault    *Vault
	origName string // "" = add mode; otherwise the name as loaded (used to detect rename)
	conn     Connection
	input    textinput.Model
	cursor   int
	mode     editMode
	fields   []editField
	err      string
	status   string
	dirty    bool
}

// NewEditConnection builds the form in edit mode.
func NewEditConnection(vault *Vault, connName string) EditConnection {
	ti := textinput.New()
	ti.Prompt = promptStyle.Render("  ") + " "
	ti.CharLimit = 256

	ec := EditConnection{
		vault:    vault,
		origName: connName,
		input:    ti,
	}
	if existing := vault.GetConnection(connName); existing != nil {
		ec.conn = *existing // working copy — changes only land in the vault on Save
	}
	ec.fields = ec.buildFields()
	return ec
}

// NewAddConnectionForm builds the form in add mode for a freshly chosen type.
// Sensible defaults (port, ssl mode, key path) are prefilled so the admin only
// has to enter required values.
func NewAddConnectionForm(vault *Vault, ct ConnectionType) EditConnection {
	ti := textinput.New()
	ti.Prompt = promptStyle.Render("  ") + " "
	ti.CharLimit = 256

	conn := Connection{Type: ct}
	conn.Port = defaultPortForType(ct, false)
	switch ct {
	case ConnDBPostgres, ConnDBMySQL, ConnDBMSSQL:
		conn.SSLMode = defaultSSLModeForType(ct)
	case ConnSSHKey:
		conn.KeyPath = "~/.ssh/id_rsa"
	}

	ec := EditConnection{
		vault: vault,
		conn:  conn,
		input: ti,
		dirty: true, // new connections are implicitly dirty until saved
	}
	ec.fields = ec.buildFields()
	return ec
}

// buildFields derives the field list from the working Connection. Name is
// always first. Type-specific fields follow. In add mode, Name starts empty
// and all other defaults are those chosen by the constructor.
func (ec EditConnection) buildFields() []editField {
	fields := []editField{
		{key: "name", label: "Name", value: ec.conn.Name},
	}

	switch ec.conn.Type {
	case ConnSSHPassword:
		fields = append(fields,
			editField{key: "host", label: "Host", value: ec.conn.Host},
			editField{key: "port", label: "Port", value: fmt.Sprintf("%d", ec.conn.Port)},
			editField{key: "username", label: "Username", value: ec.conn.Username},
			editField{key: "password", label: "Password", value: ec.conn.Password, masked: true},
		)
	case ConnSSHKey:
		fields = append(fields,
			editField{key: "host", label: "Host", value: ec.conn.Host},
			editField{key: "port", label: "Port", value: fmt.Sprintf("%d", ec.conn.Port)},
			editField{key: "username", label: "Username", value: ec.conn.Username},
			editField{key: "keypath", label: "Key Path", value: ec.conn.KeyPath},
			editField{key: "keypass", label: "Key Passphrase", value: ec.conn.KeyPass, masked: true},
		)
	case ConnAPI:
		fields = append(fields,
			editField{key: "baseurl", label: "Base URL", value: ec.conn.BaseURL},
			editField{key: "authtype", label: "Auth Type", value: ec.conn.AuthType},
			editField{key: "authheader", label: "Auth Header", value: ec.conn.AuthHeader},
			editField{key: "authvalue", label: "Auth Value", value: ec.conn.AuthValue, masked: true},
			editField{key: "totpsecret", label: "TOTP Secret", value: ec.conn.TOTPSecret, masked: true},
			editField{key: "extrafield", label: "Extra Field", value: ec.conn.ExtraField},
			editField{key: "insecure", label: "Skip TLS", value: boolToYN(ec.conn.Insecure)},
		)
	case ConnFTP:
		fields = append(fields,
			editField{key: "host", label: "Host", value: ec.conn.Host},
			editField{key: "port", label: "Port", value: fmt.Sprintf("%d", ec.conn.Port)},
			editField{key: "username", label: "Username", value: ec.conn.Username},
			editField{key: "password", label: "Password", value: ec.conn.Password, masked: true},
		)
	case ConnDBPostgres, ConnDBMySQL, ConnDBMSSQL:
		fields = append(fields,
			editField{key: "host", label: "Host", value: ec.conn.Host},
			editField{key: "port", label: "Port", value: fmt.Sprintf("%d", ec.conn.Port)},
			editField{key: "username", label: "Username", value: ec.conn.Username},
			editField{key: "password", label: "Password", value: ec.conn.Password, masked: true},
			editField{key: "database", label: "Database", value: ec.conn.Database},
			editField{key: "sslmode", label: "SSL Mode", value: ec.conn.SSLMode},
		)
	case ConnWinRM:
		fields = append(fields,
			editField{key: "host", label: "Host", value: ec.conn.Host},
			editField{key: "port", label: "Port", value: fmt.Sprintf("%d", ec.conn.Port)},
			editField{key: "username", label: "Username", value: ec.conn.Username},
			editField{key: "password", label: "Password", value: ec.conn.Password, masked: true},
			editField{key: "usehttps", label: "Use HTTPS", value: boolToYN(ec.conn.UseHTTPS)},
			editField{key: "insecure", label: "Skip TLS", value: boolToYN(ec.conn.Insecure)},
		)
	}

	return fields
}

func (ec EditConnection) Init() tea.Cmd { return nil }

func (ec EditConnection) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case testResultMsg:
		if msg.err != nil {
			ec.status = errorStyle.Render(fmt.Sprintf("FAILED: %v", msg.err))
		} else {
			ec.status = successStyle.Render("Connected")
		}
		// Commit changes to the vault now that the test has run (or been skipped).
		if err := ec.commit(); err != nil {
			ec.err = fmt.Sprintf("Error saving: %v", err)
		} else {
			verb := "Updated"
			if ec.origName == "" {
				verb = "Added"
			}
			ec.status += "\n  " + successStyle.Render(fmt.Sprintf("%s \"%s\"", verb, ec.conn.Name))
		}
		ec.mode = editModeDone
		return ec, nil

	case tea.KeyMsg:
		switch ec.mode {
		case editModePicker:
			return ec.updatePicker(msg)
		case editModeInput:
			return ec.updateInput(msg)
		case editModeTestPrompt:
			return ec.updateTestPrompt(msg)
		case editModeDone:
			if msg.String() == "enter" || msg.String() == "esc" {
				return ec, func() tea.Msg {
					return switchScreenMsg{
						screen: ScreenConnectionList,
						model:  NewConnectionList(ec.vault),
					}
				}
			}
		}
	}

	if ec.mode == editModeInput {
		var cmd tea.Cmd
		ec.input, cmd = ec.input.Update(msg)
		return ec, cmd
	}
	return ec, nil
}

func (ec EditConnection) updatePicker(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up":
		if ec.cursor > 0 {
			ec.cursor--
		}
	case "down":
		if ec.cursor < len(ec.fields)-1 {
			ec.cursor++
		}
	case "enter":
		field := ec.fields[ec.cursor]
		ec.mode = editModeInput
		ec.input.SetValue("")
		ec.input.Focus()
		if field.masked {
			ec.input.EchoMode = textinput.EchoPassword
			ec.input.Placeholder = ""
		} else {
			ec.input.EchoMode = textinput.EchoNormal
			ec.input.Placeholder = field.value
		}
		ec.err = ""
		return ec, textinput.Blink
	case "s", "S":
		if err := ec.validate(); err != nil {
			ec.err = err.Error()
			return ec, nil
		}
		return ec.promptTest()
	case "esc":
		if ec.dirty {
			// In add mode, esc returns to list without save. In edit mode, prompt for test.
			if ec.origName == "" {
				return ec, func() tea.Msg {
					return switchScreenMsg{screen: ScreenConnectionList, model: NewConnectionList(ec.vault)}
				}
			}
			return ec.promptTest()
		}
		return ec, func() tea.Msg {
			return switchScreenMsg{screen: ScreenConnectionList, model: NewConnectionList(ec.vault)}
		}
	}
	return ec, nil
}

func (ec EditConnection) updateInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		ec.mode = editModePicker
		ec.input.Blur()
		ec.input.EchoMode = textinput.EchoNormal
		return ec, nil
	case "enter":
		return ec.applyField()
	}
	var cmd tea.Cmd
	ec.input, cmd = ec.input.Update(msg)
	return ec, cmd
}

func (ec EditConnection) updateTestPrompt(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		ec.mode = editModePicker
		return ec, nil
	case "enter":
		return ec.handleTestDecision("")
	}
	var cmd tea.Cmd
	ec.input, cmd = ec.input.Update(msg)
	val := strings.TrimSpace(ec.input.Value())
	if strings.ToLower(val) == "y" || strings.ToLower(val) == "n" {
		return ec.handleTestDecision(val)
	}
	return ec, cmd
}

func (ec EditConnection) handleTestDecision(val string) (tea.Model, tea.Cmd) {
	if val == "" {
		val = strings.TrimSpace(ec.input.Value())
	}
	if val == "" || strings.ToLower(val) == "y" {
		ec.mode = editModeTesting
		ec.status = dimStyle.Render("Testing...")
		c := ec.conn // local copy for the goroutine
		return ec, func() tea.Msg {
			err := testConn(c)
			return testResultMsg{name: c.Name, err: err}
		}
	}
	// Skip test → commit directly.
	if err := ec.commit(); err != nil {
		ec.err = fmt.Sprintf("Error saving: %v", err)
		ec.mode = editModePicker
		return ec, nil
	}
	ec.mode = editModeDone
	verb := "Updated"
	if ec.origName == "" {
		verb = "Added"
	}
	ec.status = successStyle.Render(fmt.Sprintf("%s \"%s\"", verb, ec.conn.Name))
	return ec, nil
}

// applyField writes the entered value back onto the working Connection.
// buildFields is re-run so the picker reflects the new value immediately.
func (ec EditConnection) applyField() (tea.Model, tea.Cmd) {
	val := strings.TrimSpace(ec.input.Value())
	ec.input.SetValue("")
	ec.input.Blur()
	ec.input.EchoMode = textinput.EchoNormal
	ec.mode = editModePicker

	if val == "" {
		return ec, nil
	}

	field := ec.fields[ec.cursor]
	ec.err = ""

	switch field.key {
	case "name":
		ec.conn.Name = val
	case "host":
		ec.conn.Host = val
	case "port":
		p, err := strconv.Atoi(val)
		if err != nil {
			ec.err = "Invalid port number."
			return ec, nil
		}
		ec.conn.Port = p
	case "username":
		ec.conn.Username = val
	case "password":
		ec.conn.Password = val
	case "keypath":
		ec.conn.KeyPath = val
	case "keypass":
		ec.conn.KeyPass = val
	case "baseurl":
		ec.conn.BaseURL = val
	case "authtype":
		ec.conn.AuthType = val
	case "authheader":
		ec.conn.AuthHeader = val
	case "authvalue":
		ec.conn.AuthValue = val
	case "totpsecret":
		ec.conn.TOTPSecret = val
	case "extrafield":
		ec.conn.ExtraField = val
	case "insecure":
		ec.conn.Insecure = strings.ToLower(val) == "y"
	case "database":
		ec.conn.Database = val
	case "sslmode":
		ec.conn.SSLMode = val
	case "usehttps":
		ec.conn.UseHTTPS = strings.ToLower(val) == "y"
		// Port default depends on UseHTTPS for WinRM; only reset if user
		// hasn't customized it to something unusual.
		if ec.conn.Type == ConnWinRM && (ec.conn.Port == 5985 || ec.conn.Port == 5986) {
			ec.conn.Port = defaultPortForType(ec.conn.Type, ec.conn.UseHTTPS)
		}
	}

	ec.dirty = true
	ec.fields = ec.buildFields()
	return ec, nil
}

// validate enforces the minimum requirements before save. Returns nil when OK.
// Per-type connection-test catches the rest (wrong host, bad credentials, etc).
func (ec EditConnection) validate() error {
	if strings.TrimSpace(ec.conn.Name) == "" {
		return fmt.Errorf("Name is required.")
	}
	if ec.origName == "" {
		// Add mode: name collision check.
		if ec.vault.GetConnection(ec.conn.Name) != nil {
			return fmt.Errorf("A connection named %q already exists.", ec.conn.Name)
		}
	} else if ec.conn.Name != ec.origName {
		// Rename: ensure new name isn't taken.
		if ec.vault.GetConnection(ec.conn.Name) != nil {
			return fmt.Errorf("Cannot rename to %q — that name is already taken.", ec.conn.Name)
		}
	}
	switch ec.conn.Type {
	case ConnAPI:
		if strings.TrimSpace(ec.conn.BaseURL) == "" {
			return fmt.Errorf("Base URL is required for API connections.")
		}
	default:
		if strings.TrimSpace(ec.conn.Host) == "" {
			return fmt.Errorf("Host is required.")
		}
	}
	return nil
}

// commit writes the working Connection into the vault. Handles three cases:
//   - add: append new entry
//   - edit with same name: replace in place via RemoveConnection + AddConnection
//   - edit with renamed name: remove old, add new
func (ec EditConnection) commit() error {
	if ec.origName == "" {
		ec.vault.AddConnection(ec.conn)
		return ec.vault.Save()
	}
	ec.vault.RemoveConnection(ec.origName)
	ec.vault.AddConnection(ec.conn)
	return ec.vault.Save()
}

func (ec EditConnection) promptTest() (tea.Model, tea.Cmd) {
	ec.mode = editModeTestPrompt
	ec.input.SetValue("")
	ec.input.Focus()
	ec.input.EchoMode = textinput.EchoNormal
	ec.input.Placeholder = ""
	return ec, textinput.Blink
}

func (ec EditConnection) View() string {
	var b strings.Builder

	verb := "Edit"
	displayName := ec.origName
	if ec.origName == "" {
		verb = "Add"
		displayName = ec.conn.Name
		if displayName == "" {
			displayName = dimStyle.Render("(unnamed)")
		}
	}
	b.WriteString(titleStyle.Render(fmt.Sprintf("\n  -- %s: %s --\n", verb, displayName)))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  Type: %s\n\n", connTypeStyle.Render(connectionTypeLabel(ec.conn.Type))))

	switch ec.mode {
	case editModePicker, editModeInput:
		// Single field list — in input mode, the cursor row renders the
		// textinput in place of the value so editing happens inline without
		// leaving the full-form view.
		editing := ec.mode == editModeInput
		for i, f := range ec.fields {
			display := f.value
			if f.masked && f.value != "" {
				display = "********"
			}
			if display == "" {
				display = dimStyle.Render("(empty)")
			}
			label := padRight(f.label+":", 18)

			if i == ec.cursor {
				if editing {
					// Cursor row becomes the active input field.
					b.WriteString(cursorStyle.Render(">") + fmt.Sprintf("  %s %s\n",
						highlightStyle.Render(label),
						ec.input.View(),
					))
					if hint := editFieldHint(ec.conn.Type, f.key); hint != "" {
						b.WriteString("   " + strings.Repeat(" ", 19) + dimStyle.Render("Options: "+hint) + "\n")
					}
				} else {
					b.WriteString(cursorStyle.Render(">") + fmt.Sprintf("  %s %s\n",
						highlightStyle.Render(label),
						connTargetStyle.Render(display),
					))
				}
			} else {
				b.WriteString(fmt.Sprintf("   %s %s\n",
					headerStyle.Render(label),
					connTargetStyle.Render(display),
				))
			}
		}

		b.WriteString("\n")
		b.WriteString(separatorStyle.Render("  "+strings.Repeat("-", 50)) + "\n")
		var footer string
		if editing {
			footer = fmt.Sprintf("  %s",
				dimStyle.Render("Enter=apply  Esc=cancel edit"),
			)
		} else {
			footer = fmt.Sprintf("  %s  %s  %s",
				dimStyle.Render("Up/Down=navigate  Enter=edit field"),
				menuKeyStyle.Render("[S]")+" "+menuDescStyle.Render("Save"),
				menuKeyStyle.Render("[Esc]")+" "+menuDescStyle.Render("Back"),
			)
		}
		b.WriteString(footer + "\n")

		if ec.dirty && ec.origName != "" {
			b.WriteString("\n  " + warnStyle.Render("Unsaved changes") + "\n")
		}

	case editModeTestPrompt:
		b.WriteString("  Test connection? (y/n) [y]:\n")
		b.WriteString("  " + ec.input.View() + "\n")
		b.WriteString("\n  " + dimStyle.Render("Esc=cancel") + "\n")

	case editModeTesting:
		b.WriteString("  " + dimStyle.Render("Testing...") + "\n")

	case editModeDone:
		b.WriteString("  " + dimStyle.Render("Press enter to continue...") + "\n")
	}

	if ec.err != "" {
		b.WriteString("\n  " + errorStyle.Render(ec.err) + "\n")
	}
	if ec.status != "" {
		b.WriteString("\n  " + ec.status + "\n")
	}

	return b.String()
}

func boolToYN(b bool) string {
	if b {
		return "y"
	}
	return "n"
}

// connectionTypeLabel returns the human-readable label for a connection type.
func connectionTypeLabel(ct ConnectionType) string {
	switch ct {
	case ConnSSHPassword:
		return "SSH (password)"
	case ConnSSHKey:
		return "SSH (key)"
	case ConnAPI:
		return "API (REST)"
	case ConnFTP:
		return "FTP/SFTP"
	case ConnDBPostgres:
		return "Database (PostgreSQL)"
	case ConnDBMySQL:
		return "Database (MySQL/MariaDB)"
	case ConnDBMSSQL:
		return "Database (SQL Server)"
	case ConnWinRM:
		return "WinRM / PowerShell"
	default:
		return string(ct)
	}
}

// defaultPortForType returns the standard port for a connection type. For
// WinRM, the HTTPS toggle selects 5986 vs 5985.
func defaultPortForType(ct ConnectionType, useHTTPS bool) int {
	switch ct {
	case ConnSSHPassword, ConnSSHKey, ConnFTP:
		return 22
	case ConnDBPostgres:
		return 5432
	case ConnDBMySQL:
		return 3306
	case ConnDBMSSQL:
		return 1433
	case ConnWinRM:
		if useHTTPS {
			return 5986
		}
		return 5985
	}
	return 0
}

// defaultSSLModeForType returns a sensible, conservative default for each
// driver's SSL/TLS option. These strings match the driver-level expectations
// consumed in connections/db.go.
func defaultSSLModeForType(ct ConnectionType) string {
	switch ct {
	case ConnDBPostgres:
		return "require"
	case ConnDBMySQL:
		return "preferred"
	case ConnDBMSSQL:
		return "true"
	}
	return ""
}

// sslModeOptionsForType returns a human-readable list of valid SSL/TLS mode
// values for a given DB driver, shown as a hint in the TUI so admins don't
// have to grep driver docs.
func sslModeOptionsForType(ct ConnectionType) string {
	switch ct {
	case ConnDBPostgres:
		return "disable / allow / prefer / require / verify-ca / verify-full"
	case ConnDBMySQL:
		return "true / false / skip-verify / preferred"
	case ConnDBMSSQL:
		return "disable / false / true / strict"
	}
	return ""
}

// editFieldHint returns a short "valid options" string to show under an input
// while the user edits a given field. Used to surface per-driver SSL mode
// choices and similar discrete enumerations that would otherwise require
// documentation lookup.
func editFieldHint(ct ConnectionType, fieldKey string) string {
	switch fieldKey {
	case "sslmode":
		return sslModeOptionsForType(ct)
	case "usehttps", "insecure":
		return "y / n"
	case "authtype":
		if ct == ConnAPI {
			return "key / bearer / basic"
		}
	}
	return ""
}
