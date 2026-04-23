package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// HelpScreen is a scrollable help view.
type HelpScreen struct {
	lines    []string
	offset   int
	height   int
}

func NewHelpScreen() HelpScreen {
	content := buildHelpContent()
	lines := strings.Split(content, "\n")
	return HelpScreen{
		lines:  lines,
		offset: 0,
		height: 20, // default, updated by WindowSizeMsg
	}
}

func (h HelpScreen) Init() tea.Cmd {
	return nil
}

func (h HelpScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		h.height = msg.Height - 4 // leave room for footer
		return h, nil

	case tea.KeyMsg:
		maxOffset := len(h.lines) - h.height
		if maxOffset < 0 {
			maxOffset = 0
		}

		switch msg.String() {
		case "up":
			if h.offset > 0 {
				h.offset--
			}
		case "down":
			if h.offset < maxOffset {
				h.offset++
			}
		case "pgup":
			h.offset -= h.height
			if h.offset < 0 {
				h.offset = 0
			}
		case "pgdown":
			h.offset += h.height
			if h.offset > maxOffset {
				h.offset = maxOffset
			}
		case "home":
			h.offset = 0
		case "end":
			h.offset = maxOffset
		case "b", "B", "esc", "q":
			return h, func() tea.Msg {
				return switchScreenMsg{
					screen: ScreenConnectionList,
					model:  nil, // will be rebuilt by App
				}
			}
		}
	}

	return h, nil
}

func (h HelpScreen) View() string {
	var b strings.Builder

	// Show visible lines
	end := h.offset + h.height
	if end > len(h.lines) {
		end = len(h.lines)
	}

	visible := h.lines[h.offset:end]
	b.WriteString(strings.Join(visible, "\n"))
	b.WriteString("\n")

	// Footer
	b.WriteString("\n")
	scrollPct := 0
	if len(h.lines) > h.height {
		scrollPct = (h.offset * 100) / (len(h.lines) - h.height)
	}

	footer := fmt.Sprintf("  %s  %s  %s  %s  %s  %s",
		menuKeyStyle.Render("[B]")+" "+menuDescStyle.Render("Back"),
		menuKeyStyle.Render("[↑↓]")+" "+menuDescStyle.Render("Scroll"),
		menuKeyStyle.Render("[PgUp/Dn]")+" "+menuDescStyle.Render("Page"),
		menuKeyStyle.Render("[Home]")+" "+menuDescStyle.Render("Top"),
		menuKeyStyle.Render("[End]")+" "+menuDescStyle.Render("Bottom"),
		dimStyle.Render(fmt.Sprintf("%d%%", scrollPct)),
	)
	b.WriteString(footer)

	return b.String()
}

func buildHelpContent() string {
	h := headerStyle.Render
	c := connNameStyle.Render
	d := dimStyle.Render
	m := menuKeyStyle.Render
	w := connTargetStyle.Render

	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(renderLogo())
	b.WriteString("\n\n")

	b.WriteString(h("  OVERVIEW") + "\n\n")
	b.WriteString(w("  SecureWrapper is a credential vault and connection passthrough.") + "\n")
	b.WriteString(w("  It stores encrypted connection profiles (SSH, API, SFTP, etc.)") + "\n")
	b.WriteString(w("  and lets automation tools execute authenticated commands without") + "\n")
	b.WriteString(w("  ever seeing the credentials.") + "\n\n")
	b.WriteString(h("  LLM AGENT USE CASE") + "\n\n")
	b.WriteString(w("  Pair this with an LLM agent (Claude, GPT, Gemini, Copilot).") + "\n")
	b.WriteString(w("  The AI gets an auth key — NOT your secrets. It sees connection") + "\n")
	b.WriteString(w("  names and command output; never passwords, API keys, or SSH") + "\n")
	b.WriteString(w("  credentials.") + "\n\n")
	b.WriteString(w("  If a transcript leaks or a context is compromised, revoke the") + "\n")
	b.WriteString(w("  auth key (or wipe the vault) — the leaked conversation cannot") + "\n")
	b.WriteString(w("  reconstruct your credentials. Compromise becomes a revocation") + "\n")
	b.WriteString(w("  problem, not a credential-rotation problem.") + "\n\n")
	b.WriteString(d("  The vault is encrypted with three factors:") + "\n")
	b.WriteString(d("    1. Your passphrase (or auth key)") + "\n")
	b.WriteString(d("    2. This machine's hardware fingerprint") + "\n")
	b.WriteString(d("    3. A unique key derived from this binary's hash") + "\n\n")

	b.WriteString(h("  INTERACTIVE MODE") + "\n\n")
	b.WriteString(w("  Run with no arguments to manage the vault:") + "\n\n")
	b.WriteString(c("    ./wrapper") + "\n\n")

	b.WriteString(h("  CONNECTION MODE") + "\n\n")
	b.WriteString(w("  Three flags are required. Everything after is passthrough:") + "\n\n")
	b.WriteString(c("    ./wrapper --sys <name> --<mode> [args...]") + "\n\n")
	b.WriteString(d("  Auth key (one of these, in priority order):") + "\n")
	b.WriteString(c("    WRAPPER_AUTH_KEY=swk_xxx ./wrapper ...  ") + d("(preferred — not in ps)") + "\n")
	b.WriteString(c("    ./wrapper --key-file /path/to/keyfile ...") + "\n")
	b.WriteString(c("    ./wrapper --key swk_xxx ...             ") + d("(visible in ps aux)") + "\n\n")

	b.WriteString(h("  MODES") + "\n\n")
	b.WriteString(fmt.Sprintf("  %s  %s\n", m("--ssh  "), w("Execute a command on a remote host")))
	b.WriteString(fmt.Sprintf("  %s  %s\n", m("--scp  "), w("Copy files to/from a remote host")))
	b.WriteString(fmt.Sprintf("  %s  %s\n", m("--sftp "), w("Interactive file transfer session")))
	b.WriteString(fmt.Sprintf("  %s  %s\n", m("--rsync"), w("Sync files over SSH")))
	b.WriteString(fmt.Sprintf("  %s  %s\n", m("--api  "), w("Make an HTTP API request")))
	b.WriteString(fmt.Sprintf("  %s  %s\n", m("--db   "), w("Run a SQL query (Postgres / MySQL / SQL Server)")))
	b.WriteString(fmt.Sprintf("  %s  %s\n", m("--winrm"), w("Run PowerShell via WinRM")))
	b.WriteString(fmt.Sprintf("  %s  %s\n", m("--test "), w("Test connectivity (no command)")))
	b.WriteString(fmt.Sprintf("  %s  %s\n", m("--creds"), w("Output credentials as JSON (for MCP integration)")))
	b.WriteString("\n")

	b.WriteString(h("  EXAMPLES") + "\n\n")
	b.WriteString(d("  SSH — run a command:") + "\n")
	b.WriteString(c("    WRAPPER_AUTH_KEY=swk_xxx ./wrapper --sys myserver --ssh \"df -h\"") + "\n\n")
	b.WriteString(d("  SSH — interactive session:") + "\n")
	b.WriteString(c("    WRAPPER_AUTH_KEY=swk_xxx ./wrapper --sys myserver --ssh") + "\n\n")
	b.WriteString(d("  SCP — copy file to remote:") + "\n")
	b.WriteString(c("    WRAPPER_AUTH_KEY=swk_xxx ./wrapper --sys myserver --scp file.txt :/remote/path/") + "\n\n")
	b.WriteString(d("  SCP — copy file from remote:") + "\n")
	b.WriteString(c("    WRAPPER_AUTH_KEY=swk_xxx ./wrapper --sys myserver --scp :/remote/file.txt ./local/") + "\n\n")
	b.WriteString(d("  Rsync — sync directory:") + "\n")
	b.WriteString(c("    WRAPPER_AUTH_KEY=swk_xxx ./wrapper --sys myserver --rsync -av /local/ :/remote/") + "\n\n")
	b.WriteString(d("  API — GET request:") + "\n")
	b.WriteString(c("    WRAPPER_AUTH_KEY=swk_xxx ./wrapper --sys myapi --api GET /endpoint") + "\n\n")
	b.WriteString(d("  API — POST with body:") + "\n")
	b.WriteString(c("    WRAPPER_AUTH_KEY=swk_xxx ./wrapper --sys myapi --api POST /endpoint '{\"key\":\"value\"}'") + "\n\n")
	b.WriteString(d("  Database — SELECT (TSV output with header):") + "\n")
	b.WriteString(c("    WRAPPER_AUTH_KEY=swk_xxx ./wrapper --sys mydb --db \"SELECT id FROM users LIMIT 10\"") + "\n\n")
	b.WriteString(d("  WinRM — run PowerShell:") + "\n")
	b.WriteString(c("    WRAPPER_AUTH_KEY=swk_xxx ./wrapper --sys mywinhost --winrm \"Get-Service wuauserv\"") + "\n\n")
	b.WriteString(d("  Test connectivity:") + "\n")
	b.WriteString(c("    WRAPPER_AUTH_KEY=swk_xxx ./wrapper --sys myserver --test") + "\n\n")

	b.WriteString(h("  REMOTE PATHS") + "\n\n")
	b.WriteString(w("  For SCP and Rsync, prefix remote paths with \":\" — the wrapper") + "\n")
	b.WriteString(w("  automatically prepends user@host from the connection profile.") + "\n\n")
	b.WriteString(d("    :/path/to/file  →  user@host:/path/to/file") + "\n\n")

	b.WriteString(h("  AUTH KEYS") + "\n\n")
	b.WriteString(w("  Auth keys allow automated tools to use connections without the") + "\n")
	b.WriteString(w("  vault passphrase. Each key is shown once at creation. Generate") + "\n")
	b.WriteString(w("  one key per calling system for individual revocation.") + "\n\n")
	b.WriteString(d("  Manage keys from the interactive menu: [C] Config > Auth Keys") + "\n\n")

	b.WriteString(h("  SECURITY") + "\n\n")
	b.WriteString(w("  • Vault encrypted AES-256-GCM with Argon2id key derivation") + "\n")
	b.WriteString(w("  • Bound to this machine — won't decrypt on different hardware") + "\n")
	b.WriteString(w("  • Bound to this binary — won't decrypt with a different build") + "\n")
	b.WriteString(w("  • Auth keys stored as hashes — plaintext never persisted") + "\n")
	b.WriteString(w("  • Passphrase policy: 12+ chars, upper+lower+digit+special, not common") + "\n")
	b.WriteString(w("  • 5 failed passphrase attempts wipes the vault (backup saved)") + "\n")
	b.WriteString(w("  • Local-only — remote calls are rejected") + "\n")
	b.WriteString(w("  • Wrong binary detected before passphrase attempt") + "\n\n")

	b.WriteString(h("  HARDWARE MIGRATION") + "\n\n")
	b.WriteString(w("  Moving to a new machine (new CPU, motherboard, or host)?") + "\n")
	b.WriteString(w("  From Config → Export for Hardware Migration, the wrapper creates") + "\n")
	b.WriteString(w("  vault.hwmigration next to the binary, encrypted with your passphrase") + "\n")
	b.WriteString(w("  and a freshly generated one-time code shown once on screen.") + "\n\n")
	b.WriteString(d("  1. Export on the source machine → write down the code.") + "\n")
	b.WriteString(d("  2. Copy the binary and vault.hwmigration to the new machine.") + "\n")
	b.WriteString(d("  3. Launch the wrapper there — import prompt appears automatically.") + "\n\n")
	b.WriteString(d("  • Expires 24 hours after export (network-time verified).") + "\n")
	b.WriteString(d("  • Auth keys are NOT migrated — regenerate on the new machine.") + "\n\n")

	b.WriteString(h("  OTHER FLAGS") + "\n\n")
	b.WriteString(fmt.Sprintf("  %s  %s\n", m("--help    "), w("Show this help")))
	b.WriteString(fmt.Sprintf("  %s  %s\n", m("--version "), w("Show version and machine fingerprint")))
	b.WriteString(fmt.Sprintf("  %s  %s\n", m("--list    "), w("List connection names")))
	b.WriteString(fmt.Sprintf("  %s  %s\n", m("--key-file"), w("Read auth key from file (safer than --key)")))
	b.WriteString("\n")

	b.WriteString(fmt.Sprintf("  SecureWrapper v%s  •  Machine: %s  •  Binary: %s\n", version, ShortFingerprint(), BinaryKeyFingerprint()))
	b.WriteString("\n")

	return b.String()
}
