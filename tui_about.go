package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// repoURL is the canonical project home. Surfaced in the About screen and
// in the help footer so admins can find docs / report issues.
const (
	repoURL     = "https://github.com/S07734/SecureWrapper"
	issuesURL   = "https://github.com/S07734/SecureWrapper/issues"
	releasesURL = "https://github.com/S07734/SecureWrapper/releases"
	licenseName = "MIT"
)

// AboutScreen is a read-only info screen reachable from the Config submenu.
// Shows the project wordmark, version + build metadata, fingerprints, and
// links admins can copy/paste.
type AboutScreen struct {
	vault *Vault
}

func NewAboutScreen(vault *Vault) AboutScreen {
	return AboutScreen{vault: vault}
}

func (a AboutScreen) Init() tea.Cmd { return nil }

func (a AboutScreen) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "b", "B", "enter":
			return a, func() tea.Msg {
				return switchScreenMsg{screen: ScreenConfig, model: NewConfigMenu(a.vault)}
			}
		case "q", "Q":
			return a, tea.Quit
		}
	}
	return a, nil
}

func (a AboutScreen) View() string {
	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(renderLogo())
	b.WriteString("\n\n")

	b.WriteString(titleStyle.Render("  -- About --") + "\n\n")

	// Build info
	b.WriteString(fmt.Sprintf("  %s  %s\n",
		headerStyle.Render(padRight("Version:", 20)),
		connTargetStyle.Render("v"+version),
	))
	b.WriteString(fmt.Sprintf("  %s  %s\n",
		headerStyle.Render(padRight("Build date:", 20)),
		connTargetStyle.Render(buildDate),
	))
	b.WriteString(fmt.Sprintf("  %s  %s\n",
		headerStyle.Render(padRight("License:", 20)),
		connTargetStyle.Render(licenseName),
	))
	b.WriteString("\n")

	// Links
	b.WriteString(headerStyle.Render("  Project") + "\n")
	b.WriteString(fmt.Sprintf("  %s  %s\n",
		dimStyle.Render(padRight("Home:", 20)),
		connNameStyle.Render(repoURL),
	))
	b.WriteString(fmt.Sprintf("  %s  %s\n",
		dimStyle.Render(padRight("Releases:", 20)),
		connNameStyle.Render(releasesURL),
	))
	b.WriteString(fmt.Sprintf("  %s  %s\n",
		dimStyle.Render(padRight("Report issue:", 20)),
		connNameStyle.Render(issuesURL),
	))
	b.WriteString("\n")

	// Fingerprints
	b.WriteString(headerStyle.Render("  This Instance") + "\n")
	b.WriteString(fmt.Sprintf("  %s  %s\n",
		dimStyle.Render(padRight("Machine fingerprint:", 20)),
		connTargetStyle.Render(ShortFingerprint()),
	))
	b.WriteString(fmt.Sprintf("  %s  %s\n",
		dimStyle.Render(padRight("Binary fingerprint:", 20)),
		connTargetStyle.Render(BinaryKeyFingerprint()),
	))
	b.WriteString("\n")

	// Why-it-exists blurb
	b.WriteString(headerStyle.Render("  Why this exists") + "\n")
	b.WriteString(connTargetStyle.Render("  Credential vault + connection passthrough.") + "\n")
	b.WriteString(connTargetStyle.Render("  Pair with an LLM agent: the AI gets a revocable auth key,") + "\n")
	b.WriteString(connTargetStyle.Render("  not your secrets. Transcript leak → revoke the key, done.") + "\n")

	b.WriteString("\n")
	b.WriteString(separatorStyle.Render("  "+strings.Repeat("-", 40)) + "\n")
	b.WriteString("  " + menuKeyStyle.Render("[B]") + " " + menuDescStyle.Render("Back") + "\n")

	return b.String()
}
