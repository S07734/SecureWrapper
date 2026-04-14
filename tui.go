package main

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Color palette
var (
	cyan    = lipgloss.Color("#00BFFF")
	green   = lipgloss.Color("#00FF88")
	red     = lipgloss.Color("#FF4444")
	yellow  = lipgloss.Color("#FFD700")
	dim     = lipgloss.Color("#666666")
	white   = lipgloss.Color("#FFFFFF")
	magenta = lipgloss.Color("#FF44FF")
	bgDark  = lipgloss.Color("#1a1a2e")
)

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(cyan).
			Padding(0, 1)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(cyan).
			Padding(0, 1)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(yellow)

	connNameStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(green)

	connTypeStyle = lipgloss.NewStyle().
			Foreground(magenta)

	connTargetStyle = lipgloss.NewStyle().
			Foreground(white)

	dimStyle = lipgloss.NewStyle().
			Foreground(dim)

	menuKeyStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(yellow)

	menuDescStyle = lipgloss.NewStyle().
			Foreground(white)

	successStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(green)

	errorStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(red)

	warnStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(yellow)

	promptStyle = lipgloss.NewStyle().
			Foreground(cyan)

	separatorStyle = lipgloss.NewStyle().
			Foreground(dim)

	highlightStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#000000")).
			Background(cyan)

	cursorStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(cyan)
)

var logoText = strings.Join([]string{
	"╔═╗┌─┐┌─┐┬ ┬┬─┐┌─┐",
	"╚═╗├┤ │  │ │├┬┘├┤ ",
	"╚═╝└─┘└─┘└─┘┴└─└─┘",
	"╦ ╦┬─┐┌─┐┌─┐┌─┐┌─┐┬─┐",
	"║║║├┬┘├─┤├─┘├─┘├┤ ├┬┘",
	"╚╩╝┴└─┴ ┴┴  ┴  └─┘┴└─",
}, "\n")

func renderLogo() string {
	return lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(cyan).
		Foreground(cyan).
		Bold(true).
		Padding(1, 3).
		Align(lipgloss.Center).
		Width(40).
		Render(logoText)
}


// Utility

func padRight(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}
