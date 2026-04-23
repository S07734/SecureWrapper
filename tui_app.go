package main

import (
	tea "github.com/charmbracelet/bubbletea"
)

// Screen identifiers
type Screen int

const (
	ScreenConnectionList Screen = iota
	ScreenAddConnection
	ScreenEditConnection
	ScreenDetail
	ScreenAuthKeys
	ScreenChecklist
	ScreenConfirm
	ScreenPassphrase
	ScreenHelp
	ScreenConfig
	ScreenHWExport
	ScreenAbout
)

// Custom messages for screen transitions
type switchScreenMsg struct {
	screen Screen
	model  tea.Model
}

type statusMsg string

type testResultMsg struct {
	name string
	err  error
}

type upgradeRequestMsg struct{}
type restoreCompleteMsg struct{}

// App is the root Bubbletea model.
type App struct {
	activeScreen     tea.Model
	vault            *Vault
	width            int
	height           int
	upgradeRequested bool
	restoreCompleted bool
}

func NewApp(vault *Vault) App {
	return App{
		activeScreen: NewConnectionList(vault),
		vault:        vault,
		width:        80,
		height:       24,
	}
}

func (a App) Init() tea.Cmd {
	return a.activeScreen.Init()
}

func (a App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width = msg.Width
		a.height = msg.Height
		// Forward to active screen
		var cmd tea.Cmd
		a.activeScreen, cmd = a.activeScreen.Update(msg)
		return a, cmd

	case switchScreenMsg:
		if msg.model == nil {
			a.activeScreen = NewConnectionList(a.vault)
		} else {
			a.activeScreen = msg.model
		}
		// Seed the new screen with the current terminal dimensions so
		// size-aware screens (Help) render full-height on open rather than
		// waiting for the next resize event.
		if a.width > 0 && a.height > 0 {
			a.activeScreen, _ = a.activeScreen.Update(tea.WindowSizeMsg{Width: a.width, Height: a.height})
		}
		return a, a.activeScreen.Init()

	case statusMsg:
		// Only forward to active screen — don't duplicate in app
		var cmd tea.Cmd
		a.activeScreen, cmd = a.activeScreen.Update(msg)
		return a, cmd

	case testResultMsg:
		// Forward to active screen
		var cmd tea.Cmd
		a.activeScreen, cmd = a.activeScreen.Update(msg)
		return a, cmd

	case restoreCompleteMsg:
		a.restoreCompleted = true
		return a, tea.Quit

	case upgradeRequestMsg:
		a.upgradeRequested = true
		return a, tea.Quit

	case tea.KeyMsg:
		// Global quit on ctrl+c
		if msg.String() == "ctrl+c" {
			return a, tea.Quit
		}
	}

	// Dispatch to active screen
	var cmd tea.Cmd
	a.activeScreen, cmd = a.activeScreen.Update(msg)
	return a, cmd
}

func (a App) View() string {
	if a.activeScreen == nil {
		return ""
	}
	return a.activeScreen.View()
}
