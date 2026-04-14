package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// checklistResultMsg is sent when the checklist is confirmed or cancelled.
type checklistResultMsg struct {
	items     []string
	selected  []bool
	cancelled bool
}

// Checklist is a reusable checkbox list component.
type Checklist struct {
	title    string
	items    []string
	selected []bool
	cursor   int
}

func NewChecklist(title string, items []string, selected []bool) Checklist {
	sel := make([]bool, len(items))
	copy(sel, selected)
	return Checklist{
		title:    title,
		items:    items,
		selected: sel,
	}
}

func (cl Checklist) Init() tea.Cmd {
	return nil
}

func (cl Checklist) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if cl.cursor > 0 {
				cl.cursor--
			}
		case "down", "j":
			if cl.cursor < len(cl.items)-1 {
				cl.cursor++
			}
		case " ":
			if cl.cursor < len(cl.selected) {
				cl.selected[cl.cursor] = !cl.selected[cl.cursor]
			}
		case "enter":
			return cl, func() tea.Msg {
				return checklistResultMsg{
					items:    cl.items,
					selected: cl.selected,
				}
			}
		case "esc":
			return cl, func() tea.Msg {
				return checklistResultMsg{
					cancelled: true,
				}
			}
		}
	}

	return cl, nil
}

func (cl Checklist) View() string {
	var b strings.Builder

	b.WriteString("\n  " + titleStyle.Render(cl.title) + "\n\n")

	for i, item := range cl.items {
		checkbox := "[ ]"
		if cl.selected[i] {
			checkbox = "[x]"
		}

		if i == cl.cursor {
			b.WriteString(fmt.Sprintf("  %s %s %s\n",
				cursorStyle.Render(">"),
				highlightStyle.Render(checkbox),
				highlightStyle.Render(item),
			))
		} else {
			checkStyle := dimStyle
			if cl.selected[i] {
				checkStyle = connNameStyle
			}
			b.WriteString(fmt.Sprintf("    %s %s\n",
				checkStyle.Render(checkbox),
				connTargetStyle.Render(item),
			))
		}
	}

	b.WriteString("\n  " + dimStyle.Render("Space=toggle  Enter=confirm  Esc=cancel") + "\n")

	return b.String()
}
