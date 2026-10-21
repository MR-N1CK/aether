package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"aether/internal/ui/theme"
)

func TestCommandPalette_SearchFilterAndExecute(t *testing.T) {
	th := theme.NewTheme(true)
	m := Model{
		theme:  th,
		width:  100,
		height: 35,
		state:  stateDashboard,
		sortBy: sortByArrival,
	}

	// 1. Open palette with "?"
	m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	if !m.showPalette {
		t.Fatalf("expected palette to be open after pressing '?'")
	}

	// Verify rendered view contains header and search box
	view := m.View()
	if !strings.Contains(view, "AETHER FORENSIC COMMAND CENTER") {
		t.Errorf("expected palette header, got: %s", view)
	}
	if !strings.Contains(view, "Filter Actions") {
		t.Errorf("expected filter actions prompt in view, got: %s", view)
	}

	// 2. Type "sort" into the palette
	for _, r := range "sort" {
		m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	if m.paletteQuery != "sort" {
		t.Errorf("expected paletteQuery 'sort', got: %q", m.paletteQuery)
	}

	filtered := m.getFilteredPaletteActions()
	if len(filtered) == 0 {
		t.Fatalf("expected at least 1 filtered action for 'sort', got 0")
	}
	if filtered[0].ActionID != "sort" {
		t.Errorf("expected top filtered action 'sort', got: %s", filtered[0].ActionID)
	}

	// 3. Press Enter to execute the "sort" action
	m.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if m.showPalette {
		t.Errorf("expected palette to close after executing action")
	}
	if m.sortBy != sortBySeverity {
		t.Errorf("expected sort order toggled to sortBySeverity, got: %v", m.sortBy)
	}

	// 4. Test Mouse Wheel navigation in palette
	m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	m.handleMouse(tea.MouseMsg{Type: tea.MouseWheelDown})
	if m.paletteSelectedIndex != 1 {
		t.Errorf("expected paletteSelectedIndex=1 after wheel down, got: %d", m.paletteSelectedIndex)
	}
	m.handleMouse(tea.MouseMsg{Type: tea.MouseWheelUp})
	if m.paletteSelectedIndex != 0 {
		t.Errorf("expected paletteSelectedIndex=0 after wheel up, got: %d", m.paletteSelectedIndex)
	}

	// 5. Dismiss with Esc
	m.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	if m.showPalette {
		t.Errorf("expected palette closed after Esc")
	}
}
