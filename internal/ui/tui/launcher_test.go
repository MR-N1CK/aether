package tui

import (
	"strings"
	"testing"

	"aether/internal/ui/theme"
)

func launcherForTests(th *theme.Theme) LauncherModel {
	m := NewLauncherModel(th, "1.0.0")
	m.width = 100
	m.height = 40
	m.isRoot = true // deterministic FULL ACCESS badge; the non-root test overrides
	// Reveal the whole deck regardless of animation state.
	m.animFrame = 999
	return m
}

func TestLauncherView_ShowsAllActionsAndBadges(t *testing.T) {
	m := launcherForTests(theme.NewTheme(false))
	view := m.View()

	for _, want := range []string{
		"Quick Triage Scan",
		"Full System Deep Hunt",
		"Target Directory",
		"1-Click Rules Setup",
		"Open Executive HTML Report",
		"Interactive Threat Simulator",
		"Engine Status & Diagnostics",
		"Exit",
		"FULL ACCESS", // root badge
		"YARA-X ACTIVE",
		"COMMAND CENTER",
		"[Enter] Launch",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("launcher view missing %q", want)
		}
	}
}

func TestLauncherView_SelectedCardMarked(t *testing.T) {
	m := launcherForTests(theme.NewTheme(false))
	m.cursor = 1 // "Full System Deep Hunt" selected

	view := m.View()
	if !strings.Contains(view, "▌") {
		t.Error("selected card must render the luminous rail")
	}
	// The selected card carries a description line; unselected rows are compact.
	if !strings.Contains(view, "RECOMMENDED") && !strings.Contains(view, "DEEP HUNT") {
		t.Error("selected item's tag pill missing")
	}
}

func TestLauncherView_NonRootLimitedBadge(t *testing.T) {
	m := launcherForTests(theme.NewTheme(false))
	m.isRoot = false

	if !strings.Contains(m.View(), "LIMITED") {
		t.Error("non-root launcher must show the LIMITED badge")
	}
}

func TestLauncherView_NoColorFlatFallback(t *testing.T) {
	m := launcherForTests(theme.NewTheme(true))
	view := m.View()

	if !strings.Contains(view, "Quick Triage Scan") {
		t.Fatal("monochrome launcher lost its menu items")
	}
	if strings.Contains(view, "\x1b[38;2;") {
		t.Error("monochrome launcher must not emit truecolor sequences")
	}
}

func TestLauncherView_PathModalClarityLine(t *testing.T) {
	m := launcherForTests(theme.NewTheme(false))
	m.state = launcherStateInputPath
	m.textInput.SetValue("/var/www")

	view := m.View()
	// The modal wraps long lines; match on whitespace-normalized text.
	flat := strings.Join(strings.Fields(view), " ")
	for _, want := range []string{"TARGET DIRECTORY SCAN", "/var/www", "live system checks stay off."} {
		if !strings.Contains(flat, want) {
			t.Errorf("path modal missing %q", want)
		}
	}
}

func TestLauncherView_StaggeredReveal(t *testing.T) {
	m := launcherForTests(theme.NewTheme(false))
	m.animFrame = 0 // nothing revealed yet beyond the first card

	view := m.View()
	if !strings.Contains(view, "Quick Triage Scan") {
		t.Error("first card must be revealed at frame 0")
	}
	if strings.Contains(view, "Engine Status & Diagnostics") {
		t.Error("last card must still be hidden during the staggered reveal")
	}
}
