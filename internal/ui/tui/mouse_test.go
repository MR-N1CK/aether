package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"

	"aether/internal/events"
	"aether/internal/report"
)

func mouseLeft(x, y int) tea.MouseMsg {
	return tea.MouseMsg{Type: tea.MouseLeft, X: x, Y: y}
}

func TestTabHitX(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	m := newTestModel([]report.Finding{
		mkF(report.SeverityAlert, 90, "/tmp/a.sh", "R1", base),
		mkF(report.SeverityWarning, 60, "/tmp/w.sh", "R2", base),
		mkF(report.SeverityNotice, 30, "/tmp/n.sh", "R3", base),
	})

	// Label widths (3 findings, all live-host module): "1: ALL (3)"=10,
	// "2: THREATS (1)"=14, "3: ANOMALIES (1)"=16, joined by single spaces and
	// starting at column telemetryX0=3.
	cases := []struct {
		x    int
		want int
	}{
		{3, 0},   // first char of "1: ALL (3)"
		{12, 0},  // last char of tab 0
		{13, -1}, // separator gap
		{14, 1},  // first char of "2: THREATS (1)"
		{27, 1},  // last char of tab 1
		{28, -1}, // separator gap
		{29, 2},  // first char of "3: ANOMALIES (1)"
		{80, -1}, // beyond the tab bar
	}
	for _, tc := range cases {
		if got := m.tabHitX(tc.x); got != tc.want {
			t.Errorf("tabHitX(%d) = %d, want %d", tc.x, got, tc.want)
		}
	}
}

func TestFeedWindow(t *testing.T) {
	cases := []struct {
		sel, max, n, wantStart, wantVisible int
	}{
		{0, 5, 10, 0, 5},
		{4, 5, 10, 0, 5},
		{7, 5, 10, 3, 5},  // selection pinned to the bottom of the window
		{9, 5, 10, 5, 5},  // last row fully visible
		{0, 5, 3, 0, 3},   // short list
		{0, 5, 0, 0, 0},   // empty list
		{20, 5, 10, 9, 1}, // defensive clamp for stale selection
	}
	for _, tc := range cases {
		start, visible := feedWindow(tc.sel, tc.max, tc.n)
		if start != tc.wantStart || visible != tc.wantVisible {
			t.Errorf("feedWindow(%d,%d,%d) = (%d,%d), want (%d,%d)",
				tc.sel, tc.max, tc.n, start, visible, tc.wantStart, tc.wantVisible)
		}
	}
}

func mouseTestModel(t *testing.T, width, height int) Model {
	t.Helper()
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	m := newTestModel([]report.Finding{
		mkF(report.SeverityAlert, 90, "/tmp/alert.sh", "R1", base),
		mkF(report.SeverityWarning, 60, "/tmp/warn.sh", "R2", base),
		mkF(report.SeverityNotice, 30, "/tmp/note.sh", "R3", base),
	})
	m.width = width
	m.height = height
	m.spinner = spinner.New()
	return m
}

func TestDashFeedGeom_FlightDeck(t *testing.T) {
	m := mouseTestModel(t, 134, 40) // cardWidth 130 >= 120: flight deck

	g := m.dashFeedGeom()
	// brand(4) + blank(2) + telemetry box(2+3) + blank(2) = 13; pane inset 2; header 5.
	if g.firstRowY != 20 {
		t.Errorf("flight deck firstRowY = %d, want 20", g.firstRowY)
	}
	if g.start != 0 || g.visible != 3 {
		t.Errorf("flight deck window = (%d,%d), want (0,3)", g.start, g.visible)
	}
	// feed box top 13 + box height (2 border + 2 vpad + 5 header + 2*3 rows) + blank 2.
	if g.inspectorY != 30 {
		t.Errorf("flight deck inspectorY = %d, want 30", g.inspectorY)
	}
	if g.feedMaxX != -1 {
		t.Errorf("flight deck feedMaxX = %d, want -1 (full width)", g.feedMaxX)
	}
}

func TestDashFeedGeom_Stacked(t *testing.T) {
	m := mouseTestModel(t, 94, 24) // cardWidth 90 < 120: stacked layout

	g := m.dashFeedGeom()
	// The module card's wrapped height makes stacked row coordinates
	// unpredictable, so row clicks are intentionally disabled there.
	if g.firstRowY != -1 {
		t.Errorf("stacked firstRowY = %d, want -1 (row clicks disabled)", g.firstRowY)
	}
	if g.inspectorY != -1 {
		t.Errorf("stacked inspectorY = %d, want -1 (no dock)", g.inspectorY)
	}
	if g.start != 0 || g.visible != 3 {
		t.Errorf("stacked window = (%d,%d), want (0,3)", g.start, g.visible)
	}
}

func TestDashFeedGeom_MatchesRenderedView(t *testing.T) {
	m := mouseTestModel(t, 134, 40) // flight deck
	g := m.dashFeedGeom()

	// NoColor theme: rendered lines contain no ANSI sequences, so the
	// absolute line index of the first row's path is directly findable.
	frame := m.View()
	lines := strings.Split(frame, "\n")
	wantPath := "/tmp/alert.sh" // first visible row
	found := -1
	for i, ln := range lines {
		if strings.Contains(ln, wantPath) {
			found = i
			break
		}
	}
	if found < 0 {
		t.Fatalf("first row path %q not found in rendered frame", wantPath)
	}
	if found != g.firstRowY {
		t.Fatalf("rendered first row at line %d, geometry says %d", found, g.firstRowY)
	}

	// Second row must sit exactly one stride below.
	if len(lines) > g.firstRowY+g.rowStride && g.visible >= 2 {
		if !strings.Contains(lines[g.firstRowY+g.rowStride], "/tmp/warn.sh") {
			t.Fatalf("second row not at firstRowY+stride: %q", lines[g.firstRowY+g.rowStride])
		}
	}
}

func TestHandleMouseClick_StackedRowsIgnored(t *testing.T) {
	m := mouseTestModel(t, 94, 24) // stacked: no row clicks

	if cmd := m.handleMouseClick(mouseLeft(10, 28)); cmd != nil {
		t.Fatalf("stacked row click returned non-nil cmd: %v", cmd)
	}
	if m.selectedIndex != 0 {
		t.Fatalf("stacked row click changed selection to %d", m.selectedIndex)
	}
	// Tabs still work in stacked layouts.
	m.handleMouseClick(mouseLeft(14, telemetryTabY))
	if m.dashboardTab != 1 {
		t.Fatalf("stacked tab click selected tab %d, want 1", m.dashboardTab)
	}
}

func TestHandleMouseClick_RowSelectionAndDossier(t *testing.T) {
	m := mouseTestModel(t, 134, 40)
	g := m.dashFeedGeom()

	// Click row 1 (warn): selects it.
	if cmd := m.handleMouseClick(mouseLeft(10, g.firstRowY+g.rowStride)); cmd != nil {
		t.Fatalf("row select returned non-nil cmd: %v", cmd)
	}
	if m.selectedIndex != 1 {
		t.Fatalf("click on row 1 selected index %d, want 1", m.selectedIndex)
	}

	// Click the same row again: opens the dossier.
	if cmd := m.handleMouseClick(mouseLeft(10, g.firstRowY+g.rowStride)); cmd != nil {
		t.Fatalf("dossier open returned non-nil cmd: %v", cmd)
	}
	if m.state != stateDetail {
		t.Fatalf("second click on selected row: state = %v, want stateDetail", m.state)
	}

	// Clicking the inspector dock also opens the dossier.
	m2 := mouseTestModel(t, 134, 40)
	g2 := m2.dashFeedGeom()
	m2.handleMouseClick(mouseLeft(10, g2.inspectorY+2))
	if m2.state != stateDetail {
		t.Fatalf("inspector click: state = %v, want stateDetail", m2.state)
	}
}

func TestHandleMouseClick_Tabs(t *testing.T) {
	m := mouseTestModel(t, 134, 40)

	if cmd := m.handleMouseClick(mouseLeft(telemetryX0, telemetryTabY)); cmd != nil {
		t.Fatalf("tab click returned non-nil cmd: %v", cmd)
	}
	if m.dashboardTab != 0 {
		t.Fatalf("tab 0 click selected tab %d", m.dashboardTab)
	}

	// X=14 is the first char of "2: THREATS (1)".
	m.handleMouseClick(mouseLeft(14, telemetryTabY))
	if m.dashboardTab != 1 {
		t.Fatalf("THREATS tab click selected tab %d, want 1", m.dashboardTab)
	}

	// Clicks on the tab row but outside any label do nothing.
	before := m.dashboardTab
	m.handleMouseClick(mouseLeft(200, telemetryTabY))
	if m.dashboardTab != before {
		t.Fatal("click outside tab labels changed the tab")
	}

	// Tab clicks only work on the exact tab line.
	m.handleMouseClick(mouseLeft(13, telemetryTabY+1))
	if m.dashboardTab != 1 {
		t.Fatal("click one line below the tab row changed the tab")
	}
}

func TestHandleMouseClick_BlockedWhileFiltering(t *testing.T) {
	m := mouseTestModel(t, 134, 40)
	g := m.dashFeedGeom()
	m.isFiltering = true

	m.handleMouseClick(mouseLeft(10, g.firstRowY))
	if m.selectedIndex != 0 {
		t.Fatal("row click while filtering must be ignored")
	}
	m.handleMouseClick(mouseLeft(13, telemetryTabY))
	if m.dashboardTab != 0 {
		t.Fatal("tab click while filtering must be ignored")
	}
}

func TestHandleMouseClick_OutOfBoundsIgnored(t *testing.T) {
	m := mouseTestModel(t, 134, 40)
	g := m.dashFeedGeom()

	// Below the last visible row but above the inspector: dead zone between
	// the feed rows and the dock only exists when fewer rows than the window
	// allow; with 3 findings clicking far past the rows must not crash and
	// must not change selection.
	m.handleMouseClick(mouseLeft(10, g.firstRowY-1))
	if m.selectedIndex != 0 {
		t.Fatal("click above the feed changed selection")
	}
}

func TestBellOnFirstAlertOnly(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	m := newTestModel(nil)

	first := m.handleScanEvent(events.FindingRaised{Finding: mkF(report.SeverityAlert, 90, "/tmp/a.sh", "R1", base)})
	if first == nil {
		t.Fatal("first ALERT must emit a bell cmd")
	}
	if !m.bellRung {
		t.Error("bellRung must be set after the first ALERT")
	}

	second := m.handleScanEvent(events.FindingRaised{Finding: mkF(report.SeverityCritical, 95, "/tmp/b.sh", "R2", base)})
	if second != nil {
		t.Fatal("subsequent alerts must not ring the bell again")
	}
	if !m.bellRung {
		t.Error("bellRung must stay set")
	}
}

func TestNoBellForWarnings(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	m := newTestModel(nil)

	cmd := m.handleScanEvent(events.FindingRaised{Finding: mkF(report.SeverityWarning, 60, "/tmp/w.sh", "R1", base)})
	if cmd != nil {
		t.Fatal("WARNING findings must not ring the bell")
	}
	if m.bellRung {
		t.Error("bellRung must remain false for non-alert findings")
	}
}

func TestVerdictGaugeEaseFill(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	newGaugeModel := func(noAnim bool, finishedAgo time.Duration) Model {
		m := newTestModel([]report.Finding{
			mkF(report.SeverityAlert, 90, "/tmp/a.sh", "R1", base),
		})
		m.noAnim = noAnim
		m.scanFinished = true
		m.finishedAt = time.Now().Add(-finishedAgo)
		return m
	}

	countFilled := func(gauge string) int { return strings.Count(gauge, "█") }
	full := -1

	// Just after finish: fill is still animating (less than final width).
	justStarted := countFilled(newGaugeModel(false, 0).renderRiskGauge(120, 1, 0))
	// After the 600ms draw completes: fill reaches its final width.
	settled := countFilled(newGaugeModel(false, 2*time.Second).renderRiskGauge(120, 1, 0))
	// Animations disabled: final width immediately.
	static := countFilled(newGaugeModel(true, 0).renderRiskGauge(120, 1, 0))

	full = settled
	if full <= 0 {
		t.Fatalf("settled gauge has no fill: %d", full)
	}
	if static != full {
		t.Fatalf("noAnim gauge fill %d must equal settled fill %d", static, full)
	}
	if justStarted >= full {
		t.Fatalf("animating gauge fill %d must be less than settled %d at t=0", justStarted, full)
	}
}
