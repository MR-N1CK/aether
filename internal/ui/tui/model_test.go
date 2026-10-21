package tui

import (
	"context"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"aether/internal/report"
	"aether/internal/ui/theme"
)

func themeForTests() *theme.Theme { return theme.NewTheme(true) }

func mkF(sev report.Severity, score int, path, rule string, t time.Time) report.Finding {
	f := report.Finding{
		Timestamp: t,
		Module:    "process",
		Severity:  sev,
		Path:      path,
		RuleName:  rule,
		Reason:    "test reason for " + rule,
	}
	f.Metadata = map[string]interface{}{"score": score}
	return f
}

func newTestModel(findings []report.Finding) Model {
	m := Model{
		theme:         themeForTests(),
		findings:      findings,
		visible:       make([]report.Finding, 0),
		sortBy:        sortBySeverity,
		selectedIndex: 0,
		state:         stateDashboard,
	}
	m.recomputeVisible()
	return m
}

func keyRunes(r string) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(r)} }

func isQuitCmd(t *testing.T, cmd tea.Cmd) bool {
	t.Helper()
	if cmd == nil {
		return false
	}
	_, ok := cmd().(tea.QuitMsg)
	return ok
}

func TestRecomputeVisible_SeveritySort(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	m := newTestModel([]report.Finding{
		mkF(report.SeverityWarning, 50, "/tmp/warn.sh", "Process_Warn", base),
		mkF(report.SeverityAlert, 90, "/tmp/alert.sh", "Shell_Rev", base.Add(time.Second)),
		mkF(report.SeverityNotice, 30, "/tmp/note.sh", "Log_Odd", base.Add(2*time.Second)),
	})

	if len(m.visible) != 3 {
		t.Fatalf("expected 3 visible findings, got %d", len(m.visible))
	}
	if m.visible[0].Severity != report.SeverityAlert {
		t.Errorf("expected ALERT first in worst-first sort, got %s", m.visible[0].Severity)
	}
	if m.visible[1].Severity != report.SeverityWarning {
		t.Errorf("expected WARNING second, got %s", m.visible[1].Severity)
	}
	if m.visible[2].Severity != report.SeverityNotice {
		t.Errorf("expected NOTICE last, got %s", m.visible[2].Severity)
	}
}

func TestRecomputeVisible_ScoreTiebreak(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	m := newTestModel([]report.Finding{
		mkF(report.SeverityAlert, 70, "/tmp/low.sh", "Shell_Rev", base.Add(time.Minute)),
		mkF(report.SeverityAlert, 90, "/tmp/high.sh", "Shell_Rev", base),
	})

	if m.visible[0].Path != "/tmp/high.sh" {
		t.Errorf("expected higher-score ALERT first, got %s", m.visible[0].Path)
	}
	if m.visible[1].Path != "/tmp/low.sh" {
		t.Errorf("expected lower-score ALERT second, got %s", m.visible[1].Path)
	}
}

func TestRecomputeVisible_ArrivalMode(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	m := newTestModel([]report.Finding{
		mkF(report.SeverityWarning, 50, "/tmp/warn.sh", "Process_Warn", base),
		mkF(report.SeverityAlert, 90, "/tmp/alert.sh", "Shell_Rev", base.Add(time.Second)),
	})

	m.sortBy = sortByArrival
	m.recomputeVisible()

	if m.visible[0].Path != "/tmp/warn.sh" {
		t.Errorf("arrival mode should preserve detection order, got %s first", m.visible[0].Path)
	}
}

func TestRecomputeVisible_AnchorSelection(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	m := newTestModel([]report.Finding{
		mkF(report.SeverityWarning, 50, "/tmp/a.sh", "Process_Warn", base),
		mkF(report.SeverityWarning, 51, "/tmp/b.sh", "Process_Warn", base.Add(time.Second)),
		mkF(report.SeverityWarning, 52, "/tmp/c.sh", "Process_Warn", base.Add(2*time.Second)),
	})

	m.sortBy = sortBySeverity
	m.recomputeVisible()
	m.selectedIndex = 1 // cursor on /tmp/b.sh (severity sort inverted arrival order: c,b,a)
	selected := m.visible[m.selectedIndex].Path

	// A new alert arrives and sorts to the top; the cursor must stay on the
	// same finding instead of shifting with the rows above it.
	m.findings = append(m.findings, mkF(report.SeverityAlert, 95, "/tmp/z.sh", "Shell_Rev", base.Add(3*time.Second)))
	m.recomputeVisible()

	if got := m.visible[m.selectedIndex].Path; got != selected {
		t.Errorf("selection anchored to %s, but ended on %s", selected, got)
	}
	if m.visible[0].Path != "/tmp/z.sh" {
		t.Errorf("expected new ALERT at top after sort, got %s", m.visible[0].Path)
	}
}

func TestRecomputeVisible_FuzzyFilter(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	m := newTestModel([]report.Finding{
		mkF(report.SeverityAlert, 90, "/tmp/revshell.sh", "Shell_Rev", base),
		mkF(report.SeverityNotice, 30, "/var/log/dpkg.log", "Pkg_Odd", base.Add(time.Second)),
		mkF(report.SeverityWarning, 50, "/tmp/hidebin", "Process_Masquerade", base.Add(2*time.Second)),
	})

	m.filterQuery = "rvsh"
	m.recomputeVisible()
	if len(m.visible) != 1 || m.visible[0].Path != "/tmp/revshell.sh" {
		t.Errorf("expected only revshell to match 'rvsh', got %+v", m.visible)
	}

	m.filterQuery = "masq"
	m.recomputeVisible()
	if len(m.visible) != 1 || m.visible[0].RuleName != "Process_Masquerade" {
		t.Errorf("expected Masquerade rule to match 'masq', got %+v", m.visible)
	}

	m.filterQuery = ""
	m.recomputeVisible()
	if len(m.visible) != 3 {
		t.Errorf("expected all findings after clearing query, got %d", len(m.visible))
	}
}

func TestRecomputeVisible_FilterClampsSelection(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	m := newTestModel([]report.Finding{
		mkF(report.SeverityAlert, 90, "/tmp/revshell.sh", "Shell_Rev", base),
		mkF(report.SeverityWarning, 50, "/tmp/hidebin", "Process_Masquerade", base.Add(time.Second)),
	})

	m.selectedIndex = 1
	m.filterQuery = "rvsh"
	m.recomputeVisible()

	if m.selectedIndex != 0 {
		t.Errorf("selection should clamp to 0 when the selected finding is filtered out, got %d", m.selectedIndex)
	}
}

func TestRecomputeVisible_StructuredGrammar(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	f1 := mkF(report.SeverityAlert, 90, "/tmp/revshell.sh", "Shell_Rev", base)
	f1.Module = "filesystem"
	f2 := mkF(report.SeverityWarning, 50, "/etc/cron.d/stealth", "Persistence_Cron", base.Add(time.Second))
	f2.Module = "persistence"
	f3 := mkF(report.SeverityWarning, 45, "/proc/999/exe", "Process_Masquerade", base.Add(2*time.Second))
	f3.Module = "process"

	m := newTestModel([]report.Finding{f1, f2, f3})

	// Test sev:alert
	m.filterQuery = "sev:alert"
	m.recomputeVisible()
	if len(m.visible) != 1 || m.visible[0].Path != "/tmp/revshell.sh" {
		t.Errorf("expected 1 alert finding, got %+v", m.visible)
	}

	// Test mod:persistence
	m.filterQuery = "mod:persistence"
	m.recomputeVisible()
	if len(m.visible) != 1 || m.visible[0].Path != "/etc/cron.d/stealth" {
		t.Errorf("expected 1 persistence finding, got %+v", m.visible)
	}

	// Test compound sev:warning mod:process
	m.filterQuery = "sev:warning mod:process"
	m.recomputeVisible()
	if len(m.visible) != 1 || m.visible[0].Path != "/proc/999/exe" {
		t.Errorf("expected 1 process warning finding, got %+v", m.visible)
	}

	// Test path filter
	m.filterQuery = "path:/etc"
	m.recomputeVisible()
	if len(m.visible) != 1 || m.visible[0].RuleName != "Persistence_Cron" {
		t.Errorf("expected 1 cron finding matching path:/etc, got %+v", m.visible)
	}
}

func TestGuardedQuit_ConfirmFlow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newTestModel(nil)
	m.cancelScan = cancel
	m.scanFinished = false

	// q while scan is running: must NOT quit, must open the confirm modal.
	nm, _ := m.Update(keyRunes("q"))
	m = nm.(Model)
	if !m.confirmQuit {
		t.Fatal("expected confirm modal after q during an active scan")
	}
	if isQuitCmd(t, nil) {
		t.Fatal("sanity")
	}

	// Any other key is swallowed by the modal.
	nm, _ = m.Update(keyRunes("j"))
	m = nm.(Model)
	if !m.confirmQuit {
		t.Fatal("expected confirm modal to swallow unrelated keys")
	}

	// n (or Esc) cancels the modal.
	nm, _ = m.Update(keyRunes("n"))
	m = nm.(Model)
	if m.confirmQuit {
		t.Fatal("expected modal dismissed after n")
	}

	// Re-open and confirm with y: quit (and scan context cancelled).
	nm, _ = m.Update(keyRunes("q"))
	m = nm.(Model)
	nm, cmd := m.Update(keyRunes("y"))
	m = nm.(Model)
	if !isQuitCmd(t, cmd) {
		t.Fatal("expected tea.Quit after confirming with y")
	}
	if ctx.Err() == nil {
		t.Fatal("expected scan context to be cancelled on confirmed quit")
	}
}

func TestGuardedQuit_EscCancels(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newTestModel(nil)
	m.cancelScan = cancel

	nm, _ := m.Update(keyRunes("q"))
	m = nm.(Model)
	if !m.confirmQuit {
		t.Fatal("expected confirm modal after q during an active scan")
	}
	esc := tea.KeyMsg{Type: tea.KeyEsc}
	nm, _ = m.Update(esc)
	m = nm.(Model)
	if m.confirmQuit {
		t.Fatal("expected modal dismissed after Esc")
	}
}

func TestGuardedQuit_ImmediateAfterFinish(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newTestModel(nil)
	m.cancelScan = cancel
	m.scanFinished = true

	_, cmd := m.Update(keyRunes("q"))
	if !isQuitCmd(t, cmd) {
		t.Fatal("expected immediate quit once the scan has finished")
	}
}

func TestSortToggle_KeyS(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	m := newTestModel([]report.Finding{
		mkF(report.SeverityWarning, 50, "/tmp/warn.sh", "Process_Warn", base),
		mkF(report.SeverityAlert, 90, "/tmp/alert.sh", "Shell_Rev", base.Add(time.Second)),
	})

	if m.sortBy != sortBySeverity {
		t.Fatalf("expected severity sort by default")
	}
	if m.visible[0].Path != "/tmp/alert.sh" {
		t.Fatalf("expected ALERT first before toggling, got %s", m.visible[0].Path)
	}

	nm, _ := m.Update(keyRunes("s"))
	m = nm.(Model)
	if m.sortBy != sortByArrival {
		t.Fatalf("expected arrival sort after pressing s")
	}
	if m.visible[0].Path != "/tmp/warn.sh" {
		t.Errorf("arrival mode should restore detection order, got %s first", m.visible[0].Path)
	}

	nm, _ = m.Update(keyRunes("s"))
	m = nm.(Model)
	if m.sortBy != sortBySeverity || m.visible[0].Path != "/tmp/alert.sh" {
		t.Error("expected sort to toggle back to severity mode")
	}
}

func TestJumpAlertNavigation(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	findings := []report.Finding{
		mkF(report.SeverityWarning, 50, "/tmp/warn1.sh", "Process_Warn", base),
		mkF(report.SeverityAlert, 90, "/tmp/alert1.sh", "Shell_Rev", base.Add(time.Second)),
		mkF(report.SeverityNotice, 30, "/tmp/note1.sh", "Log_Odd", base.Add(2*time.Second)),
		mkF(report.SeverityAlert, 95, "/tmp/alert2.sh", "Shell_Rev", base.Add(3*time.Second)),
		mkF(report.SeverityWarning, 55, "/tmp/warn2.sh", "Process_Warn", base.Add(4*time.Second)),
	}

	m := newTestModel(findings)
	m.sortBy = sortByArrival
	m.recomputeVisible()
	m.selectedIndex = 0 // start on warn1.sh

	// Jump to next alert -> should land on alert1 (idx 1)
	nm, _ := m.Update(keyRunes("n"))
	m = nm.(Model)
	if m.selectedIndex != 1 || m.visible[m.selectedIndex].Path != "/tmp/alert1.sh" {
		t.Fatalf("expected jump to alert1 (idx 1), got idx %d (%s)", m.selectedIndex, m.visible[m.selectedIndex].Path)
	}

	// Jump to next alert -> should land on alert2 (idx 3)
	nm, _ = m.Update(keyRunes("n"))
	m = nm.(Model)
	if m.selectedIndex != 3 || m.visible[m.selectedIndex].Path != "/tmp/alert2.sh" {
		t.Fatalf("expected jump to alert2 (idx 3), got idx %d (%s)", m.selectedIndex, m.visible[m.selectedIndex].Path)
	}

	// Jump to next alert -> should wrap around to alert1 (idx 1)
	nm, _ = m.Update(keyRunes("n"))
	m = nm.(Model)
	if m.selectedIndex != 1 || m.visible[m.selectedIndex].Path != "/tmp/alert1.sh" {
		t.Fatalf("expected wrap around to alert1 (idx 1), got idx %d (%s)", m.selectedIndex, m.visible[m.selectedIndex].Path)
	}

	// Jump to prev alert (N) -> should wrap backwards to alert2 (idx 3)
	nm, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("N")})
	m = nm.(Model)
	if m.selectedIndex != 3 || m.visible[m.selectedIndex].Path != "/tmp/alert2.sh" {
		t.Fatalf("expected backward wrap to alert2 (idx 3), got idx %d (%s)", m.selectedIndex, m.visible[m.selectedIndex].Path)
	}

	// Jump to prev alert (N) -> should land on alert1 (idx 1)
	nm, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("N")})
	m = nm.(Model)
	if m.selectedIndex != 1 || m.visible[m.selectedIndex].Path != "/tmp/alert1.sh" {
		t.Fatalf("expected backward jump to alert1 (idx 1), got idx %d (%s)", m.selectedIndex, m.visible[m.selectedIndex].Path)
	}
}

