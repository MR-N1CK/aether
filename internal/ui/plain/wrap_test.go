package plain

import (
	"os"
	"strings"
	"testing"
	"time"

	"aether/internal/events"
	"aether/internal/realworld"
	"aether/internal/report"
	"aether/internal/ui/theme"
)

func TestWrapWords_Basic(t *testing.T) {
	got := WrapWords("the quick brown fox jumps over the lazy dog", 10)
	for _, line := range got {
		if len([]rune(line)) > 10 {
			t.Errorf("line exceeds width 10: %q", line)
		}
	}
	if len(got) < 3 {
		t.Errorf("expected wrapped lines, got %d: %v", len(got), got)
	}
}

func TestWrapWords_HardSplitsOversizedWords(t *testing.T) {
	long := strings.Repeat("x", 50)
	got := WrapWords(long, 10)
	if len(got) != 5 {
		t.Errorf("expected 5 hard-split lines, got %d: %v", len(got), got)
	}
	for _, line := range got {
		if len([]rune(line)) > 10 {
			t.Errorf("hard-split line exceeds width: %q", line)
		}
	}
}

func TestWrapWords_NeverEmpty(t *testing.T) {
	if got := WrapWords("", 10); len(got) != 1 || got[0] != "" {
		t.Errorf("empty input should yield a single empty line, got %v", got)
	}
}

func TestContentWidth_FallbackWithoutTerminal(t *testing.T) {
	t.Setenv("COLUMNS", "")
	w := os.Stderr
	// Non-TTY in test environments; expect the fallback (or DefaultContentWidth floor).
	got := ContentWidth(w, 88)
	if got != 88 && got != DefaultContentWidth {
		t.Errorf("expected fallback width 88 or %d, got %d", DefaultContentWidth, got)
	}

	t.Setenv("COLUMNS", "60")
	if got := ContentWidth(w, 88); got != 60 {
		t.Errorf("COLUMNS=60 should be honored, got %d", got)
	}

	t.Setenv("COLUMNS", "5")
	if got := ContentWidth(w, 88); got < MinUsableWidth {
		t.Errorf("degenerate COLUMNS must be ignored, got %d", got)
	}
}

// visualWidth returns the length of a line in terminal columns (rune-count is a
// faithful proxy for these boxes: they contain no ANSI sequences or
// double-width characters).
func visualWidth(s string) int {
	return len([]rune(s))
}

// assertBoxIntegrity checks that every emitted row matches the width defined
// by the card's horizontal rules, so borders can never be torn by long values.
func assertBoxIntegrity(t *testing.T, out string, name string) {
	t.Helper()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	expected := -1
	for _, l := range lines {
		if strings.HasPrefix(l, "+") {
			expected = visualWidth(l)
			break
		}
	}
	if expected < 10 {
		return
	}
	for _, l := range lines {
		if visualWidth(l) != expected {
			t.Errorf("%s has width %d, expected %d: %q (runes: %q)",
				name, visualWidth(l), expected, l, []rune(l))
		}
	}
}

// TestRenderFindingCard_NoColor_BoxIntegrity guards the ASCII card geometry:
// every emitted line must match the ruled card width, even with pathological values.
func TestRenderFindingCard_NoColor_BoxIntegrity(t *testing.T) {
	th := theme.NewTheme(true) // NoColor
	f := report.NewFinding("filesystem", report.SeverityAlert, "/tmp/.stealth/dropped_payload.bin",
		"reverse shell", "Script_Reverse_Shell_Interactive")
	f.Path = "/tmp/.stealth/" + strings.Repeat("very_long_directory_segment_", 8) + "/payload.sh"
	f.Title = strings.Repeat("Persisted Rootkit Loader ", 12)
	f.Why = strings.Repeat("This file establishes persistence with obfuscated re-execution hooks. ", 6)
	f.RuleName = "Script_Reverse_Shell_Interactive"
	f.Module = "filesystem"

	var buf strings.Builder
	RenderFindingCard(&buf, f, th)
	assertBoxIntegrity(t, buf.String(), "finding card")
}

// TestRenderExecutiveVerdict_NoColor_BoxIntegrity does the same for the verdict card.
func TestRenderExecutiveVerdict_NoColor_BoxIntegrity(t *testing.T) {
	th := theme.NewTheme(true)
	ev := events.ScanFinished{
		TotalDuration: 2 * time.Second,
		TotalFindings: 5,
		Alerts:        3,
		Warnings:      4,
		Notices:       6,
		Infos:         10,
		Verdict:       events.VerdictCompromised,
		VerdictReason: strings.Repeat("Post-exploitation persistence chain reconstructed from ", 6),
		ModulesNotRun: []string{"kernel", "persistence", strings.Repeat("very_long_module_name_", 6)},
		Coverage: events.CoverageStats{
			FilesScanned: 50000,
		},
	}

	var buf strings.Builder
	RenderExecutiveVerdict(&buf, ev, th)
	assertBoxIntegrity(t, buf.String(), "executive verdict card")

	if !strings.Contains(buf.String(), "CRITICAL") {
		t.Errorf("expected CRITICAL risk level in verdict output")
	}
}

func TestRenderExecutiveAssessmentCard_NoColor_BoxIntegrity(t *testing.T) {
	th := theme.NewTheme(true)
	ass := realworld.ComprehensiveSystemAssessment{
		Posture:          realworld.PostureHighRisk,
		SummaryRationale: strings.Repeat("Persistence across five stages was identified across the endpoint. ", 5),
		AlertsCount:      3,
		WarningsCount:    5,
		NoticesCount:     7,
		InfosCount:       11,
		NextActions: []realworld.PrioritizedAction{
			{Priority: 1, Title: strings.Repeat("Isolate the endpoint from the production network segment ", 3), Command: strings.Repeat("aether ack /tmp/payload ", 4)},
		},
	}
	var bd realworld.DurationBreakdown

	var buf strings.Builder
	RenderExecutiveAssessmentCard(&buf, ass, bd, th)
	assertBoxIntegrity(t, buf.String(), "executive assessment card")
}
