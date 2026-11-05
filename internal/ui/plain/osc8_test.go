package plain

import (
	"bytes"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"aether/internal/report"
	"aether/internal/ui/theme"
)

func TestOsc8Link_Format(t *testing.T) {
	got := osc8Link("/tmp/evil.sh", "/tmp/evil.sh")
	want := "\x1b]8;;file:///tmp/evil.sh\x1b\\/tmp/evil.sh\x1b]8;;\x1b\\"
	if got != want {
		t.Fatalf("osc8Link = %q, want %q", got, want)
	}
	if osc8Link("", "text") != "text" {
		t.Error("empty path must return text unchanged")
	}
	if osc8Link("/tmp/a", "") != "" {
		t.Error("empty text must return empty")
	}
}

func TestPadCell_ANSIAware(t *testing.T) {
	// ANSI-colored text: byte length 13, visible width 3.
	colored := "\x1b[31mabc\x1b[0m"
	got := padCell(colored, 6)
	if ansi.StringWidth(got) != 6 {
		t.Fatalf("padCell visible width = %d, want 6", ansi.StringWidth(got))
	}
	// Plain overlong string is returned unchanged.
	long := "abcdef"
	if padCell(long, 3) != long {
		t.Error("padCell must not truncate")
	}
}

func TestOsc8DisabledByEnv(t *testing.T) {
	t.Setenv("AETHER_NO_OSC8", "1")
	if osc8Enabled(&bytes.Buffer{}) {
		t.Fatal("osc8 must be disabled when AETHER_NO_OSC8 is set")
	}

	t.Setenv("AETHER_NO_OSC8", "")
	// bytes.Buffer is not a terminal, so still disabled regardless of env.
	if osc8Enabled(&bytes.Buffer{}) {
		t.Fatal("osc8 must be disabled on non-terminal writers")
	}
}

func TestRenderFindingCard_NoOsc8WhenPiped(t *testing.T) {
	var buf bytes.Buffer
	f := report.Finding{
		Module:   "scanner",
		Severity: report.SeverityAlert,
		Title:    "Test Finding",
		Path:     "/tmp/evil.sh",
		Reason:   "test",
	}
	RenderFindingCard(&buf, f, theme.NewTheme(false))
	if strings.Contains(buf.String(), "\x1b]8;;") {
		t.Error("piped output must not contain OSC 8 sequences")
	}
}
