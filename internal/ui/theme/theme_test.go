package theme_test

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"aether/internal/report"
	"aether/internal/ui/theme"
)

func TestDetectNoColor(t *testing.T) {
	origVal, exists := os.LookupEnv("NO_COLOR")
	defer func() {
		if exists {
			os.Setenv("NO_COLOR", origVal)
		} else {
			os.Unsetenv("NO_COLOR")
		}
	}()

	os.Setenv("NO_COLOR", "1")
	if !theme.DetectNoColor() {
		t.Error("expected DetectNoColor() true when NO_COLOR=1")
	}

	os.Setenv("NO_COLOR", "")
	if theme.DetectNoColor() {
		t.Error("expected DetectNoColor() false when NO_COLOR is empty")
	}

	os.Unsetenv("NO_COLOR")
	if theme.DetectNoColor() {
		t.Error("expected DetectNoColor() false when NO_COLOR is unset")
	}
}

func TestTheme_NoColorRendering(t *testing.T) {
	th := theme.NewTheme(true)
	if !th.NoColor {
		t.Fatal("expected theme to have NoColor=true")
	}

	badge := th.SeverityBadge(report.SeverityAlert)
	if !strings.Contains(badge, "ALERT") {
		t.Errorf("expected plain badge containing ALERT, got: %q", badge)
	}

	// Verify no ESC bytes (\x1b) in monochrome badge
	if strings.Contains(badge, "\x1b[") {
		t.Errorf("expected no ANSI color escape codes when NoColor=true, got: %q", badge)
	}
}

func TestTheme_ColorBadges(t *testing.T) {
	th := theme.NewTheme(false)
	if th.NoColor {
		t.Fatal("expected theme to have NoColor=false")
	}

	for _, sev := range []report.Severity{
		report.SeverityAlert,
		report.SeverityWarning,
		report.SeverityNotice,
		report.SeverityInfo,
	} {
		badge := th.SeverityBadge(sev)
		if badge == "" {
			t.Errorf("expected non-empty badge for severity %s", sev)
		}
	}
}

func TestTheme_ASCII(t *testing.T) {
	th := theme.NewTheme(false, true)
	if !th.ASCII {
		t.Fatal("expected theme to have ASCII=true")
	}

	if th.IconAlert() != "[!]" {
		t.Errorf("expected [!], got %q", th.IconAlert())
	}
	if th.IconWarn() != "[*]" {
		t.Errorf("expected [*], got %q", th.IconWarn())
	}
	if th.IconClean() != "[OK]" {
		t.Errorf("expected [OK], got %q", th.IconClean())
	}
	if th.IconBolt() != "[YARA]" {
		t.Errorf("expected [YARA], got %q", th.IconBolt())
	}
}

func TestTheme_GradientText(t *testing.T) {
	thColor := theme.NewTheme(false)
	rendered := thColor.RenderGradientText("AETHER", "#0284C7", "#38BDF8", "#F8FAFC")
	if !strings.Contains(rendered, "A") || !strings.Contains(rendered, "R") {
		t.Errorf("expected gradient text to contain runes, got: %q", rendered)
	}

	thNoColor := theme.NewTheme(true)
	plain := thNoColor.RenderGradientText("AETHER", "#0284C7", "#38BDF8")
	if plain != "AETHER" {
		t.Errorf("expected unmodified string in NoColor mode, got: %q", plain)
	}
}

func TestTheme_ThreatScoreMeter(t *testing.T) {
	thColor := theme.NewTheme(false)
	meterAlert := thColor.RenderThreatScoreMeter(90, 10)
	if !strings.Contains(meterAlert, "90/100") || !strings.Contains(meterAlert, "█") {
		t.Errorf("expected 90/100 with fill block in meter, got: %q", meterAlert)
	}

	thASCII := theme.NewTheme(false, true)
	meterASCII := thASCII.RenderThreatScoreMeter(50, 10)
	if !strings.Contains(meterASCII, "50/100") || !strings.Contains(meterASCII, "#") {
		t.Errorf("expected 50/100 with # block in ASCII meter, got: %q", meterASCII)
	}
}

func TestTheme_GradientBar(t *testing.T) {
	// lipgloss strips colors when stdout is not a TTY (as in tests); force
	// TrueColor so the gradient ramp is actually rendered, then restore.
	prevProfile := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(prevProfile)

	th := theme.NewTheme(false)
	empty := lipgloss.NewStyle().Foreground(lipgloss.Color("#333333"))

	// Truecolor: columns are tinted along the ramp — a wide bar must carry
	// more than one distinct SGR truecolor sequence (38;2;r;g;b).
	bar := th.RenderGradientBar(20, 1.0, empty, theme.AuroraRamp...)
	colors := ansiTrueColorRegex.FindAllString(bar, -1)
	uniq := map[string]bool{}
	for _, c := range colors {
		uniq[c] = true
	}
	if len(uniq) < 2 {
		t.Errorf("expected multi-stop gradient (>=2 distinct colors), got %d in %q", len(uniq), bar)
	}
	if strings.Contains(bar, "░") {
		t.Errorf("full-ratio bar must have no empty track, got %q", bar)
	}

	// Partial ratio leaves an empty track.
	partial := th.RenderGradientBar(20, 0.5, empty, theme.AuroraRamp...)
	if !strings.Contains(partial, "░") {
		t.Errorf("half bar must contain empty track, got %q", partial)
	}

	// Ratio clamping.
	over := th.RenderGradientBar(10, 2.0, empty, theme.AuroraRamp...)
	if strings.Contains(over, "░") {
		t.Errorf("ratio > 1 must clamp to full, got %q", over)
	}
	under := th.RenderGradientBar(10, -1, empty, theme.AuroraRamp...)
	if !strings.Contains(under, "░") {
		t.Errorf("negative ratio must clamp to empty, got %q", under)
	}

	// Monochrome fallback: solid fractional bar, no gradient escapes. The
	// empty style is plain too — production callers pass themed mono styles.
	thMono := theme.NewTheme(true)
	mono := thMono.RenderGradientBar(10, 0.5, lipgloss.NewStyle(), theme.AuroraRamp...)
	if ansiTrueColorRegex.MatchString(mono) {
		t.Errorf("monochrome bar must not contain color escapes, got %q", mono)
	}

	// ASCII fallback: # fills.
	thASCII := theme.NewTheme(false, true)
	ascii := thASCII.RenderGradientBar(10, 0.5, empty, theme.AuroraRamp...)
	if !strings.Contains(ascii, "#") {
		t.Errorf("ASCII bar must use # fills, got %q", ascii)
	}
}

// ansiTrueColorRegex matches 24-bit SGR foreground sequences.
var ansiTrueColorRegex = regexp.MustCompile(`38;2;\d+;\d+;\d+`)
