package theme_test

import (
	"os"
	"strings"
	"testing"

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

