package theme

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"aether/internal/report"
)

// Spacing and layout constants
const (
	PaddingSmall  = 1
	PaddingMedium = 2
	MarginSmall   = 1
	MarginMedium  = 2
	MinTermWidth  = 72
	MinTermHeight = 18
)

// Palette definitions - Dark Luxurious Palette with truecolor, 256-color and 16-color fallbacks.
var (
	ColorObsidian = lipgloss.Color("#0B0F17") // Deep void black
	ColorSurface  = lipgloss.Color("#161B22") // Card background
	ColorBorder   = lipgloss.Color("#30363D") // Border slate
	ColorBorderLit= lipgloss.Color("#58A6FF") // Focused border
	ColorTextPrim = lipgloss.Color("#F0F6FC") // Platinum text
	ColorTextMute = lipgloss.Color("#8B949E") // Muted slate gray
	ColorAccent   = lipgloss.Color("#7C3AED") // Electric violet accent
	ColorCyan     = lipgloss.Color("#38BDF8") // Vibrant cyan

	// Severity colors
	ColorInfo    = lipgloss.Color("#38BDF8") // Electric sky
	ColorNotice  = lipgloss.Color("#34D399") // Emerald mint
	ColorWarning = lipgloss.Color("#FBBF24") // Vivid amber
	ColorAlert   = lipgloss.Color("#F43F5E") // Hyper crimson
)

// Theme encapsulates styling configurations respecting terminal capabilities and NO_COLOR.
type Theme struct {
	NoColor bool

	// Layout and Card styles
	AppContainer lipgloss.Style
	HeaderBox    lipgloss.Style
	LogoText     lipgloss.Style
	SubHeaderText lipgloss.Style
	CardBox      lipgloss.Style
	CardActive   lipgloss.Style
	StatusBar    lipgloss.Style

	// Finding list styles
	FindingRowNormal   lipgloss.Style
	FindingRowSelected lipgloss.Style
	FindingTimestamp   lipgloss.Style
	FindingModule      lipgloss.Style
	FindingPath        lipgloss.Style
	FindingReason      lipgloss.Style

	// Modal / detail styles
	ModalBox     lipgloss.Style
	ModalHeader  lipgloss.Style
	ModalFieldKey lipgloss.Style
	ModalFieldVal lipgloss.Style

	// Verdict banner styles
	VerdictClean       lipgloss.Style
	VerdictSuspicious  lipgloss.Style
	VerdictCompromised lipgloss.Style

	// Severity badge styles
	BadgeInfo    lipgloss.Style
	BadgeNotice  lipgloss.Style
	BadgeWarning lipgloss.Style
	BadgeAlert   lipgloss.Style
}

// DetectNoColor returns true if NO_COLOR environment variable is set per no-color.org.
func DetectNoColor() bool {
	val, ok := os.LookupEnv("NO_COLOR")
	return ok && val != ""
}

// NewTheme creates a Theme instance customized for color or monochrome terminals.
func NewTheme(noColor bool) *Theme {
	t := &Theme{NoColor: noColor}

	if noColor {
		// Monochrome styles: no background/foreground color escapes
		t.AppContainer = lipgloss.NewStyle().Padding(0, 1)
		t.HeaderBox = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
		t.LogoText = lipgloss.NewStyle().Bold(true)
		t.SubHeaderText = lipgloss.NewStyle()
		t.CardBox = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
		t.CardActive = lipgloss.NewStyle().Border(lipgloss.ThickBorder()).Padding(0, 1)
		t.StatusBar = lipgloss.NewStyle().Border(lipgloss.NormalBorder(), true, false, false, false)

		t.FindingRowNormal = lipgloss.NewStyle()
		t.FindingRowSelected = lipgloss.NewStyle().Bold(true)
		t.FindingTimestamp = lipgloss.NewStyle()
		t.FindingModule = lipgloss.NewStyle()
		t.FindingPath = lipgloss.NewStyle()
		t.FindingReason = lipgloss.NewStyle()

		t.ModalBox = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(1, 2)
		t.ModalHeader = lipgloss.NewStyle().Bold(true)
		t.ModalFieldKey = lipgloss.NewStyle().Bold(true)
		t.ModalFieldVal = lipgloss.NewStyle()

		t.VerdictClean = lipgloss.NewStyle().Bold(true).Border(lipgloss.RoundedBorder()).Padding(1, 2)
		t.VerdictSuspicious = lipgloss.NewStyle().Bold(true).Border(lipgloss.RoundedBorder()).Padding(1, 2)
		t.VerdictCompromised = lipgloss.NewStyle().Bold(true).Border(lipgloss.RoundedBorder()).Padding(1, 2)

		t.BadgeInfo = lipgloss.NewStyle().Bold(true)
		t.BadgeNotice = lipgloss.NewStyle().Bold(true)
		t.BadgeWarning = lipgloss.NewStyle().Bold(true)
		t.BadgeAlert = lipgloss.NewStyle().Bold(true)
		return t
	}

	// Luxurious Dark Palette with rounded borders
	t.AppContainer = lipgloss.NewStyle().
		Background(ColorObsidian).
		Padding(0, 1)

	t.HeaderBox = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorBorder).
		Background(ColorSurface).
		Padding(0, 1)

	t.LogoText = lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorCyan)

	t.SubHeaderText = lipgloss.NewStyle().
		Foreground(ColorTextMute)

	t.CardBox = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorBorder).
		Background(ColorSurface).
		Padding(0, 1)

	t.CardActive = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorBorderLit).
		Background(ColorSurface).
		Padding(0, 1)

	t.StatusBar = lipgloss.NewStyle().
		Foreground(ColorTextMute).
		Border(lipgloss.NormalBorder(), true, false, false, false).
		BorderForeground(ColorBorder)

	t.FindingRowNormal = lipgloss.NewStyle().
		Foreground(ColorTextPrim)

	t.FindingRowSelected = lipgloss.NewStyle().
		Foreground(ColorTextPrim).
		Background(lipgloss.Color("#21262D")).
		Bold(true)

	t.FindingTimestamp = lipgloss.NewStyle().
		Foreground(ColorTextMute)

	t.FindingModule = lipgloss.NewStyle().
		Foreground(ColorCyan).
		Bold(true)

	t.FindingPath = lipgloss.NewStyle().
		Foreground(ColorTextPrim)

	t.FindingReason = lipgloss.NewStyle().
		Foreground(ColorTextMute)

	t.ModalBox = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorCyan).
		Background(ColorSurface).
		Padding(1, 2)

	t.ModalHeader = lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorTextPrim)

	t.ModalFieldKey = lipgloss.NewStyle().
		Foreground(ColorTextMute).
		Bold(true)

	t.ModalFieldVal = lipgloss.NewStyle().
		Foreground(ColorTextPrim)

	t.VerdictClean = lipgloss.NewStyle().
		Bold(true).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorNotice).
		Foreground(ColorNotice).
		Padding(1, 2)

	t.VerdictSuspicious = lipgloss.NewStyle().
		Bold(true).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorWarning).
		Foreground(ColorWarning).
		Padding(1, 2)

	t.VerdictCompromised = lipgloss.NewStyle().
		Bold(true).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorAlert).
		Foreground(ColorAlert).
		Padding(1, 2)

	t.BadgeInfo = lipgloss.NewStyle().
		Foreground(ColorInfo).
		Bold(true)

	t.BadgeNotice = lipgloss.NewStyle().
		Foreground(ColorNotice).
		Bold(true)

	t.BadgeWarning = lipgloss.NewStyle().
		Foreground(ColorWarning).
		Bold(true)

	t.BadgeAlert = lipgloss.NewStyle().
		Foreground(ColorAlert).
		Bold(true)

	return t
}

// SeverityBadge renders a styled badge with brackets for the given severity.
func (t *Theme) SeverityBadge(sev report.Severity) string {
	var s lipgloss.Style
	var label string

	switch sev {
	case report.SeverityAlert:
		s = t.BadgeAlert
		label = "ALERT"
	case report.SeverityWarning:
		s = t.BadgeWarning
		label = "WARN "
	case report.SeverityNotice:
		s = t.BadgeNotice
		label = "NOTE "
	case report.SeverityInfo:
		s = t.BadgeInfo
		label = "INFO "
	default:
		s = t.BadgeInfo
		label = string(sev)
	}

	return s.Render(fmt.Sprintf("[%s]", label))
}

// SeverityStyle returns the appropriate styling for a given severity.
func (t *Theme) SeverityStyle(sev report.Severity) lipgloss.Style {
	switch sev {
	case report.SeverityAlert:
		return t.BadgeAlert
	case report.SeverityWarning:
		return t.BadgeWarning
	case report.SeverityNotice:
		return t.BadgeNotice
	default:
		return t.BadgeInfo
	}
}

// CleanANSI removes ANSI escape sequences when plain output is needed.
func CleanANSI(s string) string {
	return strings.ReplaceAll(s, "\x1b", "")
}
