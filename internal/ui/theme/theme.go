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

// Palette definitions - Premium Executive Studio Palette (Apple Pro / Stripe / Linear luxury clarity)
var (
	ColorObsidian  = lipgloss.Color("#0B0F17") // Deep void black
	ColorSurface   = lipgloss.Color("#161B22") // Card background
	ColorBorder    = lipgloss.Color("#334155") // Sleek titanium slate border
	ColorBorderLit = lipgloss.Color("#3B82F6") // Focused azure border
	ColorTextPrim  = lipgloss.Color("#FFFFFF") // Crisp platinum white text
	ColorTextSec   = lipgloss.Color("#F1F5F9") // Soft silver text
	ColorTextMute  = lipgloss.Color("#94A3B8") // Refined slate gray
	ColorAccent    = lipgloss.Color("#3B82F6") // Luminous Royal Azure
	ColorIndigo    = lipgloss.Color("#6366F1") // Electric Indigo
	ColorCyan      = lipgloss.Color("#0EA5E9") // Bright Sapphire Sky

	// Executive severity colors - vibrant, distinct, harmonious
	ColorInfo    = lipgloss.Color("#0EA5E9") // Sapphire Blue
	ColorNotice  = lipgloss.Color("#10B981") // Emerald Mint
	ColorWarning = lipgloss.Color("#F59E0B") // Honey Amber
	ColorAlert   = lipgloss.Color("#EF4444") // Coral Crimson
)

// Theme encapsulates styling configurations respecting terminal capabilities and NO_COLOR.
type Theme struct {
	NoColor bool

	// Layout and Card styles
	AppContainer  lipgloss.Style
	HeaderBox     lipgloss.Style
	LogoText      lipgloss.Style
	SubHeaderText lipgloss.Style
	CardBox       lipgloss.Style
	CardActive    lipgloss.Style
	StatusBar     lipgloss.Style

	// Finding list styles
	FindingRowNormal   lipgloss.Style
	FindingRowSelected lipgloss.Style
	FindingTimestamp   lipgloss.Style
	FindingModule      lipgloss.Style
	FindingPath        lipgloss.Style
	FindingReason      lipgloss.Style

	// Modal / detail styles
	ModalBox      lipgloss.Style
	ModalHeader   lipgloss.Style
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

	// Enhanced Executive Studio styles
	BrandBannerBox   lipgloss.Style
	BrandTitle       lipgloss.Style
	BrandTagline     lipgloss.Style
	StatValueSafe    lipgloss.Style
	StatValueNotice  lipgloss.Style
	StatValueWarn    lipgloss.Style
	StatValueAlert   lipgloss.Style
	KeyHint          lipgloss.Style
	KeyDesc          lipgloss.Style
	SectionHeader    lipgloss.Style
	SubSectionHeader lipgloss.Style
	TabActive        lipgloss.Style
	TabInactive      lipgloss.Style
	ToastBox         lipgloss.Style
	CommandPalette   lipgloss.Style

	// Executive Pill Badges & Table Headings
	PillAlert   lipgloss.Style
	PillWarn    lipgloss.Style
	PillNotice  lipgloss.Style
	PillInfo    lipgloss.Style
	PillNeutral lipgloss.Style
	PillKey     lipgloss.Style
	TableHead   lipgloss.Style
	Divider     lipgloss.Style
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

		t.BrandBannerBox = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
		t.BrandTitle = lipgloss.NewStyle().Bold(true)
		t.BrandTagline = lipgloss.NewStyle()
		t.StatValueSafe = lipgloss.NewStyle().Bold(true)
		t.StatValueNotice = lipgloss.NewStyle().Bold(true)
		t.StatValueWarn = lipgloss.NewStyle().Bold(true)
		t.StatValueAlert = lipgloss.NewStyle().Bold(true)
		t.KeyHint = lipgloss.NewStyle().Bold(true)
		t.KeyDesc = lipgloss.NewStyle()
		t.SectionHeader = lipgloss.NewStyle().Bold(true)
		t.SubSectionHeader = lipgloss.NewStyle().Bold(true)
		t.TabActive = lipgloss.NewStyle().Bold(true)
		t.TabInactive = lipgloss.NewStyle()
		t.ToastBox = lipgloss.NewStyle().Bold(true).Border(lipgloss.RoundedBorder()).Padding(0, 1)
		t.CommandPalette = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(1, 2)
		t.PillAlert = lipgloss.NewStyle().Bold(true)
		t.PillWarn = lipgloss.NewStyle().Bold(true)
		t.PillNotice = lipgloss.NewStyle().Bold(true)
		t.PillInfo = lipgloss.NewStyle().Bold(true)
		t.PillNeutral = lipgloss.NewStyle()
		t.PillKey = lipgloss.NewStyle().Bold(true)
		t.TableHead = lipgloss.NewStyle().Bold(true)
		t.Divider = lipgloss.NewStyle()
		return t
	}

	// Luxurious Dark Palette with rounded borders & luminous accents
	t.AppContainer = lipgloss.NewStyle().
		Background(ColorObsidian).
		Padding(0, 1)

	t.BrandBannerBox = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorAccent).
		Background(ColorSurface).
		Padding(0, 1)

	t.BrandTitle = lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorTextPrim)

	t.BrandTagline = lipgloss.NewStyle().
		Foreground(ColorCyan).
		Bold(true)

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
		Foreground(ColorTextSec)

	t.FindingRowSelected = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(lipgloss.Color("#1E3A8A")).
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
		BorderForeground(ColorAccent).
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
		Background(lipgloss.Color("#064E3B")).
		Padding(1, 2)

	t.VerdictSuspicious = lipgloss.NewStyle().
		Bold(true).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorWarning).
		Foreground(ColorWarning).
		Background(lipgloss.Color("#451A03")).
		Padding(1, 2)

	t.VerdictCompromised = lipgloss.NewStyle().
		Bold(true).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorAlert).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(lipgloss.Color("#7F1D1D")).
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

	t.StatValueSafe = lipgloss.NewStyle().
		Foreground(ColorNotice).
		Bold(true)

	t.StatValueNotice = lipgloss.NewStyle().
		Foreground(ColorNotice).
		Bold(true)

	t.StatValueWarn = lipgloss.NewStyle().
		Foreground(ColorWarning).
		Bold(true)

	t.StatValueAlert = lipgloss.NewStyle().
		Foreground(ColorAlert).
		Bold(true)

	t.KeyHint = lipgloss.NewStyle().
		Foreground(ColorCyan).
		Bold(true)

	t.KeyDesc = lipgloss.NewStyle().
		Foreground(ColorTextMute)

	t.SectionHeader = lipgloss.NewStyle().
		Foreground(ColorTextPrim).
		Bold(true)

	t.SubSectionHeader = lipgloss.NewStyle().
		Foreground(ColorCyan).
		Bold(true)

	t.TabActive = lipgloss.NewStyle().
		Bold(true).
		Background(ColorAccent).
		Foreground(ColorTextPrim).
		Padding(0, 1)

	t.TabInactive = lipgloss.NewStyle().
		Foreground(ColorTextMute).
		Background(lipgloss.Color("#1E293B")).
		Padding(0, 1)

	t.ToastBox = lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorTextPrim).
		Background(ColorAccent).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorBorderLit).
		Padding(0, 2)

	t.CommandPalette = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorBorderLit).
		Background(ColorSurface).
		Padding(1, 2)

	t.PillAlert = lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorAlert).
		Background(lipgloss.Color("#450A0A")).
		Padding(0, 1)

	t.PillWarn = lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorWarning).
		Background(lipgloss.Color("#451A03")).
		Padding(0, 1)

	t.PillNotice = lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorNotice).
		Background(lipgloss.Color("#064E3B")).
		Padding(0, 1)

	t.PillInfo = lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorInfo).
		Background(lipgloss.Color("#0C4A6E")).
		Padding(0, 1)

	t.PillNeutral = lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorTextPrim).
		Background(lipgloss.Color("#1E293B")).
		Padding(0, 1)

	t.PillKey = lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorCyan)

	t.TableHead = lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorCyan)

	t.Divider = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#334155"))

	return t
}

// SeverityBadge renders a styled badge with distinct colorblind textual markers for the given severity.
func (t *Theme) SeverityBadge(sev report.Severity) string {
	var s lipgloss.Style
	var label string

	switch sev {
	case report.SeverityAlert:
		s = t.BadgeAlert
		label = "! ALERT"
	case report.SeverityWarning:
		s = t.BadgeWarning
		label = "? WARN "
	case report.SeverityNotice:
		s = t.BadgeNotice
		label = "* NOTE "
	case report.SeverityInfo:
		s = t.BadgeInfo
		label = "i INFO "
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

// PillBadge renders a high-contrast pill badge with background and foreground colors.
func (t *Theme) PillBadge(label string, sev report.Severity) string {
	if t.NoColor {
		return fmt.Sprintf("[%s]", label)
	}

	var bg, fg lipgloss.Color
	switch sev {
	case report.SeverityAlert, report.SeverityCritical:
		bg = ColorAlert
		fg = lipgloss.Color("#FFFFFF")
	case report.SeverityWarning, report.SeverityHigh:
		bg = ColorWarning
		fg = lipgloss.Color("#000000")
	case report.SeverityNotice, report.SeverityMedium:
		bg = ColorNotice
		fg = lipgloss.Color("#000000")
	default:
		bg = ColorInfo
		fg = lipgloss.Color("#FFFFFF")
	}

	style := lipgloss.NewStyle().
		Background(bg).
		Foreground(fg).
		Bold(true).
		Padding(0, 1)

	return style.Render(label)
}

// StatusPill renders an active/inactive status indicator pill (e.g. ● ACTIVE).
func (t *Theme) StatusPill(label string, active bool) string {
	if t.NoColor {
		if active {
			return fmt.Sprintf("[● %s]", label)
		}
		return fmt.Sprintf("[○ %s]", label)
	}

	if active {
		return lipgloss.NewStyle().
			Foreground(ColorNotice).
			Bold(true).
			Render(fmt.Sprintf("● %s", label))
	}
	return lipgloss.NewStyle().
		Foreground(ColorTextMute).
		Render(fmt.Sprintf("○ %s", label))
}

// CleanANSI removes ANSI escape sequences when plain output is needed.
func CleanANSI(s string) string {
	return strings.ReplaceAll(s, "\x1b", "")
}
