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

	TierCompact   = 84  // < 84 cols: compact single-column layout
	TierStandard  = 120 // 84 - 120 cols: balanced standard layout
	TierWide      = 160 // 120 - 160 cols: wide multi-column layout
	TierUltraWide = 200 // > 160 cols: high-density flight deck
)

// Geometric Unicode architectural glyphs (Zero-Emoji precision standard)
const (
	GlyphBrand       = "◈"
	GlyphSelected    = "▶"
	GlyphUnselected  = " "
	GlyphRunning     = "◈"
	GlyphCheck       = "✔"
	GlyphCross       = "✖"
	GlyphAlert       = "▲"
	GlyphWarn        = "◆"
	GlyphNotice      = "◇"
	GlyphClean       = "■"
	GlyphActiveRail  = "▌"
	GlyphKernel      = "⏣"
	GlyphNetwork     = "⬡"
	GlyphProcess     = "⚙"
	GlyphPersistence = "⚓"
	GlyphFilesystem  = "▤"
)

// SubBlocks defines 1/8th fractional vertical block runes for smooth gradient rendering.
var SubBlocks = []rune{' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉', '█'}

// ASCIIBorder defines standard 7-bit ASCII borders for serial consoles and minimal terminals.
var ASCIIBorder = lipgloss.Border{
	Top:         "-",
	Bottom:      "-",
	Left:        "|",
	Right:       "|",
	TopLeft:     "+",
	TopRight:    "+",
	BottomLeft:  "+",
	BottomRight: "+",
}

// Palette definitions - Master-tier Obsidian Studio 4-Tier Elevation Ladder
var (
	ColorObsidian   = lipgloss.Color("#05070B") // Deepest void obsidian (tier 0 root container)
	ColorVoid       = lipgloss.Color("#05070B") // Tier 0: Root void canvas
	ColorSurface    = lipgloss.Color("#0A0E15") // Tier 1: Panels and standard card background
	ColorRaised     = lipgloss.Color("#10151F") // Tier 2: Focused panels, headers, floating cards
	ColorOverlay    = lipgloss.Color("#161C27") // Tier 3: Modals, active selections, dropdowns
	ColorBorder     = lipgloss.Color("#1E293B") // Subtle slate hairline border
	ColorBorderLit  = lipgloss.Color("#38BDF8") // Focused sky cyan border & luminous rail
	ColorActiveRail = lipgloss.Color("#38BDF8") // Luminous active pane rail
	ColorTextPrim   = lipgloss.Color("#F8FAFC") // Crisp platinum white text
	ColorTextSec    = lipgloss.Color("#E2E8F0") // Soft titanium slate text
	ColorTextMute   = lipgloss.Color("#8B9BB4") // Soft slate gray (WCAG AA on obsidian)
	ColorAccent     = lipgloss.Color("#0284C7") // Deep Sky Cyan / Steel
	ColorIndigo     = lipgloss.Color("#6366F1") // Electric Indigo
	ColorCyan       = lipgloss.Color("#38BDF8") // Telemetry cyan

	// Executive severity colors - restrained, distinct, high-contrast.
	// Canonical tokens live in internal/report/palette.go and are shared by
	// the TUI, plain ANSI, and HTML surfaces: sky = NOTICE, mint = SAFE,
	// slate = INFO.
	ColorInfo    = lipgloss.Color(report.PaletteInfoHex)    // Slate
	ColorNotice  = lipgloss.Color(report.PaletteNoticeHex)  // Sky Cyan
	ColorSafe    = lipgloss.Color(report.PaletteSafeHex)    // Mint Emerald
	ColorWarning = lipgloss.Color(report.PaletteWarningHex) // Warm Amber
	ColorAlert   = lipgloss.Color(report.PaletteAlertHex)   // Vivid Rose Crimson
)

// Theme encapsulates styling configurations respecting terminal capabilities and NO_COLOR.
type Theme struct {
	NoColor bool
	ASCII   bool

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
	KeyCap           lipgloss.Style
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

	// Flight Deck & Inspector styles
	FlightDeckLeftPane  lipgloss.Style
	FlightDeckRightPane lipgloss.Style
	InspectorBox        lipgloss.Style
	InspectorTitle      lipgloss.Style
	InspectorTarget     lipgloss.Style
	InspectorHash       lipgloss.Style
	InspectorCmd        lipgloss.Style
	ModuleRowRunning    lipgloss.Style
	ModuleRowDone       lipgloss.Style
	ModuleRowPending    lipgloss.Style
	TabBadgeActive      lipgloss.Style
	TabBadgeInactive    lipgloss.Style
	ActiveRail          lipgloss.Style
}

// DetectNoColor returns true if NO_COLOR environment variable is set per no-color.org.
func DetectNoColor() bool {
	val, ok := os.LookupEnv("NO_COLOR")
	return ok && val != ""
}

// NewTheme creates a Theme instance customized for color, monochrome, and ASCII terminals.
func NewTheme(noColor bool, ascii ...bool) *Theme {
	isASCII := len(ascii) > 0 && ascii[0]
	t := &Theme{NoColor: noColor, ASCII: isASCII}

	border := lipgloss.RoundedBorder()
	thickBorder := lipgloss.ThickBorder()
	if isASCII {
		border = ASCIIBorder
		thickBorder = ASCIIBorder
	}

	if noColor {
		// Monochrome styles: no background/foreground color escapes
		t.AppContainer = lipgloss.NewStyle().Padding(0, 1)
		t.HeaderBox = lipgloss.NewStyle().Border(border).Padding(0, 1)
		t.LogoText = lipgloss.NewStyle().Bold(true)
		t.SubHeaderText = lipgloss.NewStyle()
		t.CardBox = lipgloss.NewStyle().Border(border).Padding(1, 1)
		t.CardActive = lipgloss.NewStyle().Border(thickBorder).Padding(0, 1)
		t.StatusBar = lipgloss.NewStyle().Border(lipgloss.NormalBorder(), true, false, false, false)

		t.FindingRowNormal = lipgloss.NewStyle()
		t.FindingRowSelected = lipgloss.NewStyle().Bold(true)
		t.FindingTimestamp = lipgloss.NewStyle()
		t.FindingModule = lipgloss.NewStyle()
		t.FindingPath = lipgloss.NewStyle()
		t.FindingReason = lipgloss.NewStyle()

		t.ModalBox = lipgloss.NewStyle().Border(border).Padding(1, 2)
		t.ModalHeader = lipgloss.NewStyle().Bold(true)
		t.ModalFieldKey = lipgloss.NewStyle().Bold(true)
		t.ModalFieldVal = lipgloss.NewStyle()

		t.VerdictClean = lipgloss.NewStyle().Bold(true).Border(border).Padding(1, 2)
		t.VerdictSuspicious = lipgloss.NewStyle().Bold(true).Border(border).Padding(1, 2)
		t.VerdictCompromised = lipgloss.NewStyle().Bold(true).Border(border).Padding(1, 2)

		t.BadgeInfo = lipgloss.NewStyle().Bold(true)
		t.BadgeNotice = lipgloss.NewStyle().Bold(true)
		t.BadgeWarning = lipgloss.NewStyle().Bold(true)
		t.BadgeAlert = lipgloss.NewStyle().Bold(true)

		t.BrandBannerBox = lipgloss.NewStyle().Border(border).Padding(0, 1)
		t.BrandTitle = lipgloss.NewStyle().Bold(true)
		t.BrandTagline = lipgloss.NewStyle()
		t.StatValueSafe = lipgloss.NewStyle().Bold(true)
		t.StatValueNotice = lipgloss.NewStyle().Bold(true)
		t.StatValueWarn = lipgloss.NewStyle().Bold(true)
		t.StatValueAlert = lipgloss.NewStyle().Bold(true)
		t.KeyHint = lipgloss.NewStyle().Bold(true)
		t.KeyCap = lipgloss.NewStyle().Bold(true).Padding(0, 1)
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
		t.FlightDeckLeftPane = lipgloss.NewStyle().Border(border).Padding(1, 2)
		t.FlightDeckRightPane = lipgloss.NewStyle().Border(border).Padding(1, 2)
		t.InspectorBox = lipgloss.NewStyle().Border(border).Padding(1, 2)
		t.InspectorTitle = lipgloss.NewStyle().Bold(true)
		t.InspectorTarget = lipgloss.NewStyle().Bold(true)
		t.InspectorHash = lipgloss.NewStyle()
		t.InspectorCmd = lipgloss.NewStyle().Bold(true)
		t.ModuleRowRunning = lipgloss.NewStyle().Bold(true)
		t.ModuleRowDone = lipgloss.NewStyle()
		t.ModuleRowPending = lipgloss.NewStyle()
		t.TabBadgeActive = lipgloss.NewStyle().Bold(true)
		t.TabBadgeInactive = lipgloss.NewStyle()
		t.ActiveRail = lipgloss.NewStyle().Bold(true)
		return t
	}

	// Luxurious Dark Palette with rounded borders & luminous accents
	t.AppContainer = lipgloss.NewStyle().
		Background(ColorObsidian).
		Padding(0, 1)

	t.BrandBannerBox = lipgloss.NewStyle().
		Border(border).
		BorderForeground(ColorBorder).
		Background(ColorSurface).
		Padding(0, 1)

	t.BrandTitle = lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorTextPrim)

	t.BrandTagline = lipgloss.NewStyle().
		Foreground(ColorCyan).
		Bold(true)

	t.HeaderBox = lipgloss.NewStyle().
		Border(border).
		BorderForeground(ColorBorder).
		Background(ColorSurface).
		Padding(0, 1)

	t.LogoText = lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorCyan)

	t.SubHeaderText = lipgloss.NewStyle().
		Foreground(ColorTextMute)

	t.CardBox = lipgloss.NewStyle().
		Border(border).
		BorderForeground(ColorBorder).
		Background(ColorSurface).
		Padding(0, 1)

	t.ActiveRail = lipgloss.NewStyle().
		Foreground(ColorActiveRail).
		Bold(true)

	t.CardActive = lipgloss.NewStyle().
		Border(border).
		BorderForeground(ColorBorderLit).
		Background(ColorRaised).
		Padding(0, 1)

	t.StatusBar = lipgloss.NewStyle().
		Foreground(ColorTextMute).
		Border(lipgloss.NormalBorder(), true, false, false, false).
		BorderForeground(ColorBorder)

	t.FindingRowNormal = lipgloss.NewStyle().
		Foreground(ColorTextSec)

	t.FindingRowSelected = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(ColorRaised).
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
		Border(border).
		BorderForeground(ColorBorderLit).
		Background(ColorOverlay).
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
		Border(border).
		BorderForeground(ColorNotice).
		Foreground(ColorNotice).
		Background(lipgloss.Color("#064E3B")).
		Padding(1, 2)

	t.VerdictSuspicious = lipgloss.NewStyle().
		Bold(true).
		Border(border).
		BorderForeground(ColorWarning).
		Foreground(ColorWarning).
		Background(lipgloss.Color("#451A03")).
		Padding(1, 2)

	t.VerdictCompromised = lipgloss.NewStyle().
		Bold(true).
		Border(border).
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

	// KeyCap: keycap chip for primary footers — raised overlay surface,
	// cyan ink, hairline border. Reads as a physical key, not text.
	t.KeyCap = lipgloss.NewStyle().
		Foreground(ColorCyan).
		Background(ColorOverlay).
		Border(lipgloss.NormalBorder(), false, true, false, true).
		BorderForeground(ColorBorder).
		Padding(0, 1).
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
		Border(border).
		BorderForeground(ColorBorderLit).
		Padding(0, 2)

	t.CommandPalette = lipgloss.NewStyle().
		Border(border).
		BorderForeground(ColorBorderLit).
		Background(ColorOverlay).
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

	t.FlightDeckLeftPane = lipgloss.NewStyle().
		Border(lipgloss.NormalBorder(), false, true, false, false).
		BorderForeground(ColorBorder).
		Padding(1, 2)

	t.FlightDeckRightPane = lipgloss.NewStyle().
		Padding(1, 2)

	t.InspectorBox = lipgloss.NewStyle().
		Border(border).
		BorderForeground(ColorBorderLit).
		Background(ColorRaised).
		Padding(1, 2)

	t.InspectorTitle = lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorCyan)

	t.InspectorTarget = lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorTextPrim)

	t.InspectorHash = lipgloss.NewStyle().
		Foreground(ColorTextMute)

	t.InspectorCmd = lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorNotice).
		Background(lipgloss.Color("#064E3B")).
		Padding(0, 1)

	t.ModuleRowRunning = lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorCyan)

	t.ModuleRowDone = lipgloss.NewStyle().
		Foreground(ColorNotice)

	t.ModuleRowPending = lipgloss.NewStyle().
		Foreground(ColorTextMute)

	t.TabBadgeActive = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(ColorAccent).
		Padding(0, 1)

	t.TabBadgeInactive = lipgloss.NewStyle().
		Foreground(ColorTextMute).
		Background(lipgloss.Color("#1E293B")).
		Padding(0, 1)

	return t
}

// RenderFractionalBar renders a high-precision progress bar using Unicode eighth-blocks.
func RenderFractionalBar(width int, ratio float64, filledStyle, emptyStyle lipgloss.Style, ascii bool) string {
	if width <= 0 {
		return ""
	}
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}

	if ascii {
		filled := int(ratio * float64(width))
		if filled > width {
			filled = width
		}
		empty := width - filled
		if empty < 0 {
			empty = 0
		}
		return filledStyle.Render(strings.Repeat("#", filled)) + emptyStyle.Render(strings.Repeat("-", empty))
	}

	// 8 sub-divisions per column cell
	totalSubUnits := int(ratio * float64(width) * 8.0)
	fullChars := totalSubUnits / 8
	fraction := totalSubUnits % 8

	var b strings.Builder
	if fullChars > width {
		fullChars = width
	}
	b.WriteString(filledStyle.Render(strings.Repeat("█", fullChars)))

	if fullChars < width {
		if fraction > 0 {
			subRunes := []rune{' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉'}
			b.WriteString(filledStyle.Render(string(subRunes[fraction])))
			remaining := width - fullChars - 1
			if remaining > 0 {
				b.WriteString(emptyStyle.Render(strings.Repeat("░", remaining)))
			}
		} else {
			remaining := width - fullChars
			if remaining > 0 {
				b.WriteString(emptyStyle.Render(strings.Repeat("░", remaining)))
			}
		}
	}

	return b.String()
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

// IconAlert returns the severity alert icon, falling back to [!] in ASCII mode.
func (t *Theme) IconAlert() string {
	if t.ASCII {
		return "[!]"
	}
	return "▲"
}

// IconWarn returns the severity warning icon, falling back to [*] in ASCII mode.
func (t *Theme) IconWarn() string {
	if t.ASCII {
		return "[*]"
	}
	return "◆"
}

// IconNotice returns the severity notice icon, falling back to [+] in ASCII mode.
func (t *Theme) IconNotice() string {
	if t.ASCII {
		return "[+]"
	}
	return "◇"
}

// IconInfo returns the severity info icon, falling back to [i] in ASCII mode.
func (t *Theme) IconInfo() string {
	if t.ASCII {
		return "[i]"
	}
	return "▫"
}

// IconClean returns the clean verdict icon, falling back to [OK] in ASCII mode.
func (t *Theme) IconClean() string {
	if t.ASCII {
		return "[OK]"
	}
	return "■"
}

// IconCheck returns the success checkmark icon, falling back to [+] in ASCII mode.
func (t *Theme) IconCheck() string {
	if t.ASCII {
		return "[+]"
	}
	return "✔"
}

// IconCross returns the failure cross icon, falling back to [x] in ASCII mode.
func (t *Theme) IconCross() string {
	if t.ASCII {
		return "[x]"
	}
	return "✖"
}

// IconSkip returns the skipped module icon, falling back to [-] in ASCII mode.
func (t *Theme) IconSkip() string {
	if t.ASCII {
		return "[-]"
	}
	return "⊘"
}

// IconBolt returns the YARA/engine icon, falling back to [YARA] in ASCII mode.
func (t *Theme) IconBolt() string {
	if t.ASCII {
		return "[YARA]"
	}
	return "◈"
}

// IconFile returns the file inspected icon, falling back to [FILES] in ASCII mode.
func (t *Theme) IconFile() string {
	if t.ASCII {
		return "[FILES]"
	}
	return "▤"
}

// IconTime returns the elapsed duration icon, falling back to [TIME] in ASCII mode.
func (t *Theme) IconTime() string {
	if t.ASCII {
		return "[TIME]"
	}
	return "◷"
}

// auroraRGB parses a #RRGGBB (or #RGB) hex color into float channels.
func auroraRGB(h string) (r, g, b float64) {
	h = strings.TrimPrefix(h, "#")
	if len(h) == 3 {
		h = string([]byte{h[0], h[0], h[1], h[1], h[2], h[2]})
	}
	var rr, gg, bb uint8
	fmt.Sscanf(h, "%02x%02x%02x", &rr, &gg, &bb)
	return float64(rr), float64(gg), float64(bb)
}

// auroraStops converts hex stops to float channels.
func auroraStops(hexColors []string) [][3]float64 {
	stops := make([][3]float64, len(hexColors))
	for i, hc := range hexColors {
		r, g, b := auroraRGB(hc)
		stops[i] = [3]float64{r, g, b}
	}
	return stops
}

// auroraLerp interpolates a multi-stop ramp at pos in [0,1] and returns a
// #RRGGBB string.
func auroraLerp(stops [][3]float64, pos float64) string {
	if len(stops) == 0 {
		return ""
	}
	if len(stops) == 1 || pos <= 0 {
		return fmt.Sprintf("#%02x%02x%02x", int(stops[0][0]), int(stops[0][1]), int(stops[0][2]))
	}
	if pos >= 1 {
		last := stops[len(stops)-1]
		return fmt.Sprintf("#%02x%02x%02x", int(last[0]), int(last[1]), int(last[2]))
	}
	numSegments := len(stops) - 1
	scaled := pos * float64(numSegments)
	segIndex := int(scaled)
	if segIndex >= numSegments {
		segIndex = numSegments - 1
	}
	t := scaled - float64(segIndex)
	c0 := stops[segIndex]
	c1 := stops[segIndex+1]
	return fmt.Sprintf("#%02x%02x%02x",
		int(c0[0]+t*(c1[0]-c0[0])),
		int(c0[1]+t*(c1[1]-c0[1])),
		int(c0[2]+t*(c1[2]-c0[2])))
}

// RenderGradientText applies a smooth linear RGB truecolor gradient across the runes of text.
// If the theme is monochrome or ASCII, it returns the text unmodified or styled with BrandTitle.
func (t *Theme) RenderGradientText(text string, hexColors ...string) string {
	if t.NoColor || len(hexColors) == 0 {
		return text
	}
	if len(hexColors) == 1 {
		return lipgloss.NewStyle().Foreground(lipgloss.Color(hexColors[0])).Bold(true).Render(text)
	}

	runes := []rune(text)
	totalRunes := len(runes)
	if totalRunes == 0 {
		return ""
	}
	if totalRunes == 1 {
		return lipgloss.NewStyle().Foreground(lipgloss.Color(hexColors[0])).Bold(true).Render(text)
	}

	stops := auroraStops(hexColors)

	var out strings.Builder
	for i, r := range runes {
		pos := float64(i) / float64(totalRunes-1)
		hex := auroraLerp(stops, pos)
		charStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(hex)).Bold(true)
		out.WriteString(charStyle.Render(string(r)))
	}

	return out.String()
}

// Aurora accent ramp (DESIGN.md §1): deep steel → telemetry cyan → platinum.
var AuroraRamp = []string{"#0284C7", "#38BDF8", "#F8FAFC"}

// RenderGradientBar renders a high-precision eighth-block progress bar whose
// fill columns are tinted along the given hex-color ramp — the Aurora Command
// Deck meter treatment. Falls back to the solid fractional bar under
// monochrome themes, ASCII terminals, or an empty ramp.
func (t *Theme) RenderGradientBar(width int, ratio float64, emptyStyle lipgloss.Style, hexColors ...string) string {
	if width <= 0 {
		return ""
	}
	if t.NoColor || t.ASCII || len(hexColors) == 0 {
		// Monochrome themes never emit a foreground color; ASCII/empty-ramp
		// fallbacks may keep the ramp's first color.
		filledStyle := lipgloss.NewStyle().Bold(true)
		if !t.NoColor && len(hexColors) > 0 {
			filledStyle = filledStyle.Foreground(lipgloss.Color(hexColors[0]))
		}
		return RenderFractionalBar(width, ratio, filledStyle, emptyStyle, t.ASCII)
	}
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}

	stops := auroraStops(hexColors)
	totalSubUnits := int(ratio * float64(width) * 8.0)
	fullChars := totalSubUnits / 8
	fraction := totalSubUnits % 8
	if fullChars > width {
		fullChars = width
	}

	var b strings.Builder
	for i := 0; i < fullChars; i++ {
		hex := auroraLerp(stops, float64(i)/float64(maxInt(width-1, 1)))
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(hex)).Bold(true).Render("█"))
	}
	if fullChars < width {
		if fraction > 0 {
			subRunes := []rune{' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉'}
			hex := auroraLerp(stops, float64(fullChars)/float64(maxInt(width-1, 1)))
			b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(hex)).Bold(true).Render(string(subRunes[fraction])))
			remaining := width - fullChars - 1
			if remaining > 0 {
				b.WriteString(emptyStyle.Render(strings.Repeat("░", remaining)))
			}
		} else {
			remaining := width - fullChars
			if remaining > 0 {
				b.WriteString(emptyStyle.Render(strings.Repeat("░", remaining)))
			}
		}
	}
	return b.String()
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Type scale (DESIGN.md §2): semantic text styles used instead of ad-hoc
// Bold flags. Monochrome themes keep the hierarchy through weight alone.
func (t *Theme) TextTitle() lipgloss.Style { return t.BrandTitle }
func (t *Theme) TextLg() lipgloss.Style    { return t.SectionHeader }
func (t *Theme) TextBase() lipgloss.Style  { return t.FindingRowNormal }
func (t *Theme) TextSm() lipgloss.Style    { return t.FindingTimestamp }

// RenderThreatScoreMeter renders a high-density score meter e.g. [████████░░] 85/100
// with color matched to severity threshold.
func (t *Theme) RenderThreatScoreMeter(score int, barWidth int) string {
	if barWidth <= 0 {
		barWidth = 10
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	var color lipgloss.TerminalColor
	switch {
	case score >= 85:
		color = ColorAlert
	case score >= 50:
		color = ColorWarning
	case score >= 20:
		color = ColorNotice
	default:
		color = ColorInfo
	}

	filled := (score * barWidth) / 100
	if filled == 0 && score > 0 {
		filled = 1
	}
	empty := barWidth - filled
	if empty < 0 {
		empty = 0
	}

	fillChar := "█"
	emptyChar := "░"
	if t.ASCII {
		fillChar = "#"
		emptyChar = "-"
	}

	meterBar := strings.Repeat(fillChar, filled)
	if !t.NoColor {
		meterBar = lipgloss.NewStyle().Foreground(color).Render(meterBar)
	}
	emptyBar := strings.Repeat(emptyChar, empty)
	if !t.NoColor {
		emptyBar = lipgloss.NewStyle().Foreground(ColorTextMute).Render(emptyBar)
	}

	return fmt.Sprintf("[%s%s] %d/100", meterBar, emptyBar, score)
}
