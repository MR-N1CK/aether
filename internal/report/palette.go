package report

// Canonical severity and verdict palette — the single source of truth for
// every output surface (TUI theme, plain ANSI cards, HTML report). Before
// this registry existed the surfaces drifted: sky-cyan meant INFO in the
// TUI, SAFE in plain cards, and NOTICE in the HTML donut, and three
// different reds, ambers, and greens were in concurrent use. Surfaces must
// consume these tokens; introducing a raw severity hex anywhere else is a
// regression.
const (
	// Primary severity band colors.
	PaletteAlertHex   = "#F43F5E" // rose     — ALERT / MALICIOUS
	PaletteWarningHex = "#FBBF24" // amber    — WARNING / SUSPICIOUS
	PaletteNoticeHex  = "#38BDF8" // sky      — NOTICE (elevated informational)
	PaletteInfoHex    = "#94A3B8" // slate    — INFO / baseline observations
	PaletteSafeHex    = "#34D399" // mint     — SAFE / verified clean

	// Dimmed background variants for badges and fills where white-on-color
	// text needs extra contrast. Hue-locked to their primary counterparts.
	PaletteAlertDimHex   = "#E11D48"
	PaletteWarningDimHex = "#D97706"
	PaletteNoticeDimHex  = "#0284C7"
	PaletteSafeDimHex    = "#059669"
	PaletteInfoDimHex    = "#475569"
)

// SeverityHex maps a severity to its canonical palette color.
func SeverityHex(s Severity) string {
	switch s {
	case SeverityCritical, SeverityAlert, SeverityHigh:
		return PaletteAlertHex
	case SeverityWarning, SeverityMedium:
		return PaletteWarningHex
	case SeverityNotice, SeverityLow:
		return PaletteNoticeHex
	default:
		return PaletteInfoHex
	}
}

// SeverityDimHex maps a severity to its canonical dimmed background color.
func SeverityDimHex(s Severity) string {
	switch s {
	case SeverityCritical, SeverityAlert, SeverityHigh:
		return PaletteAlertDimHex
	case SeverityWarning, SeverityMedium:
		return PaletteWarningDimHex
	case SeverityNotice, SeverityLow:
		return PaletteNoticeDimHex
	default:
		return PaletteInfoDimHex
	}
}

// VerdictHex maps a verdict to its canonical palette color.
func VerdictHex(v Verdict) string {
	switch v {
	case VerdictMalicious:
		return PaletteAlertHex
	case VerdictSuspicious:
		return PaletteWarningHex
	case VerdictSafe:
		return PaletteSafeHex
	default:
		return PaletteInfoHex
	}
}
