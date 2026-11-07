package plain

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"aether/internal/realworld"
	"aether/internal/report"
	"aether/internal/ui/theme"
)

// RenderFindingCard renders a finding as a structured, explainable security card.
func RenderFindingCard(w io.Writer, f report.Finding, th *theme.Theme) {
	if th == nil {
		th = theme.NewTheme(theme.DetectNoColor())
	}

	report.PopulateFindingDetails(&f)

	sev := strings.ToUpper(string(f.Severity))
	conf := string(f.Confidence)
	if conf == "" {
		conf = "MEDIUM"
	}
	verdict := string(f.Verdict)
	if verdict == "" {
		verdict = "SUSPICIOUS"
	}

	pathVal := f.Path
	if f.LineNumber > 0 {
		pathVal = fmt.Sprintf("%s:%d", f.Path, f.LineNumber)
	}

	if th.NoColor {
		cardWidth := ContentWidth(w, 75)
		if cardWidth > MaxCardWidth {
			cardWidth = MaxCardWidth
		}
		if cardWidth < MinUsableWidth {
			cardWidth = MinUsableWidth
		}
		cellWidth := cardWidth - 19 // borders(2) + label(14: "Corroboration:") + separators(2)
		hr := "+" + strings.Repeat("-", cardWidth-2) + "+"
		row := func(label, value string) {
			for i, l := range WrapWords(value, cellWidth) {
				lbl := strings.Repeat(" ", 14)
				if i == 0 {
					lbl = fmt.Sprintf("%-14s", label)
				}
				fmt.Fprintf(w, "| %s %-*s |\n", lbl, cellWidth, l)
			}
		}

		fmt.Fprintf(w, "%s\n", hr)
		titleLines := WrapWords(f.Title, cardWidth-27)
		fmt.Fprintf(w, "| [%-7s │ %-10s] %-*s |\n", sev, verdict, cardWidth-27, titleLines[0])
		for _, l := range titleLines[1:] {
			fmt.Fprintf(w, "| %-22s %-*s |\n", "", cardWidth-27, l)
		}
		// Path row with an OSC 8 hyperlink on the first wrapped line; padding
		// is ANSI-aware so the escape bytes never widen the card.
		linkPath := osc8Enabled(w)
		for i, l := range WrapWords(pathVal, cellWidth) {
			lbl := strings.Repeat(" ", 14)
			if i == 0 {
				lbl = fmt.Sprintf("%-14s", "Path:")
				if linkPath {
					l = osc8Link(f.Path, l)
				}
			}
			fmt.Fprintf(w, "| %s %s |\n", lbl, padCell(l, cellWidth))
		}
		if f.RuleName != "" {
			row("Rule:", f.RuleName)
		}
		if cardWidth >= 75 {
			extra := cardWidth - 75
			modW, confW := 20+extra/2, 25+extra-extra/2
			fmt.Fprintf(w, "| Module:     %-*s  Confidence: %-*s |\n", modW, f.Module, confW, conf)
		} else {
			row("Module:", f.Module)
			row("Confidence:", conf)
		}
		if f.ConfidenceRationale != "" {
			row("Rationale:", f.ConfidenceRationale)
		}
		if len(f.MITRE) > 0 {
			var mitreTags []string
			for _, m := range f.MITRE {
				mitreTags = append(mitreTags, fmt.Sprintf("%s (%s)", m.Technique, m.TechniqueName))
			}
			row("MITRE:", strings.Join(mitreTags, ", "))
		}
		if f.Why != "" {
			row("Why:", f.Why)
		}
		if f.Evidence != "" {
			row("Evidence:", f.Evidence)
		}
		if len(f.Remediation) > 0 {
			row("Action:", f.Remediation[0])
		}
		fmt.Fprintf(w, "%s\n\n", hr)
		return
	}

	// Dynamic Color based on severity / verdict
	var borderColor lipgloss.Color
	var badgeBg lipgloss.Color
	var badgeFg lipgloss.Color = lipgloss.Color("#FFFFFF")

	// Canonical palette from internal/report/palette.go — sky means NOTICE,
	// mint means SAFE, on every surface.
	switch f.Verdict {
	case report.VerdictMalicious:
		borderColor = lipgloss.Color(report.VerdictHex(f.Verdict))
		badgeBg = lipgloss.Color(report.PaletteAlertDimHex)
	case report.VerdictSuspicious:
		borderColor = lipgloss.Color(report.VerdictHex(f.Verdict))
		badgeBg = lipgloss.Color(report.PaletteWarningDimHex)
	case report.VerdictSafe:
		borderColor = lipgloss.Color(report.VerdictHex(f.Verdict))
		badgeBg = lipgloss.Color(report.PaletteSafeDimHex)
	case report.VerdictUnknown:
		borderColor = lipgloss.Color(report.VerdictHex(f.Verdict))
		badgeBg = lipgloss.Color(report.PaletteInfoDimHex)
	default:
		switch f.Severity {
		case report.SeverityCritical, report.SeverityAlert:
			borderColor = lipgloss.Color(report.SeverityHex(f.Severity))
			badgeBg = lipgloss.Color(report.SeverityDimHex(f.Severity))
		case report.SeverityHigh, report.SeverityWarning:
			borderColor = lipgloss.Color(report.SeverityHex(f.Severity))
			badgeBg = lipgloss.Color(report.SeverityDimHex(f.Severity))
		case report.SeverityMedium, report.SeverityNotice:
			borderColor = lipgloss.Color(report.SeverityHex(f.Severity))
			badgeBg = lipgloss.Color(report.SeverityDimHex(f.Severity))
		default:
			borderColor = lipgloss.Color(report.PaletteInfoDimHex)
			badgeBg = lipgloss.Color(report.PaletteInfoDimHex)
		}
	}

	badge := lipgloss.NewStyle().
		Background(badgeBg).
		Foreground(badgeFg).
		Bold(true).
		Padding(0, 1).
		Render(fmt.Sprintf("%s │ %s", sev, verdict))

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#E6EDF7"))

	keyStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#94A3B8")).
		Width(12)

	valStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#C9D6E8"))

	var lines []string
	// Value-column wrapping keeps every line inside the terminal so the
	// lipgloss border hugs a rectangular block instead of a runaway string.
	cardContentW := ContentWidth(w, DefaultContentWidth) - 6 // border glyphs + Padding(0,2)
	valueW := cardContentW - 13                              // key column (12) + separator space
	if valueW < 16 {
		valueW = 16
	}
	addKeyValue := func(label, value string, render func(string) string) {
		if value == "" {
			return
		}
		wrapped := WrapWords(value, valueW)
		lines = append(lines, fmt.Sprintf("%s %s", keyStyle.Render(label), render(wrapped[0])))
		for _, cont := range wrapped[1:] {
			lines = append(lines, fmt.Sprintf("%s %s", keyStyle.Render(""), render(cont)))
		}
	}

	titleW := cardContentW - lipgloss.Width(badge) - 2
	if titleW < 8 {
		titleW = 8
	}
	titleLines := WrapWords(f.Title, titleW)
	lines = append(lines, fmt.Sprintf("%s  %s", badge, titleStyle.Render(titleLines[0])))
	for _, l := range titleLines[1:] {
		lines = append(lines, fmt.Sprintf("%s  %s", strings.Repeat(" ", lipgloss.Width(badge)-1), titleStyle.Render(l)))
	}
	lines = append(lines, "")

	unwrap := func(s string) string { return s }
	wrapRender := func(render func(...string) string) func(string) string {
		return func(s string) string { return render(s) }
	}
	// Path value gets an OSC 8 hyperlink on its first wrapped line; lipgloss
	// width is ANSI-aware so borders still hug the card exactly.
	pathRender := unwrap
	if osc8Enabled(w) {
		first := true
		pathRender = func(s string) string {
			if first {
				first = false
				return osc8Link(f.Path, s)
			}
			return s
		}
	}
	addKeyValue("Path:", pathVal, pathRender)
	if f.RuleName != "" {
		addKeyValue("Rule:", f.RuleName, unwrap)
	}

	metaRow := fmt.Sprintf("%s %s  │  %s %s",
		keyStyle.Render("Module:"), valStyle.Render(f.Module),
		keyStyle.Render("Confidence:"), valStyle.Render(conf),
	)
	lines = append(lines, metaRow)

	addKeyValue("Rationale:", f.ConfidenceRationale, wrapRender(valStyle.Render))

	if f.EvidenceRecord != nil && len(f.EvidenceRecord.ContributingDetectors) > 0 {
		addKeyValue("Corroboration:", strings.Join(f.EvidenceRecord.ContributingDetectors, ", "), unwrap)
	}

	if len(f.MITRE) > 0 {
		var mitreParts []string
		for _, m := range f.MITRE {
			mitreParts = append(mitreParts, fmt.Sprintf("[%s %s]", m.Technique, m.TechniqueName))
		}
		mitreVal := strings.Join(mitreParts, " ")
		mitreStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#A78BFA"))
		addKeyValue("MITRE:", mitreVal, wrapRender(mitreStyle.Render))
	}

	addKeyValue("Why:", f.Why, wrapRender(valStyle.Render))

	if f.Evidence != "" {
		evStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FDE047")).
			Background(lipgloss.Color("#24334F")).
			Padding(0, 1)
		evWrapped := WrapWords(f.Evidence, valueW-2)
		lines = append(lines, fmt.Sprintf("%s %s", keyStyle.Render("Evidence:"), evStyle.Render(evWrapped[0])))
		for _, cont := range evWrapped[1:] {
			lines = append(lines, fmt.Sprintf("%s %s", keyStyle.Render(""), evStyle.Render(cont)))
		}
	}

	if len(f.Remediation) > 0 {
		remStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#4ADE80"))
		addKeyValue("Action:", f.Remediation[0], wrapRender(remStyle.Render))
	}

	card := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(borderColor).
		Padding(0, 2).
		MarginBottom(1).
		Render(strings.Join(lines, "\n"))

	fmt.Fprintln(w, card)
}

// RenderExecutiveAssessmentCard renders a dedicated, formatted executive posture assessment card.
func RenderExecutiveAssessmentCard(w io.Writer, ass realworld.ComprehensiveSystemAssessment, bd realworld.DurationBreakdown, th *theme.Theme) {
	if th == nil {
		th = theme.NewTheme(theme.DetectNoColor())
	}

	if th.NoColor {
		cardWidth := ContentWidth(w, 75)
		if cardWidth > MaxCardWidth {
			cardWidth = MaxCardWidth
		}
		if cardWidth < MinUsableWidth {
			cardWidth = MinUsableWidth
		}
		cellWidth := cardWidth - 17
		hr := strings.Repeat("=", cardWidth-2)
		hrFine := strings.Repeat("-", cardWidth-2)
		row := func(label, value string) {
			for i, l := range WrapWords(value, cellWidth) {
				lbl := strings.Repeat(" ", 12)
				if i == 0 {
					lbl = fmt.Sprintf("%-12s", label)
				}
				fmt.Fprintf(w, "| %s %-*s |\n", lbl, cellWidth, l)
			}
		}

		fmt.Fprintf(w, "+%s+\n", hr)
		fmt.Fprintf(w, "|%-*s|\n", cardWidth-2, "                   EXECUTIVE SECURITY POSTURE ASSESSMENT ")
		fmt.Fprintf(w, "+%s+\n", hr)
		row("Posture:", string(ass.Posture))
		row("Summary:", ass.SummaryRationale)
		row("Findings:", fmt.Sprintf("%d Alerts, %d Warnings, %d Notices, %d Infos", ass.AlertsCount, ass.WarningsCount, ass.NoticesCount, ass.InfosCount))
		row("Duration:", bd.Total.Round(time.Millisecond).String())
		if len(ass.NextActions) > 0 {
			fmt.Fprintf(w, "+%s+\n", hrFine)
			fmt.Fprintf(w, "|%-*s|\n", cardWidth-2, " Prioritized Action Recommendations ")
			for _, act := range ass.NextActions {
				row("", fmt.Sprintf("[P%d] %s -> %s", act.Priority, act.Title, act.Command))
			}
		}
		fmt.Fprintf(w, "+%s+\n\n", hr)
		return
	}

	var color lipgloss.Color
	switch ass.Posture {
	case realworld.PostureHighRisk:
		color = lipgloss.Color("#EF4444")
	case realworld.PostureAttentionRequired:
		color = lipgloss.Color("#F59E0B")
	case realworld.PostureLimitedVisibility:
		color = lipgloss.Color("#22D3EE")
	default:
		color = lipgloss.Color("#10B981")
	}

	badge := lipgloss.NewStyle().
		Background(color).
		Foreground(lipgloss.Color("#FFFFFF")).
		Bold(true).
		Padding(0, 2).
		Render(fmt.Sprintf("POSTURE: %s", ass.Posture))

	keyStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#94A3B8")).Width(16)
	valStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#E6EDF7"))

	var lines []string
	lines = append(lines, badge)
	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("%s %s", keyStyle.Render("Summary:"), valStyle.Render(ass.SummaryRationale)))
	lines = append(lines, fmt.Sprintf("%s %d alerts, %d warnings, %d notices, %d infos (%d unknowns)",
		keyStyle.Render("Findings:"), ass.AlertsCount, ass.WarningsCount, ass.NoticesCount, ass.InfosCount, ass.UnknownsCount))
	lines = append(lines, fmt.Sprintf("%s %s (Walk: %s, Hash: %s, Proc: %s)",
		keyStyle.Render("Timing:"),
		bd.Total.Round(time.Millisecond),
		bd.FilesystemWalk.Round(time.Millisecond),
		bd.Hashing.Round(time.Millisecond),
		bd.Process.Round(time.Millisecond),
	))

	if len(ass.NextActions) > 0 {
		lines = append(lines, "")
		lines = append(lines, lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#4ADE80")).Render("Action Recommendations:"))
		for _, act := range ass.NextActions {
			pTag := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FBBF24")).Render(fmt.Sprintf("[P%d]", act.Priority))
			cmdTag := lipgloss.NewStyle().Foreground(lipgloss.Color("#22D3EE")).Render(act.Command)
			lines = append(lines, fmt.Sprintf("  • %s %-30s -> %s", pTag, act.Title, cmdTag))
		}
	}

	card := lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(color).
		Padding(1, 2).
		MarginBottom(1).
		Render(strings.Join(lines, "\n"))

	fmt.Fprintln(w, card)
}
