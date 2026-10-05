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

	if th.NoColor {
		fmt.Fprintf(w, "+-------------------------------------------------------------------------+\n")
		fmt.Fprintf(w, "| [%-7s │ %-10s] %-48s |\n", sev, verdict, f.Title)
		fmt.Fprintf(w, "| Path:       %-59s |\n", f.Path)
		if f.RuleName != "" {
			fmt.Fprintf(w, "| Rule:       %-59s |\n", f.RuleName)
		}
		fmt.Fprintf(w, "| Module:     %-20s  Confidence: %-25s |\n", f.Module, conf)
		if f.ConfidenceRationale != "" {
			fmt.Fprintf(w, "| Rationale:  %-59s |\n", f.ConfidenceRationale)
		}
		if len(f.MITRE) > 0 {
			var mitreTags []string
			for _, m := range f.MITRE {
				mitreTags = append(mitreTags, fmt.Sprintf("%s (%s)", m.Technique, m.TechniqueName))
			}
			fmt.Fprintf(w, "| MITRE:      %-59s |\n", strings.Join(mitreTags, ", "))
		}
		if f.Why != "" {
			fmt.Fprintf(w, "| Why:        %-59s |\n", f.Why)
		}
		if f.Evidence != "" {
			fmt.Fprintf(w, "| Evidence:   %-59s |\n", f.Evidence)
		}
		if len(f.Remediation) > 0 {
			fmt.Fprintf(w, "| Action:     %-59s |\n", f.Remediation[0])
		}
		fmt.Fprintf(w, "+-------------------------------------------------------------------------+\n\n")
		return
	}

	// Dynamic Color based on severity / verdict
	var borderColor lipgloss.Color
	var badgeBg lipgloss.Color
	var badgeFg lipgloss.Color = lipgloss.Color("#FFFFFF")

	switch f.Verdict {
	case report.VerdictMalicious:
		borderColor = lipgloss.Color("#F43F5E") // Hyper Crimson
		badgeBg = lipgloss.Color("#E11D48")
	case report.VerdictSuspicious:
		borderColor = lipgloss.Color("#FBBF24") // Amber
		badgeBg = lipgloss.Color("#D97706")
	case report.VerdictSafe:
		borderColor = lipgloss.Color("#38BDF8") // Sky Cyan
		badgeBg = lipgloss.Color("#0284C7")
	case report.VerdictUnknown:
		borderColor = lipgloss.Color("#94A3B8") // Slate
		badgeBg = lipgloss.Color("#475569")
	default:
		switch f.Severity {
		case report.SeverityCritical, report.SeverityAlert:
			borderColor = lipgloss.Color("#F43F5E")
			badgeBg = lipgloss.Color("#E11D48")
		case report.SeverityHigh, report.SeverityWarning:
			borderColor = lipgloss.Color("#FBBF24")
			badgeBg = lipgloss.Color("#D97706")
		case report.SeverityMedium, report.SeverityNotice:
			borderColor = lipgloss.Color("#38BDF8")
			badgeBg = lipgloss.Color("#0284C7")
		default:
			borderColor = lipgloss.Color("#475569")
			badgeBg = lipgloss.Color("#334155")
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
		Foreground(lipgloss.Color("#F8FAFC"))

	keyStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#94A3B8")).
		Width(12)

	valStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#E2E8F0"))

	pathVal := f.Path
	if f.LineNumber > 0 {
		pathVal = fmt.Sprintf("%s:%d", f.Path, f.LineNumber)
	}

	var lines []string
	lines = append(lines, fmt.Sprintf("%s  %s", badge, titleStyle.Render(f.Title)))
	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("%s %s", keyStyle.Render("Path:"), valStyle.Render(pathVal)))
	if f.RuleName != "" {
		lines = append(lines, fmt.Sprintf("%s %s", keyStyle.Render("Rule:"), valStyle.Render(f.RuleName)))
	}

	metaRow := fmt.Sprintf("%s %s  │  %s %s",
		keyStyle.Render("Module:"), valStyle.Render(f.Module),
		keyStyle.Render("Confidence:"), valStyle.Render(conf),
	)
	lines = append(lines, metaRow)

	if f.ConfidenceRationale != "" {
		lines = append(lines, fmt.Sprintf("%s %s", keyStyle.Render("Rationale:"), valStyle.Render(f.ConfidenceRationale)))
	}

	if f.EvidenceRecord != nil && len(f.EvidenceRecord.ContributingDetectors) > 0 {
		lines = append(lines, fmt.Sprintf("%s %s", keyStyle.Render("Corroboration:"), valStyle.Render(strings.Join(f.EvidenceRecord.ContributingDetectors, ", "))))
	}

	if len(f.MITRE) > 0 {
		var mitreParts []string
		for _, m := range f.MITRE {
			mitreParts = append(mitreParts, fmt.Sprintf("[%s %s]", m.Technique, m.TechniqueName))
		}
		lines = append(lines, fmt.Sprintf("%s %s", keyStyle.Render("MITRE:"), lipgloss.NewStyle().Foreground(lipgloss.Color("#A78BFA")).Render(strings.Join(mitreParts, " "))))
	}

	if f.Why != "" {
		lines = append(lines, fmt.Sprintf("%s %s", keyStyle.Render("Why:"), valStyle.Render(f.Why)))
	}

	if f.Evidence != "" {
		evStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FDE047")).
			Background(lipgloss.Color("#1E293B")).
			Padding(0, 1)
		lines = append(lines, fmt.Sprintf("%s %s", keyStyle.Render("Evidence:"), evStyle.Render(f.Evidence)))
	}

	if len(f.Remediation) > 0 {
		remStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#4ADE80"))
		lines = append(lines, fmt.Sprintf("%s %s", keyStyle.Render("Action:"), remStyle.Render(f.Remediation[0])))
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
		fmt.Fprintf(w, "\n+=========================================================================+\n")
		fmt.Fprintf(w, "|                   EXECUTIVE SECURITY POSTURE ASSESSMENT                 |\n")
		fmt.Fprintf(w, "+=========================================================================+\n")
		fmt.Fprintf(w, "| System Posture: %-55s |\n", ass.Posture)
		fmt.Fprintf(w, "| Summary:        %-55s |\n", ass.SummaryRationale)
		fmt.Fprintf(w, "| Findings:       %d Alerts, %d Warnings, %d Notices, %d Infos       |\n",
			ass.AlertsCount, ass.WarningsCount, ass.NoticesCount, ass.InfosCount)
		fmt.Fprintf(w, "| Duration:       %-55s |\n", bd.Total.Round(time.Millisecond))
		if len(ass.NextActions) > 0 {
			fmt.Fprintf(w, "+-------------------------------------------------------------------------+\n")
			fmt.Fprintf(w, "| Prioritized Action Recommendations:                                     |\n")
			for _, act := range ass.NextActions {
				fmt.Fprintf(w, "| [P%d] %-30s -> %-28s |\n", act.Priority, act.Title, act.Command)
			}
		}
		fmt.Fprintf(w, "+=========================================================================+\n\n")
		return
	}

	var color lipgloss.Color
	switch ass.Posture {
	case realworld.PostureHighRisk:
		color = lipgloss.Color("#EF4444")
	case realworld.PostureAttentionRequired:
		color = lipgloss.Color("#F59E0B")
	case realworld.PostureLimitedVisibility:
		color = lipgloss.Color("#38BDF8")
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
	valStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#F8FAFC"))

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
			cmdTag := lipgloss.NewStyle().Foreground(lipgloss.Color("#38BDF8")).Render(act.Command)
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
