package plain

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"aether/internal/events"
	"aether/internal/realworld"
	"aether/internal/ui/theme"
)

// RenderExecutiveVerdict renders a comprehensive executive risk assessment box,
// including host posture, subsystem duration breakdown, and prioritized action recommendations.
func RenderExecutiveVerdict(w io.Writer, ev events.ScanFinished, th *theme.Theme) {
	if th == nil {
		th = theme.NewTheme(theme.DetectNoColor())
	}

	// Synthesize executive system assessment and duration breakdown
	synth := realworld.NewAssessmentSynthesizer()
	ass := synth.SynthesizeFromScan(nil, ev)
	bd := realworld.FromScanFinished(ev, 0)

	// Calculate threat score and risk level
	threatScore := 0
	threatScore += ev.Alerts * 25
	threatScore += ev.Warnings * 5
	threatScore += ev.Notices * 1
	if threatScore > 100 {
		threatScore = 100
	}

	var postureTitle string
	var riskColor lipgloss.Color

	var riskLevel string
	if ev.Alerts > 0 || threatScore >= 25 {
		riskLevel = "CRITICAL"
	} else if ev.Warnings > 0 || threatScore >= 10 {
		riskLevel = "ELEVATED"
	} else if ev.Notices > 0 || threatScore >= 5 {
		riskLevel = "MODERATE"
	} else {
		riskLevel = "LOW"
	}

	switch ass.Posture {
	case realworld.PostureHighRisk:
		riskColor = lipgloss.Color("#EF4444")
		postureTitle = fmt.Sprintf("HIGH RISK — %d Active Threat Alert(s) Detected", ev.Alerts)
	case realworld.PostureAttentionRequired:
		riskColor = lipgloss.Color("#F59E0B")
		postureTitle = fmt.Sprintf("ATTENTION REQUIRED — %d Warning(s) & %d Notice(s) Detected", ev.Warnings, ev.Notices)
	case realworld.PostureLimitedVisibility:
		riskColor = lipgloss.Color("#38BDF8")
		postureTitle = "LIMITED VISIBILITY — Subsystems Uninspected Due to Permissions"
	default:
		riskColor = lipgloss.Color("#10B981")
		postureTitle = "SAFE & HEALTHY — Zero Threats or Anomalies Identified"
	}

	// Coverage calculation
	coverageState := "FULL COVERAGE"
	if ev.Partial || ass.Posture == realworld.PostureLimitedVisibility {
		coverageState = fmt.Sprintf("PARTIAL COVERAGE (%d Visibility Gap(s))", len(ass.VisibilityGaps))
	}

	// ASCII Risk Meter Bar (20 blocks)
	meterBlocks := 20
	filledBlocks := (threatScore * meterBlocks) / 100
	if filledBlocks == 0 && threatScore > 0 {
		filledBlocks = 1
	}

	barFilled := strings.Repeat("█", filledBlocks)
	barEmpty := strings.Repeat("░", meterBlocks-filledBlocks)

	if th.NoColor {
		cardWidth := ContentWidth(w, 75)
		if cardWidth > MaxCardWidth {
			cardWidth = MaxCardWidth
		}
		if cardWidth < MinUsableWidth {
			cardWidth = MinUsableWidth
		}
		cellWidth := cardWidth - 21 // borders(2) + label(16: "Modules Not Run:") + separators(2)
		hr := strings.Repeat("=", cardWidth-2)
		hrFine := strings.Repeat("-", cardWidth-2)
		row := func(label, value string) {
			for i, l := range WrapWords(value, cellWidth) {
				lbl := strings.Repeat(" ", 16)
				if i == 0 {
					lbl = fmt.Sprintf("%-16s", label+":")
				}
				fmt.Fprintf(w, "| %s %-*s |\n", lbl, cellWidth, l)
			}
		}

		fmt.Fprintf(w, "+%s+\n", hr)
		fmt.Fprintf(w, "|%-*s|\n", cardWidth-2, "                       SYSTEM EXECUTIVE RISK ASSESSMENT                  ")
		fmt.Fprintf(w, "+%s+\n", hr)
		row("Host Posture", fmt.Sprintf("[%s] %s", ass.Posture, postureTitle))
		row("Risk Level", fmt.Sprintf("%s (Score: %d/100)", riskLevel, threatScore))
		row("Rationale", ass.SummaryRationale)
		row("Coverage", coverageState)
		if len(ev.ModulesNotRun) > 0 {
			row("Modules Not Run", strings.Join(ev.ModulesNotRun, ", "))
		}
		row("Findings", fmt.Sprintf("%d Alerts, %d Warnings, %d Notices, %d Infos", ev.Alerts, ev.Warnings, ev.Notices, ev.Infos))
		row("Risk Meter", fmt.Sprintf("[%s%s] %d/100", barFilled, barEmpty, threatScore))
		row("Duration", fmt.Sprintf("%s  Coverage: %d/%d (%.1f%%)", ev.TotalDuration.Round(time.Millisecond), ev.Coverage.FilesScanned, ev.Coverage.TotalEligible(), ev.Coverage.CoveragePercentage()))
		fmt.Fprintf(w, "+%s+\n", hrFine)
		timingTitle := " Subsystem Timing Breakdown "
		if bd.Estimated {
			timingTitle = " Subsystem Timing Breakdown [ESTIMATED] "
		}
		fmt.Fprintf(w, "|%-*s|\n", cardWidth-2, timingTitle)
		row("Walk / Hash", fmt.Sprintf("%s / %s", bd.FilesystemWalk.Round(time.Millisecond), bd.Hashing.Round(time.Millisecond)))
		row("Heuristics", fmt.Sprintf("%s (YARA: %s)", bd.Heuristics.Round(time.Millisecond), bd.YARA.Round(time.Millisecond)))
		row("Proc/Net", fmt.Sprintf("%s / %s", bd.Process.Round(time.Millisecond), bd.Network.Round(time.Millisecond)))
		row("Correlation", fmt.Sprintf("total %s", bd.Total.Round(time.Millisecond)))
		if len(ass.NextActions) > 0 {
			fmt.Fprintf(w, "+%s+\n", hrFine)
			fmt.Fprintf(w, "|%-*s|\n", cardWidth-2, " Prioritized Action Recommendations ")
			for _, act := range ass.NextActions {
				row("Action", fmt.Sprintf("[P%d] %s -> %s", act.Priority, act.Title, act.Command))
			}
		}
		fmt.Fprintf(w, "+%s+\n\n", hr)
		return
	}

	// Rich Card Rendering
	titleBanner := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(riskColor).
		Padding(0, 2).
		Render(fmt.Sprintf("POSTURE: %s [%s]  (Score: %d/100)", ass.Posture, riskLevel, threatScore))

	statusStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(riskColor)

	keyStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#94A3B8")).
		Width(18)

	valStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#F8FAFC"))

	verdictContentW := ContentWidth(w, DefaultContentWidth) - 8 // border + Padding(1,2)
	verdictValW := verdictContentW - 19                         // key column (18) + space
	if verdictValW < 16 {
		verdictValW = 16
	}

	meterStyled := lipgloss.NewStyle().Foreground(riskColor).Render(barFilled) +
		lipgloss.NewStyle().Foreground(lipgloss.Color("#334155")).Render(barEmpty)

	badgeAlert := lipgloss.NewStyle().Background(lipgloss.Color("#E11D48")).Foreground(lipgloss.Color("#FFFFFF")).Bold(true).Padding(0, 1).Render(fmt.Sprintf("%d Alerts", ev.Alerts))
	badgeWarn := lipgloss.NewStyle().Background(lipgloss.Color("#D97706")).Foreground(lipgloss.Color("#FFFFFF")).Bold(true).Padding(0, 1).Render(fmt.Sprintf("%d Warnings", ev.Warnings))
	badgeNotice := lipgloss.NewStyle().Background(lipgloss.Color("#0284C7")).Foreground(lipgloss.Color("#FFFFFF")).Bold(true).Padding(0, 1).Render(fmt.Sprintf("%d Notices", ev.Notices))
	badgeInfo := lipgloss.NewStyle().Background(lipgloss.Color("#334155")).Foreground(lipgloss.Color("#FFFFFF")).Padding(0, 1).Render(fmt.Sprintf("%d Infos", ev.Infos))

	var lines []string
	verdictRow := func(label, value string, render func(...string) string) {
		if value == "" {
			return
		}
		wrapped := WrapWords(value, verdictValW)
		lines = append(lines, fmt.Sprintf("%s %s", keyStyle.Render(label), render(wrapped[0])))
		for _, cont := range wrapped[1:] {
			lines = append(lines, fmt.Sprintf("%s %s", keyStyle.Render(""), render(cont)))
		}
	}
	lines = append(lines, titleBanner)
	lines = append(lines, "")
	statusLines := WrapWords(postureTitle, verdictValW)
	lines = append(lines, fmt.Sprintf("%s %s", keyStyle.Render("Status:"), statusStyle.Render(statusLines[0])))
	for _, cont := range statusLines[1:] {
		lines = append(lines, fmt.Sprintf("%s %s", keyStyle.Render(""), statusStyle.Render(cont)))
	}
	lines = append(lines, fmt.Sprintf("%s %s", keyStyle.Render("Risk Level:"), lipgloss.NewStyle().Foreground(riskColor).Bold(true).Render(fmt.Sprintf("%s (Score: %d/100)", riskLevel, threatScore))))
	verdictRow("Rationale:", ass.SummaryRationale, valStyle.Render)
	lines = append(lines, fmt.Sprintf("%s %s", keyStyle.Render("Coverage:"), valStyle.Render(coverageState)))
	if len(ev.ModulesNotRun) > 0 {
		modVal := strings.Join(ev.ModulesNotRun, ", ")
		modStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FDA4AF"))
		verdictRow("Modules Not Run:", modVal, modStyle.Render)
	}
	lines = append(lines, fmt.Sprintf("%s %s", keyStyle.Render("Risk Meter:"), fmt.Sprintf("[%s] %d%%", meterStyled, threatScore)))
	lines = append(lines, fmt.Sprintf("%s %s %s %s %s", keyStyle.Render("Breakdown:"), badgeAlert, badgeWarn, badgeNotice, badgeInfo))
	lines = append(lines, fmt.Sprintf("%s %s (%d files inspected, %d skipped)",
		keyStyle.Render("Telemetry:"),
		valStyle.Render(ev.TotalDuration.Round(time.Millisecond).String()),
		ev.Coverage.FilesScanned,
		ev.Coverage.TotalSkipped(),
	))

	// Duration Breakdown
	durLabel := "Durations:"
	if bd.Estimated {
		durLabel = "Durations (Est):"
	}
	timingRow := fmt.Sprintf("%s Walk: %s │ Hash: %s │ Heur: %s │ YARA: %s │ Proc: %s",
		keyStyle.Render(durLabel),
		valStyle.Render(bd.FilesystemWalk.Round(time.Millisecond).String()),
		valStyle.Render(bd.Hashing.Round(time.Millisecond).String()),
		valStyle.Render(bd.Heuristics.Round(time.Millisecond).String()),
		valStyle.Render(bd.YARA.Round(time.Millisecond).String()),
		valStyle.Render(bd.Process.Round(time.Millisecond).String()),
	)
	lines = append(lines, timingRow)

	if len(ev.TopRules) > 0 {
		lines = append(lines, "")
		lines = append(lines, lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#38BDF8")).Render("Top Triggered Detection Rules:"))
		for i, tr := range ev.TopRules {
			if i >= 5 {
				break
			}
			rSev := lipgloss.NewStyle().Foreground(lipgloss.Color("#94A3B8")).Render(fmt.Sprintf("[%s]", tr.Severity))
			rName := lipgloss.NewStyle().Foreground(lipgloss.Color("#E2E8F0")).Render(tr.RuleName)
			rCnt := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FDE047")).Render(fmt.Sprintf("%d occurrences", tr.Count))
			lines = append(lines, fmt.Sprintf("  • %s %-45s %s", rSev, rName, rCnt))
		}
	}

	if len(ass.NextActions) > 0 {
		lines = append(lines, "")
		lines = append(lines, lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#4ADE80")).Render("Prioritized Action Recommendations:"))
		for _, act := range ass.NextActions {
			pBadge := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FBBF24")).Render(fmt.Sprintf("[P%d]", act.Priority))
			cmdBadge := lipgloss.NewStyle().Foreground(lipgloss.Color("#38BDF8")).Render(act.Command)
			lines = append(lines, fmt.Sprintf("  • %s %-32s -> %s", pBadge, act.Title, cmdBadge))
		}
	}

	card := lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(riskColor).
		Padding(1, 2).
		MarginTop(1).
		MarginBottom(1).
		Render(strings.Join(lines, "\n"))

	fmt.Fprintln(w, card)
}
