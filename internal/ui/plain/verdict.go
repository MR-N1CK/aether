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
		fmt.Fprintf(w, "\n+=========================================================================+\n")
		fmt.Fprintf(w, "|                       SYSTEM EXECUTIVE RISK ASSESSMENT                  |\n")
		fmt.Fprintf(w, "+=========================================================================+\n")
		fmt.Fprintf(w, "| Host Posture:  %-56s |\n", fmt.Sprintf("[%s] %s", ass.Posture, postureTitle))
		fmt.Fprintf(w, "| Risk Level:    %-56s |\n", fmt.Sprintf("%s (Score: %d/100)", riskLevel, threatScore))
		fmt.Fprintf(w, "| Rationale:     %-56s |\n", ass.SummaryRationale)
		fmt.Fprintf(w, "| Coverage:      %-56s |\n", coverageState)
		if len(ev.ModulesNotRun) > 0 {
			fmt.Fprintf(w, "| Modules Not Run: %-53s |\n", strings.Join(ev.ModulesNotRun, ", "))
		}
		fmt.Fprintf(w, "| Findings:      %d Alerts, %d Warnings, %d Notices, %d Infos       |\n",
			ev.Alerts, ev.Warnings, ev.Notices, ev.Infos)
		fmt.Fprintf(w, "| Risk Meter:    [%s%s] %3d%%                      |\n", barFilled, barEmpty, threatScore)
		fmt.Fprintf(w, "| Duration:      %-15s  Inspected: %-15d Files        |\n",
			ev.TotalDuration.Round(time.Millisecond), ev.Coverage.FilesScanned)
		fmt.Fprintf(w, "+-------------------------------------------------------------------------+\n")
		fmt.Fprintf(w, "| Subsystem Timing Breakdown:                                             |\n")
		fmt.Fprintf(w, "| Walk: %-10s Hash: %-10s Heuristics: %-10s YARA: %-8s |\n",
			bd.FilesystemWalk.Round(time.Millisecond), bd.Hashing.Round(time.Millisecond),
			bd.Heuristics.Round(time.Millisecond), bd.YARA.Round(time.Millisecond))
		fmt.Fprintf(w, "| Process: %-7s Network: %-7s Correlation: %-7s Total: %-7s |\n",
			bd.Process.Round(time.Millisecond), bd.Network.Round(time.Millisecond),
			bd.Correlation.Round(time.Millisecond), bd.Total.Round(time.Millisecond))
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

	// Rich Card Rendering
	titleBanner := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(riskColor).
		Padding(0, 2).
		Render(fmt.Sprintf("POSTURE: %s [%s]  (Score: %d/100)", ass.Posture, riskLevel, threatScore))

	statusStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(riskColor).
		Render(postureTitle)

	keyStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#94A3B8")).
		Width(18)

	valStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#F8FAFC"))

	meterStyled := lipgloss.NewStyle().Foreground(riskColor).Render(barFilled) +
		lipgloss.NewStyle().Foreground(lipgloss.Color("#334155")).Render(barEmpty)

	badgeAlert := lipgloss.NewStyle().Background(lipgloss.Color("#E11D48")).Foreground(lipgloss.Color("#FFFFFF")).Bold(true).Padding(0, 1).Render(fmt.Sprintf("%d Alerts", ev.Alerts))
	badgeWarn := lipgloss.NewStyle().Background(lipgloss.Color("#D97706")).Foreground(lipgloss.Color("#FFFFFF")).Bold(true).Padding(0, 1).Render(fmt.Sprintf("%d Warnings", ev.Warnings))
	badgeNotice := lipgloss.NewStyle().Background(lipgloss.Color("#0284C7")).Foreground(lipgloss.Color("#FFFFFF")).Bold(true).Padding(0, 1).Render(fmt.Sprintf("%d Notices", ev.Notices))
	badgeInfo := lipgloss.NewStyle().Background(lipgloss.Color("#334155")).Foreground(lipgloss.Color("#FFFFFF")).Padding(0, 1).Render(fmt.Sprintf("%d Infos", ev.Infos))

	var lines []string
	lines = append(lines, titleBanner)
	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("%s %s", keyStyle.Render("Status:"), statusStyle))
	lines = append(lines, fmt.Sprintf("%s %s", keyStyle.Render("Risk Level:"), lipgloss.NewStyle().Foreground(riskColor).Bold(true).Render(fmt.Sprintf("%s (Score: %d/100)", riskLevel, threatScore))))
	lines = append(lines, fmt.Sprintf("%s %s", keyStyle.Render("Rationale:"), valStyle.Render(ass.SummaryRationale)))
	lines = append(lines, fmt.Sprintf("%s %s", keyStyle.Render("Coverage:"), valStyle.Render(coverageState)))
	if len(ev.ModulesNotRun) > 0 {
		lines = append(lines, fmt.Sprintf("%s %s", keyStyle.Render("Modules Not Run:"), lipgloss.NewStyle().Foreground(lipgloss.Color("#FDA4AF")).Render(strings.Join(ev.ModulesNotRun, ", "))))
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
	timingRow := fmt.Sprintf("%s Walk: %s │ Hash: %s │ Heur: %s │ YARA: %s │ Proc: %s",
		keyStyle.Render("Durations:"),
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
