package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"aether/internal/events"
	"aether/internal/report"
	"aether/internal/ui/theme"
)

var asciiLogo = []string{
	` █████╗ ███████╗████████╗██╗  ██╗███████╗██████╗ `,
	`██╔══██╗██╔════╝╚══██╔══╝██║  ██║██╔════╝██╔══██╗`,
	`███████║█████╗     ██║   ███████║█████╗  ██████╔╝`,
	`██╔══██║██╔══╝     ██║   ██╔══██║██╔══╝  ██╔══██╗`,
	`██║  ██║███████╗   ██║   ██║  ██║███████╗██║  ██║`,
	`╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝`,
}

// View computes the full terminal UI representation for the current frame.
func (m Model) View() string {
	if m.width > 0 && m.height > 0 {
		if m.width < theme.MinTermWidth || m.height < theme.MinTermHeight {
			return m.renderTooSmall()
		}
	}

	switch m.state {
	case stateSplash:
		return m.renderSplash()
	case stateDetail:
		return m.renderDetailModal()
	case stateFinished:
		return m.renderFinished()
	case stateDashboard:
		fallthrough
	default:
		return m.renderDashboard()
	}
}

func (m Model) renderTooSmall() string {
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(theme.ColorAlert).
		Padding(1, 2).
		Align(lipgloss.Center).
		Render(fmt.Sprintf(
			"TERMINAL TOO SMALL\n\nCurrent Size: %dx%d\nRequired Minimum: %dx%d\n\nPlease expand your terminal window.",
			m.width, m.height, theme.MinTermWidth, theme.MinTermHeight,
		))

	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
}

func (m Model) renderSplash() string {
	var b strings.Builder
	revealRatio := float64(m.splashFrame) / float64(m.maxSplash)
	linesToShow := int(revealRatio * float64(len(asciiLogo)+2))

	b.WriteString("\n\n")
	for i, line := range asciiLogo {
		if i <= linesToShow {
			b.WriteString(m.theme.LogoText.Render(line) + "\n")
		} else {
			b.WriteString("\n")
		}
	}

	b.WriteString("\n")
	if linesToShow >= len(asciiLogo) {
		sub := m.theme.SubHeaderText.Render("LINUX-NATIVE DEFENSIVE THREAT HUNTING ENGINE")
		b.WriteString(sub + "\n\n")
		hint := m.theme.FindingTimestamp.Render("Press any key to skip...")
		b.WriteString(hint + "\n")
	}

	content := b.String()
	w := m.width
	if w <= 0 {
		w = 80
	}
	h := m.height
	if h <= 0 {
		h = 24
	}

	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, content)
}

func (m Model) renderDashboard() string {
	var b strings.Builder
	cardWidth := m.width - 4
	if cardWidth < 68 {
		cardWidth = 68
	}

	// 1. Permanent Brand Header
	b.WriteString(m.renderBrandHeader(cardWidth, m.spinner.View()+" SCANNING IN PROGRESS...") + "\n")

	// 2. Active Modules Row
	var modRow strings.Builder
	modRow.WriteString(m.theme.SectionHeader.Render("Active Modules: ") + " ")
	if len(m.moduleOrder) == 0 {
		modRow.WriteString(m.spinner.View() + " Initializing detection modules & YARA-X rules...")
	} else {
		for i, name := range m.moduleOrder {
			mod := m.activeModules[name]
			if i > 0 {
				modRow.WriteString("  │  ")
			}
			if mod.Running {
				modRow.WriteString(fmt.Sprintf("%s %s (%d hits)", m.spinner.View(), name, mod.Findings))
			} else if mod.Finished {
				if mod.Status == "NOT IMPLEMENTED" {
					modRow.WriteString(m.theme.BadgeInfo.Render(fmt.Sprintf("⊘ %s", name)))
				} else if mod.Err != nil || mod.Status == "FAILED" {
					modRow.WriteString(m.theme.BadgeAlert.Render(fmt.Sprintf("✕ %s", name)))
				} else {
					modRow.WriteString(m.theme.BadgeNotice.Render(fmt.Sprintf("✓ %s (%d)", name, mod.Findings)))
				}
			} else {
				modRow.WriteString(fmt.Sprintf("○ %s", name))
			}
		}
	}
	b.WriteString(m.theme.CardBox.Width(cardWidth).Render(modRow.String()) + "\n")

	// 3. Progress / Stats Bar
	statText := fmt.Sprintf("Files Inspected: %s", m.formatNumber(m.filesScanned))
	if m.filesPerSec > 0 {
		statText += fmt.Sprintf("  │  Velocity: %.0f files/sec", m.filesPerSec)
	}

	// Render custom smooth progress track
	barWidth := cardWidth - len(statText) - 10
	if barWidth > 15 {
		gauge := m.renderProgressBar(barWidth)
		statText = fmt.Sprintf("%s   %s", gauge, statText)
	}
	b.WriteString(m.theme.CardBox.Width(cardWidth).Render(statText) + "\n")

	// 4. Findings Feed Table
	findingsView := m.renderFindingsFeed(cardWidth)
	b.WriteString(findingsView + "\n")

	// 5. Status / Keybinding Footer
	footerText := fmt.Sprintf("%s Navigate   %s Inspect Finding   %s Filter   %s Cancel/Exit",
		m.theme.KeyHint.Render("[↑/↓/j/k]"),
		m.theme.KeyHint.Render("[Enter]"),
		m.theme.KeyHint.Render("[/]"),
		m.theme.KeyHint.Render("[q]"),
	)
	if m.isFiltering {
		footerText = fmt.Sprintf("Search Filter: %s█  (Press [Enter] to apply, [Esc] to clear)", m.filterQuery)
	}
	b.WriteString(m.theme.StatusBar.Width(cardWidth).Render(footerText))

	return m.theme.AppContainer.Render(b.String())
}

func (m Model) renderBrandHeader(width int, statusText string) string {
	title := m.theme.BrandTitle.Render("✦ A E T H E R") + "  " + m.theme.BrandTagline.Render(":: DEFENSIVE LINUX THREAT HUNTING ENGINE")

	targetPath := "Root Filesystem (/)"
	if len(m.paths) > 0 {
		targetPath = strings.Join(m.paths, ", ")
		if len(targetPath) > 35 {
			targetPath = "..." + targetPath[len(targetPath)-32:]
		}
	}

	infoRow := fmt.Sprintf("Host: %s  │  Target: %s  │  Elapsed: %s  │  Workers: %d  │  %s",
		m.hostname, targetPath, m.formatDuration(m.elapsed), m.threads, statusText)

	content := fmt.Sprintf("%s\n%s", title, m.theme.FindingTimestamp.Render(infoRow))
	return m.theme.BrandBannerBox.Width(width).Render(content)
}

func (m Model) renderRiskGauge(width int, alerts, warnings int) string {
	gaugeWidth := width - 42
	if gaugeWidth < 10 {
		gaugeWidth = 10
	}
	if gaugeWidth > 35 {
		gaugeWidth = 35
	}

	percent := 0
	label := "0% (SECURE / CLEAN)"
	var fillStyle lipgloss.Style

	if alerts > 0 {
		percent = 60 + alerts*10
		if percent > 100 {
			percent = 100
		}
		label = fmt.Sprintf("%d%% CRITICAL RISK", percent)
		fillStyle = m.theme.StatValueAlert
	} else if warnings > 0 {
		percent = 25 + warnings*10
		if percent > 85 {
			percent = 85
		}
		label = fmt.Sprintf("%d%% ELEVATED RISK", percent)
		fillStyle = m.theme.StatValueWarn
	} else {
		label = "0% (CLEAN & SECURE)"
		fillStyle = m.theme.StatValueSafe
	}

	filled := (percent * gaugeWidth) / 100
	empty := gaugeWidth - filled
	if empty < 0 {
		empty = 0
	}

	bar := fillStyle.Render(strings.Repeat("█", filled)) + m.theme.FindingTimestamp.Render(strings.Repeat("░", empty))
	return fmt.Sprintf("Threat Level: [%s] %s", bar, fillStyle.Render(label))
}

func (m Model) renderExecutiveSummaryMatrix(width int, alerts, warnings, notices, infos int, filesScanned int64) string {
	cleanFiles := filesScanned - int64(alerts) - int64(warnings)
	if cleanFiles < 0 {
		cleanFiles = 0
	}

	colWidth := (width - 10) / 3
	if colWidth < 20 {
		colWidth = 20
	}

	maliciousBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(theme.ColorAlert).
		Background(lipgloss.Color("#161B22")).
		Padding(0, 1).
		Width(colWidth)

	suspiciousBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(theme.ColorWarning).
		Background(lipgloss.Color("#161B22")).
		Padding(0, 1).
		Width(colWidth)

	safeBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(theme.ColorNotice).
		Background(lipgloss.Color("#161B22")).
		Padding(0, 1).
		Width(colWidth)

	malText := fmt.Sprintf("%s\n%s\n%s",
		m.theme.StatValueAlert.Render(fmt.Sprintf("🚨 MALICIOUS (%d)", alerts)),
		m.theme.FindingRowNormal.Render(fmt.Sprintf("%d Confirmed Threat(s)", alerts)),
		m.theme.FindingTimestamp.Render("Backdoors & Implants"),
	)
	if alerts == 0 {
		malText = fmt.Sprintf("%s\n%s\n%s",
			m.theme.StatValueAlert.Render("🚨 MALICIOUS (0)"),
			m.theme.FindingTimestamp.Render("0 Active Threats"),
			m.theme.FindingTimestamp.Render("No Backdoors Found"),
		)
	}

	suspText := fmt.Sprintf("%s\n%s\n%s",
		m.theme.StatValueWarn.Render(fmt.Sprintf("⚠️ SUSPICIOUS (%d)", warnings+notices)),
		m.theme.FindingRowNormal.Render(fmt.Sprintf("%d Warn / %d Notice", warnings, notices)),
		m.theme.FindingTimestamp.Render("Anomalies / Autostarts"),
	)

	safeText := fmt.Sprintf("%s\n%s\n%s",
		m.theme.StatValueSafe.Render(fmt.Sprintf("🛡️ SAFE ASSETS (%s)", m.formatNumber(cleanFiles))),
		m.theme.FindingRowNormal.Render(fmt.Sprintf("%s Files Verified Clean", m.formatNumber(cleanFiles))),
		m.theme.FindingTimestamp.Render("Baseline Intact"),
	)

	cols := lipgloss.JoinHorizontal(lipgloss.Top,
		maliciousBox.Render(malText), " ",
		suspiciousBox.Render(suspText), " ",
		safeBox.Render(safeText),
	)

	return cols
}

func (m Model) renderFindingsFeed(width int) string {
	list := m.currentList()

	var b strings.Builder
	header := fmt.Sprintf("Findings Feed (%d total", len(m.findings))
	if m.filterQuery != "" {
		header += fmt.Sprintf(", %d matched filter %q", len(list), m.filterQuery)
	}
	header += "):"
	b.WriteString(m.theme.SectionHeader.Render(header) + "\n")

	if len(list) == 0 {
		b.WriteString(m.theme.StatValueSafe.Render("  ✓ No security indicators or anomalies detected. All inspected files verified clean.") + "\n")
		return m.theme.CardBox.Width(width).Render(b.String())
	}

	// Determine vertical window to display
	maxVisible := 5
	if m.height > 26 {
		maxVisible = 7
	}

	start := 0
	if m.selectedIndex >= maxVisible {
		start = m.selectedIndex - maxVisible + 1
	}
	end := start + maxVisible
	if end > len(list) {
		end = len(list)
	}

	for i := start; i < end; i++ {
		f := list[i]
		badge := m.theme.SeverityBadge(f.Severity)
		ts := f.Timestamp.Format("15:04:05")
		prefix := "  "
		if i == m.selectedIndex {
			prefix = "> "
		}

		path := f.Path
		if len(path) > 34 {
			path = "..." + path[len(path)-31:]
		}

		reason := f.Reason
		line := fmt.Sprintf("%s%s  %s  %-10s  %-34s  %s", prefix, badge, ts, f.Module, path, reason)

		if i == m.selectedIndex {
			b.WriteString(m.theme.FindingRowSelected.Render(line) + "\n")
		} else {
			b.WriteString(m.theme.FindingRowNormal.Render(line) + "\n")
		}
	}

	feedBox := m.theme.CardBox.Width(width).Render(b.String())

	// If a finding is currently highlighted, append a sleek Live Quick-Preview Box!
	sel := m.SelectedFinding()
	if sel != nil {
		report.PopulateFindingDetails(sel)
		var p strings.Builder
		pTitle := fmt.Sprintf("🔍 SELECTED THREAT PREVIEW: %s %s", m.theme.SeverityBadge(sel.Severity), sel.Title)
		p.WriteString(m.theme.SubSectionHeader.Render(pTitle) + "\n")
		p.WriteString(fmt.Sprintf("%s %s\n", m.theme.ModalFieldKey.Render("Path:       "), sel.Path))
		if sel.Why != "" {
			p.WriteString(fmt.Sprintf("%s %s\n", m.theme.ModalFieldKey.Render("Assessment: "), sel.Why))
		}
		if len(sel.Remediation) > 0 {
			p.WriteString(fmt.Sprintf("%s %s\n", m.theme.ModalFieldKey.Render("Remediation:"), sel.Remediation[0]))
		}
		p.WriteString(m.theme.KeyHint.Render("💡 Press [Enter] for Full Forensic Dossier with Hashes, Line Evidence & MITRE ATT&CK"))

		previewBox := m.theme.CardActive.Width(width).Render(p.String())
		return feedBox + "\n" + previewBox
	}

	return feedBox
}

func (m Model) renderDetailModal() string {
	f := m.SelectedFinding()
	if f == nil {
		return m.renderDashboard()
	}

	report.PopulateFindingDetails(f)

	modalWidth := 74
	if m.width > 80 {
		modalWidth = m.width - 10
	}
	if modalWidth > 96 {
		modalWidth = 96
	}

	var b strings.Builder
	badge := m.theme.SeverityBadge(f.Severity)
	title := fmt.Sprintf("🔍 FORENSIC THREAT DOSSIER :: %s %s", badge, f.Title)
	b.WriteString(m.theme.ModalHeader.Render(title) + "\n\n")

	// Threat Assessment Section
	b.WriteString(m.theme.SubSectionHeader.Render("1. EXECUTIVE THREAT ASSESSMENT") + "\n")
	b.WriteString(fmt.Sprintf("%s %s\n", m.theme.ModalFieldKey.Render("Detection Rule:"), f.RuleName))
	b.WriteString(fmt.Sprintf("%s %s\n", m.theme.ModalFieldKey.Render("Security Module:"), f.Module))
	b.WriteString(fmt.Sprintf("%s %s  │  %s %s (Confidence: %s)\n",
		m.theme.ModalFieldKey.Render("Alert Severity:"), f.Severity,
		m.theme.ModalFieldKey.Render("Verdict:"), f.Verdict, f.Confidence))
	if f.ConfidenceRationale != "" {
		b.WriteString(fmt.Sprintf("%s %s\n", m.theme.ModalFieldKey.Render("Rationale:     "), f.ConfidenceRationale))
	}
	if f.EvidenceRecord != nil && len(f.EvidenceRecord.ContributingDetectors) > 0 {
		b.WriteString(fmt.Sprintf("%s %s\n", m.theme.ModalFieldKey.Render("Corroboration: "), strings.Join(f.EvidenceRecord.ContributingDetectors, ", ")))
	}
	if f.Why != "" {
		b.WriteString(fmt.Sprintf("%s\n%s\n", m.theme.ModalFieldKey.Render("Why This Is Dangerous:"), f.Why))
	}
	b.WriteString("\n")

	// Artifact Details Section
	b.WriteString(m.theme.SubSectionHeader.Render("2. FORENSIC ARTIFACT DETAILS") + "\n")
	b.WriteString(fmt.Sprintf("%s %s\n", m.theme.ModalFieldKey.Render("Target File Path:"), f.Path))
	b.WriteString(fmt.Sprintf("%s %s\n", m.theme.ModalFieldKey.Render("Detection Time:  "), f.Timestamp.Format(time.RFC3339)))
	if f.EvidenceRecord != nil {
		b.WriteString(fmt.Sprintf("%s %s  │  %s %s\n",
			m.theme.ModalFieldKey.Render("Package Status:  "), f.EvidenceRecord.PackageStatus,
			m.theme.ModalFieldKey.Render("Context Profile:"), f.EvidenceRecord.ContextProfile))
	}
	if f.Evidence != "" {
		b.WriteString(fmt.Sprintf("%s %s\n", m.theme.ModalFieldKey.Render("Evidence Snippet:"), f.Evidence))
	}

	if len(f.Hashes) > 0 {
		b.WriteString(m.theme.ModalFieldKey.Render("Cryptographic Hashes:") + "\n")
		for k, v := range f.Hashes {
			b.WriteString(fmt.Sprintf("  • %-8s %s\n", k+":", v))
		}
	}
	b.WriteString("\n")

	// MITRE ATT&CK Mapping Section
	if len(f.MITRE) > 0 {
		b.WriteString(m.theme.SubSectionHeader.Render("3. MITRE ATT&CK FRAMEWORK CLASSIFICATION") + "\n")
		for _, mit := range f.MITRE {
			b.WriteString(fmt.Sprintf("  • [%s] %s — %s\n", mit.Technique, mit.Tactic, mit.TechniqueName))
		}
		b.WriteString("\n")
	}

	// Actionable Remediation Plan Section
	if len(f.Remediation) > 0 {
		b.WriteString(m.theme.SubSectionHeader.Render("4. RECOMMENDED CONTAINMENT & REMEDIATION") + "\n")
		for idx, step := range f.Remediation {
			b.WriteString(fmt.Sprintf("  %d. %s\n", idx+1, step))
		}
		b.WriteString("\n")
	}

	b.WriteString(m.theme.KeyHint.Render("Press [Esc] or [Enter] to return to Command Center"))

	box := m.theme.ModalBox.Width(modalWidth).Render(b.String())
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
}

func (m Model) renderFinished() string {
	cardWidth := m.width - 4
	if cardWidth < 68 {
		cardWidth = 68
	}

	var b strings.Builder

	// 1. Permanent Brand Header
	b.WriteString(m.renderBrandHeader(cardWidth, "COMPLETED") + "\n")

	// 2. Final Verdict Card
	verdict := events.VerdictClean
	alerts, warnings, notices, infos := 0, 0, 0, 0
	partial := false
	var cov events.CoverageStats

	if m.finishEvent != nil {
		verdict = m.finishEvent.Verdict
		alerts = m.finishEvent.Alerts
		warnings = m.finishEvent.Warnings
		notices = m.finishEvent.Notices
		infos = m.finishEvent.Infos
		partial = m.finishEvent.Partial
		cov = m.finishEvent.Coverage
	}

	coverageSuffix := ""
	if partial {
		coverageSuffix = " (PARTIAL COVERAGE)"
	}

	var verdictBanner string
	switch {
	case verdict == events.VerdictCompromised || alerts > 0:
		riskGauge := m.renderRiskGauge(cardWidth, alerts, warnings)
		verdictBanner = m.theme.VerdictCompromised.Width(cardWidth).Render(
			fmt.Sprintf("🚨 VERDICT: SYSTEM COMPROMISED%s\nActive threats or high-confidence compromise indicators detected (%d MALICIOUS ALERT(S)).\n%s", coverageSuffix, alerts, riskGauge),
		)
	case verdict == events.VerdictSuspicious || warnings > 0 || notices > 0:
		riskGauge := m.renderRiskGauge(cardWidth, alerts, warnings)
		verdictBanner = m.theme.VerdictSuspicious.Width(cardWidth).Render(
			fmt.Sprintf("⚠️ VERDICT: SUSPICIOUS ANOMALIES IDENTIFIED%s\nSecurity anomalies or unverified persistence hooks detected (%d Warnings, %d Notices).\n%s", coverageSuffix, warnings, notices, riskGauge),
		)
	default:
		riskGauge := m.renderRiskGauge(cardWidth, 0, 0)
		verdictBanner = m.theme.VerdictClean.Width(cardWidth).Render(
			fmt.Sprintf("🛡️ VERDICT: SYSTEM CLEAN & SECURE%s\nNo known indicators of compromise, backdoors, webshells, or anomalous artifacts identified.\n%s", coverageSuffix, riskGauge),
		)
	}
	b.WriteString(verdictBanner + "\n")

	// 3. 3-Column Executive Summary Matrix Card
	summaryMatrix := m.renderExecutiveSummaryMatrix(cardWidth, alerts, warnings, notices, infos, m.filesScanned)
	b.WriteString(summaryMatrix + "\n")

	// 4. Detailed Telemetry & Coverage Card
	var stats strings.Builder
	stats.WriteString(fmt.Sprintf("Inspected: %s files  │  Duration: %s  │  Total Findings: %d  (Alerts: %d, Warnings: %d, Notices: %d, Infos: %d)",
		m.formatNumber(m.filesScanned), m.formatDuration(m.elapsed), len(m.findings), alerts, warnings, notices, infos))

	if cov.TotalSkipped() > 0 {
		stats.WriteString(fmt.Sprintf("\nSkipped Files: %d  (Oversize: %d, Perm Denied: %d, Vanished: %d, Non-Regular: %d, Excluded: %d)",
			cov.TotalSkipped(), cov.SkippedOversize, cov.SkippedPermission, cov.SkippedVanished, cov.SkippedNotRegular, cov.SkippedExcluded))
	}
	if m.finishEvent != nil && m.finishEvent.YARACoverage != nil {
		yCov := m.finishEvent.YARACoverage
		if yCov.RulesLoaded > 0 {
			stats.WriteString(fmt.Sprintf("\nYARA-X Engine: %d Rules Active (Scanned: %d, Oversize: %d, Errors: %d)",
				yCov.RulesLoaded, yCov.FilesScanned, yCov.SkippedOversize, yCov.SkippedError))
		}
	}
	if m.finishEvent != nil && len(m.finishEvent.TopRules) > 0 {
		stats.WriteString("\nTop Rules Triggered: ")
		var trParts []string
		for _, tr := range m.finishEvent.TopRules {
			trParts = append(trParts, fmt.Sprintf("%s (%d)", tr.RuleName, tr.Count))
		}
		stats.WriteString(strings.Join(trParts, ", "))
	}
	b.WriteString(m.theme.CardBox.Width(cardWidth).Render(stats.String()) + "\n")

	// 5. Findings Feed Table + Live Preview
	b.WriteString(m.renderFindingsFeed(cardWidth) + "\n")

	// 6. Navigation Footer
	footerText := fmt.Sprintf("%s Navigate   %s Full Forensic Dossier   %s Filter   %s Exit Command Center",
		m.theme.KeyHint.Render("[↑/↓/j/k]"),
		m.theme.KeyHint.Render("[Enter]"),
		m.theme.KeyHint.Render("[/]"),
		m.theme.KeyHint.Render("[q]"),
	)
	if m.isFiltering {
		footerText = fmt.Sprintf("Search Filter: %s█  (Press [Enter] to apply, [Esc] to clear)", m.filterQuery)
	}
	b.WriteString(m.theme.StatusBar.Width(cardWidth).Render(footerText))

	return m.theme.AppContainer.Render(b.String())
}

func (m Model) renderProgressBar(width int) string {
	if width < 5 {
		return ""
	}
	// Dynamic animated pulse bar
	chars := make([]rune, width)
	activePos := int(m.elapsed.Milliseconds()/100) % width
	for i := 0; i < width; i++ {
		dist := i - activePos
		if dist < 0 {
			dist = -dist
		}
		if dist == 0 {
			chars[i] = '█'
		} else if dist <= 2 {
			chars[i] = '▓'
		} else if dist <= 4 {
			chars[i] = '▒'
		} else {
			chars[i] = '░'
		}
	}
	return string(chars)
}

func (m Model) formatDuration(d time.Duration) string {
	h := int(d.Hours())
	min := int(d.Minutes()) % 60
	sec := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", h, min, sec)
	}
	return fmt.Sprintf("%02d:%02d", min, sec)
}

func (m Model) formatNumber(n int64) string {
	in := fmt.Sprintf("%d", n)
	out := ""
	for i, c := range in {
		if i > 0 && (len(in)-i)%3 == 0 {
			out += ","
		}
		out += string(c)
	}
	return out
}
