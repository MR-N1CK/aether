package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"aether/internal/events"
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

	// 1. Header
	header := fmt.Sprintf(
		" AETHER  |  Host: %s  |  Mode: %s  |  Elapsed: %s  |  Workers: %d",
		m.hostname, m.mode, m.formatDuration(m.elapsed), m.threads,
	)
	b.WriteString(m.theme.HeaderBox.Width(cardWidth).Render(header) + "\n")

	// 2. Active Modules Row
	var modRow strings.Builder
	modRow.WriteString("Modules: ")
	if len(m.moduleOrder) == 0 {
		modRow.WriteString(m.spinner.View() + " Initializing detection modules...")
	} else {
		for i, name := range m.moduleOrder {
			mod := m.activeModules[name]
			if i > 0 {
				modRow.WriteString("  |  ")
			}
			if mod.Running {
				modRow.WriteString(fmt.Sprintf("%s %s (%d hits)", m.spinner.View(), name, mod.Findings))
			} else if mod.Finished {
				if mod.Status == "NOT IMPLEMENTED" {
					modRow.WriteString(m.theme.BadgeInfo.Render(fmt.Sprintf("⊘ %s (not implemented)", name)))
				} else if mod.Err != nil || mod.Status == "FAILED" {
					modRow.WriteString(m.theme.BadgeAlert.Render(fmt.Sprintf("✕ %s (failed)", name)))
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
		statText += fmt.Sprintf("  |  Velocity: %.0f files/sec", m.filesPerSec)
	}

	// Render custom smooth progress track
	barWidth := cardWidth - len(statText) - 8
	if barWidth > 15 {
		gauge := m.renderProgressBar(barWidth)
		statText = fmt.Sprintf("%s   %s", gauge, statText)
	}
	b.WriteString(m.theme.CardBox.Width(cardWidth).Render(statText) + "\n")

	// 4. Findings Feed Table
	findingsView := m.renderFindingsFeed(cardWidth)
	b.WriteString(findingsView + "\n")

	// 5. Status / Keybinding Footer
	footerText := "[↑/↓/j/k] Navigate   [Enter] Inspect Finding   [/] Filter   [q] Cancel/Exit"
	if m.isFiltering {
		footerText = fmt.Sprintf("Search Filter: %s█  (Press [Enter] to apply, [Esc] to clear)", m.filterQuery)
	}
	b.WriteString(m.theme.StatusBar.Width(cardWidth).Render(footerText))

	return m.theme.AppContainer.Render(b.String())
}

func (m Model) renderFindingsFeed(width int) string {
	list := m.currentList()

	var b strings.Builder
	header := fmt.Sprintf("Findings Feed (%d total", len(m.findings))
	if m.filterQuery != "" {
		header += fmt.Sprintf(", %d matched filter %q", len(list), m.filterQuery)
	}
	header += "):"
	b.WriteString(m.theme.FindingRowSelected.Render(header) + "\n")

	if len(list) == 0 {
		b.WriteString(m.theme.FindingReason.Render("  No security indicators or anomalies detected yet.") + "\n")
		return m.theme.CardBox.Width(width).Render(b.String())
	}

	// Determine vertical window to display
	maxVisible := m.height - 13
	if maxVisible < 5 {
		maxVisible = 5
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
		ts := f.Timestamp.Format("15:04:05-07:00")
		prefix := "  "
		if i == m.selectedIndex {
			prefix = "> "
		}

		path := f.Path
		if len(path) > 30 {
			path = "..." + path[len(path)-27:]
		}

		reason := f.Reason
		line := fmt.Sprintf("%s%s  %s  %-10s  %-30s  %s", prefix, badge, ts, f.Module, path, reason)

		if i == m.selectedIndex {
			b.WriteString(m.theme.FindingRowSelected.Render(line) + "\n")
		} else {
			b.WriteString(m.theme.FindingRowNormal.Render(line) + "\n")
		}
	}

	return m.theme.CardBox.Width(width).Render(b.String())
}

func (m Model) renderDetailModal() string {
	f := m.SelectedFinding()
	if f == nil {
		return m.renderDashboard()
	}

	modalWidth := 70
	if m.width > 80 {
		modalWidth = m.width - 14
	}
	if modalWidth > 90 {
		modalWidth = 90
	}

	var b strings.Builder
	badge := m.theme.SeverityBadge(f.Severity)
	title := fmt.Sprintf("FINDING INSPECTION: %s %s", badge, f.RuleName)
	b.WriteString(m.theme.ModalHeader.Render(title) + "\n\n")

	b.WriteString(fmt.Sprintf("%s %s\n", m.theme.ModalFieldKey.Render("Module:    "), f.Module))
	b.WriteString(fmt.Sprintf("%s %s\n", m.theme.ModalFieldKey.Render("Severity:  "), f.Severity))
	b.WriteString(fmt.Sprintf("%s %s\n", m.theme.ModalFieldKey.Render("Timestamp: "), f.Timestamp.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("%s %s\n\n", m.theme.ModalFieldKey.Render("Path:      "), f.Path))
	b.WriteString(fmt.Sprintf("%s\n%s\n\n", m.theme.ModalFieldKey.Render("Reason / Detection Rationale:"), f.Reason))

	if f.Count > 1 || len(f.Paths) > 1 {
		b.WriteString(fmt.Sprintf("%s %d\n", m.theme.ModalFieldKey.Render("Instances: "), f.Count))
		if len(f.Paths) > 0 {
			b.WriteString(m.theme.ModalFieldKey.Render("All Matched Paths:") + "\n")
			for _, p := range f.Paths {
				b.WriteString(fmt.Sprintf("  - %s\n", p))
			}
			b.WriteString("\n")
		}
	}

	if len(f.Hashes) > 0 {
		b.WriteString(m.theme.ModalFieldKey.Render("Cryptographic Hashes:") + "\n")
		for k, v := range f.Hashes {
			b.WriteString(fmt.Sprintf("  %-8s %s\n", k+":", v))
		}
		b.WriteString("\n")
	}

	if len(f.Metadata) > 0 {
		b.WriteString(m.theme.ModalFieldKey.Render("Forensic Metadata:") + "\n")
		for k, v := range f.Metadata {
			b.WriteString(fmt.Sprintf("  %-16s %v\n", k+":", v))
		}
		b.WriteString("\n")
	}

	b.WriteString(m.theme.FindingTimestamp.Render("Press [Esc] or [Enter] to return to dashboard"))

	box := m.theme.ModalBox.Width(modalWidth).Render(b.String())
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
}

func (m Model) renderFinished() string {
	cardWidth := m.width - 4
	if cardWidth < 68 {
		cardWidth = 68
	}

	var b strings.Builder

	// Header
	header := fmt.Sprintf(
		" AETHER THREAT HUNT COMPLETED  |  Host: %s  |  Duration: %s",
		m.hostname, m.formatDuration(m.elapsed),
	)
	b.WriteString(m.theme.HeaderBox.Width(cardWidth).Render(header) + "\n")

	// Final Verdict Card
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
	switch verdict {
	case events.VerdictCompromised:
		verdictBanner = m.theme.VerdictCompromised.Width(cardWidth).Render(
			fmt.Sprintf("VERDICT: COMPROMISED%s\nActive threats or high-confidence indicators of compromise detected (%d ALERT(S)).", coverageSuffix, alerts),
		)
	case events.VerdictSuspicious:
		verdictBanner = m.theme.VerdictSuspicious.Width(cardWidth).Render(
			fmt.Sprintf("VERDICT: SUSPICIOUS%s\nAnomalies or suspicious persistence hooks detected (%d Warnings, %d Notices).", coverageSuffix, warnings, notices),
		)
	default:
		verdictBanner = m.theme.VerdictClean.Width(cardWidth).Render(
			fmt.Sprintf("VERDICT: CLEAN%s\nNo known indicators of compromise or anomalous artifacts identified.", coverageSuffix),
		)
	}
	b.WriteString(verdictBanner + "\n")

	stats := fmt.Sprintf("Files Inspected: %s  |  Total Findings: %d  (Alerts: %d, Warnings: %d, Notices: %d, Infos: %d)",
		m.formatNumber(m.filesScanned), len(m.findings), alerts, warnings, notices, infos)
	if cov.TotalSkipped() > 0 {
		stats += fmt.Sprintf("\nSkipped Files: %d  (Oversize: %d, Perm Denied: %d, Vanished: %d, Non-Regular: %d, Excluded: %d)",
			cov.TotalSkipped(), cov.SkippedOversize, cov.SkippedPermission, cov.SkippedVanished, cov.SkippedNotRegular, cov.SkippedExcluded)
	}
	if cov.Suppressed > 0 {
		stats += fmt.Sprintf("\nSuppressed Files: %d", cov.Suppressed)
	}
	if cov.Acknowledged > 0 {
		stats += fmt.Sprintf("\nAcknowledged Findings: %d", cov.Acknowledged)
	}
	if m.finishEvent != nil {
		if m.finishEvent.ProcessCoverage != nil {
			stats += fmt.Sprintf("\nProcess Coverage: Inspected: %d, Limited: %d, Perm Denied: %d, Vanished: %d, Kernel Threads: %d, Zombies: %d, Non-Root: %v, Hidden-PID: %s, Not Hashed: %d",
				m.finishEvent.ProcessCoverage.Inspected, m.finishEvent.ProcessCoverage.Limited, m.finishEvent.ProcessCoverage.SkippedPermission, m.finishEvent.ProcessCoverage.SkippedVanished, m.finishEvent.ProcessCoverage.KernelThreads, m.finishEvent.ProcessCoverage.Zombies, m.finishEvent.ProcessCoverage.NonRootLimited, m.finishEvent.ProcessCoverage.HiddenPIDRange, m.finishEvent.ProcessCoverage.NotHashed)
		}
		if m.finishEvent.PersistenceCoverage != nil {
			stats += fmt.Sprintf("\nPersistence Coverage: Inspected: %d, Unreadable: %d, Masked: %d, Not Present: %d",
				m.finishEvent.PersistenceCoverage.TotalInspected, m.finishEvent.PersistenceCoverage.TotalUnreadable, m.finishEvent.PersistenceCoverage.TotalMasked, m.finishEvent.PersistenceCoverage.NotPresent)
		}
		if m.finishEvent.UsersCoverage != nil {
			shadowStatus := "readable"
			if m.finishEvent.UsersCoverage.ShadowGapNonRoot {
				shadowStatus = "unreadable (non-root)"
			} else if !m.finishEvent.UsersCoverage.ShadowReadable {
				shadowStatus = "unreadable"
			}
			stats += fmt.Sprintf("\nUsers Coverage: Accounts: %d (System: %d), Shadow: %s, Duplicate UIDs: %d",
				m.finishEvent.UsersCoverage.AccountsInspected, m.finishEvent.UsersCoverage.SystemAccounts, shadowStatus, m.finishEvent.UsersCoverage.DuplicateUIDs)
		}
		if m.finishEvent.NetworkCoverage != nil {
			stats += fmt.Sprintf("\nNetwork Coverage: Sockets: %d (TCP Listeners: %d, UDP Listeners: %d, Established: %d, Raw/Packet: %d)",
				m.finishEvent.NetworkCoverage.SocketsInspected, m.finishEvent.NetworkCoverage.TCPListeners, m.finishEvent.NetworkCoverage.UDPListeners, m.finishEvent.NetworkCoverage.EstablishedConnections, m.finishEvent.NetworkCoverage.RawPacketSockets)
		}
		if m.finishEvent.KernelCoverage != nil {
			taintFlagsStr := "clean"
			if len(m.finishEvent.KernelCoverage.TaintFlags) > 0 {
				taintFlagsStr = strings.Join(m.finishEvent.KernelCoverage.TaintFlags, "+")
			}
			stats += fmt.Sprintf("\nKernel Coverage: Loaded Modules: %d (Sysfs: %d), Taint: %d (%s, %s), Modprobe Files: %d",
				m.finishEvent.KernelCoverage.LoadedModulesInspected, m.finishEvent.KernelCoverage.SysfsLoadableEntries, m.finishEvent.KernelCoverage.TaintValue, taintFlagsStr, m.finishEvent.KernelCoverage.TaintSeverity, m.finishEvent.KernelCoverage.ModprobeFilesInspected)
		}
		if m.finishEvent.YARACoverage != nil {
			if m.finishEvent.YARACoverage.NotRunReason != "" {
				stats += fmt.Sprintf("\nYARA Not Run: %s", m.finishEvent.YARACoverage.NotRunReason)
			} else if m.finishEvent.YARACoverage.DemoRulesOnly {
				stats += fmt.Sprintf("\nYARA: demo rules only, no real rule set loaded (Rules Loaded: %d, Scanned: %d)",
					m.finishEvent.YARACoverage.RulesLoaded, m.finishEvent.YARACoverage.FilesScanned)
			} else {
				ruleFilesSeenStr := ""
				if m.finishEvent.YARACoverage.RuleFilesSeen > 0 {
					ruleFilesSeenStr = fmt.Sprintf(", Rule Files Seen: %d", m.finishEvent.YARACoverage.RuleFilesSeen)
				}
				stats += fmt.Sprintf("\nYARA Coverage: Rules Loaded: %d (Failed: %d), Scanned: %d%s, Oversize: %d, Timeout: %d, Error: %d",
					m.finishEvent.YARACoverage.RulesLoaded, m.finishEvent.YARACoverage.RulesFailed, m.finishEvent.YARACoverage.FilesScanned,
					ruleFilesSeenStr, m.finishEvent.YARACoverage.SkippedOversize, m.finishEvent.YARACoverage.SkippedTimeout, m.finishEvent.YARACoverage.SkippedError)
			}
		}
		if len(m.finishEvent.ModulesNotRun) > 0 {
			stats += fmt.Sprintf("\nModules Not Run: %s", strings.Join(m.finishEvent.ModulesNotRun, ", "))
		}
		if len(m.finishEvent.TopRules) > 0 {
			stats += "\nTop Rules: "
			limit := 3
			if len(m.finishEvent.TopRules) < limit {
				limit = len(m.finishEvent.TopRules)
			}
			var trParts []string
			for i := 0; i < limit; i++ {
				tr := m.finishEvent.TopRules[i]
				trParts = append(trParts, fmt.Sprintf("%s (%d)", tr.RuleName, tr.Count))
			}
			stats += strings.Join(trParts, ", ")
		}
	}
	b.WriteString(m.theme.CardBox.Width(cardWidth).Render(stats) + "\n")

	// Findings list
	b.WriteString(m.renderFindingsFeed(cardWidth) + "\n")

	// Footer
	footerText := "[↑/↓/j/k] Navigate   [Enter] Inspect Finding   [/] Filter   [q] Exit"
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
