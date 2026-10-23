package tui

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"

	"aether/internal/events"
	"aether/internal/report"
	"aether/internal/ui/theme"
	"aether/internal/yara"
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

	if m.showPalette {
		return m.renderCommandPalette()
	}

	if m.confirmQuit {
		return m.renderQuitConfirm()
	}

	var baseView string
	switch m.state {
	case stateSplash:
		return m.renderSplash()
	case stateDetail:
		baseView = m.renderDetailModal()
	case stateFinished:
		baseView = m.renderFinished()
	case stateDashboard:
		fallthrough
	default:
		baseView = m.renderDashboard()
	}

	if m.toastMessage != "" && time.Now().Before(m.toastUntil) {
		toast := m.theme.ToastBox.Render("  ✓ " + m.toastMessage + "  ")
		baseView = baseView + "\n" + toast
	}

	return baseView
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
	b.WriteString("\n\n")

	// Determine styling based on animation phase
	var logoStyle lipgloss.Style
	if m.theme.NoColor {
		logoStyle = lipgloss.NewStyle().Bold(true)
	} else if m.splashFrame <= 6 {
		// Phase 1: Deep Navy wipe
		logoStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#2563EB")).Bold(true)
	} else if m.splashFrame <= 12 {
		// Phase 2: Bright Cyan
		logoStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#38BDF8")).Bold(true)
	} else {
		// Phase 3: Crisp Platinum White / Azure Glow
		logoStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Bold(true)
	}

	linesToShow := len(asciiLogo)
	if m.splashFrame <= 6 {
		ratio := float64(m.splashFrame) / 6.0
		linesToShow = int(ratio * float64(len(asciiLogo)))
		if linesToShow < 1 {
			linesToShow = 1
		}
	}

	for i, line := range asciiLogo {
		if i < linesToShow {
			b.WriteString(logoStyle.Render(line) + "\n")
		} else {
			b.WriteString("\n")
		}
	}
	b.WriteString("\n")

	// Typewriter tagline during Phase 2 and 3
	fullTagline := "LINUX-NATIVE DEFENSIVE THREAT HUNTING ENGINE"
	if m.splashFrame >= 6 {
		var tagline string
		if m.splashFrame < 13 {
			typedLen := int(float64(m.splashFrame-6) / 6.0 * float64(len(fullTagline)))
			if typedLen > len(fullTagline) {
				typedLen = len(fullTagline)
			}
			tagline = fullTagline[:typedLen] + "█"
		} else {
			tagline = fullTagline
		}
		sub := m.theme.BrandTagline.Render(tagline)
		b.WriteString(sub + "\n\n")

		// High-precision fractional sub-block progress track
		trackWidth := 46
		ratio := float64(m.splashFrame) / float64(m.maxSplash)
		bar := theme.RenderFractionalBar(trackWidth, ratio, lipgloss.NewStyle().Foreground(theme.ColorCyan), m.theme.FindingTimestamp, m.theme.ASCII)
		b.WriteString(bar + "\n\n")

		hint := m.theme.FindingTimestamp.Render("Press any key to enter command center...")
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

	// 2. Telemetry HUD: Tab Bar & Progress Bar
	tabBar := m.renderTabBar(cardWidth)
	statText := fmt.Sprintf("Files Inspected: %s", m.formatNumber(int64(m.smoothFilesScanned)))
	if m.filesPerSec > 0 {
		spark := m.renderSparkline(m.velocitySamples)
		statText += fmt.Sprintf("  │  Velocity: %.0f files/sec [%s]", m.filesPerSec, spark)
	}

	barWidth := cardWidth - lipgloss.Width(statText) - 10
	if barWidth > 15 {
		gauge := m.renderProgressBar(barWidth)
		statText = fmt.Sprintf("%s   %s", gauge, statText)
	}

	telemetryContent := tabBar + "\n" + statText
	b.WriteString(m.theme.CardBox.Width(cardWidth).Render(telemetryContent) + "\n")

	// 3. Center Section: Adaptive Flight Deck vs Compact Stacked
	if cardWidth >= theme.TierStandard { // >= 120 cols: Flight Deck 3-pane layout
		matrixWidth := 36
		feedWidth := cardWidth - matrixWidth - 2
		if feedWidth < 70 {
			feedWidth = 70
			matrixWidth = cardWidth - feedWidth - 2
		}

		maxRows := 6
		if m.height > 28 {
			maxRows = 8
		}
		if m.height > 34 {
			maxRows = 12
		}

		feedInner, _ := m.renderFeedInner(feedWidth, maxRows, true)
		feedBox := m.theme.FlightDeckRightPane.Width(feedWidth).Render(feedInner)

		feedHeight := lipgloss.Height(feedBox)
		matrixBox := m.renderModuleMatrixPane(matrixWidth, feedHeight)

		centerSplit := lipgloss.JoinHorizontal(lipgloss.Top, matrixBox, " ", feedBox)
		b.WriteString(centerSplit + "\n")

		// 4. Bottom Forensic Inspector Dock
		inspectorDock := m.renderInspectorDock(m.SelectedFinding(), cardWidth)
		b.WriteString(inspectorDock + "\n")
	} else {
		// Compact / Narrow Stacked Layout (< 120 cols)
		var modRow strings.Builder
		modRow.WriteString(m.theme.SectionHeader.Render("Active Modules: ") + " ")
		if len(m.moduleOrder) == 0 {
			if yara.IsCompiledIn() {
				modRow.WriteString(m.spinner.View() + " Initializing detection modules & YARA-X rules...")
			} else {
				modRow.WriteString(m.spinner.View() + " Initializing detection modules (native heuristics only)...")
			}
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
						modRow.WriteString(m.theme.BadgeInfo.Render(fmt.Sprintf("%s %s", m.theme.IconSkip(), name)))
					} else if mod.Err != nil || mod.Status == "FAILED" {
						modRow.WriteString(m.theme.BadgeAlert.Render(fmt.Sprintf("%s %s", m.theme.IconCross(), name)))
					} else {
						modRow.WriteString(m.theme.BadgeNotice.Render(fmt.Sprintf("%s %s (%d)", m.theme.IconCheck(), name, mod.Findings)))
					}
				} else {
					modRow.WriteString(fmt.Sprintf("○ %s", name))
				}
			}
		}
		b.WriteString(m.theme.CardBox.Width(cardWidth).Render(modRow.String()) + "\n")

		// Findings Feed Table
		findingsView := m.renderFindingsFeed(cardWidth)
		b.WriteString(findingsView + "\n")
	}

	// 5. Status / Keybinding Footer
	sortLabel := "severity"
	if m.sortBy == sortByArrival {
		sortLabel = "arrival"
	}
	footerText := fmt.Sprintf("%s Tabs   %s Nav   %s Dossier   %s Filter   %s Sort:%s   %s Yank   %s Shortcuts   %s Quit",
		m.theme.KeyHint.Render("[1-5]"),
		m.theme.KeyHint.Render("[j/k]"),
		m.theme.KeyHint.Render("[Enter]"),
		m.theme.KeyHint.Render("[/]"),
		m.theme.KeyHint.Render("[s]"),
		sortLabel,
		m.theme.KeyHint.Render("[p/y/c]"),
		m.theme.KeyHint.Render("[?]"),
		m.theme.KeyHint.Render("[q]"),
	)
	if m.isFiltering {
		footerText = fmt.Sprintf("Search Filter: %s█  (Press [Enter] to apply, [Esc] to cancel)", m.filterQuery)
	} else if m.filterQuery != "" {
		footerText = fmt.Sprintf("Filter: %s (%s Clear)   %s Nav   %s Dossier   %s Yank Cmd",
			m.formatFilterSummary(),
			m.theme.KeyHint.Render("[Esc]"),
			m.theme.KeyHint.Render("[j/k]"),
			m.theme.KeyHint.Render("[Enter]"),
			m.theme.KeyHint.Render("[c]"),
		)
	}
	b.WriteString(m.theme.StatusBar.Width(cardWidth).Render(footerText))

	return m.theme.AppContainer.Render(b.String())
}

// renderTabBar renders the interactive 1-5 filter tabs.
func (m Model) renderTabBar(width int) string {
	alerts, warns, notes := 0, 0, 0
	for _, f := range m.findings {
		switch f.Severity {
		case report.SeverityAlert, report.SeverityCritical:
			alerts++
		case report.SeverityWarning, report.SeverityHigh, report.SeverityMedium:
			warns++
		case report.SeverityNotice, report.SeverityLow, report.SeverityInfo:
			notes++
		}
	}

	tabs := []struct {
		id    int
		label string
	}{
		{0, fmt.Sprintf("1: ALL (%d)", len(m.findings))},
		{1, fmt.Sprintf("2: THREATS (%d)", alerts)},
		{2, fmt.Sprintf("3: ANOMALIES (%d)", warns)},
		{3, fmt.Sprintf("4: NOTICES (%d)", notes)},
		{4, fmt.Sprintf("5: PIPELINE (%d)", len(m.activeModules))},
	}

	var tabItems []string
	for _, tab := range tabs {
		if m.dashboardTab == tab.id {
			tabItems = append(tabItems, m.theme.TabBadgeActive.Render(tab.label))
		} else {
			tabItems = append(tabItems, m.theme.TabBadgeInactive.Render(tab.label))
		}
	}

	return strings.Join(tabItems, " ")
}

// renderModuleMatrixPane renders the execution pipeline matrix for the left pane of the Flight Deck.
func (m Model) renderModuleMatrixPane(width, height int) string {
	var b strings.Builder
	title := fmt.Sprintf("%s EXECUTION PIPELINE", theme.GlyphBrand)
	b.WriteString(m.theme.SectionHeader.Render(title) + "\n\n")

	if len(m.moduleOrder) == 0 {
		msg := "Initializing modules..."
		if yara.IsCompiledIn() {
			msg = "Loading YARA-X rules..."
		}
		b.WriteString(m.theme.ModuleRowPending.Render(m.spinner.View() + " " + msg) + "\n")
	} else {
		innerWidth := width - 4
		if innerWidth < 20 {
			innerWidth = 20
		}
		nameColWidth := innerWidth - 13
		if nameColWidth < 8 {
			nameColWidth = 8
		}

		for _, name := range m.moduleOrder {
			mod := m.activeModules[name]
			var icon, hitsStr, durStr string
			var rowStyle lipgloss.Style

			if mod.Running {
				icon = m.spinner.View()
				rowStyle = m.theme.ModuleRowRunning
				hitsStr = fmt.Sprintf("%2dh", mod.Findings)
				durStr = "..."
			} else if mod.Finished {
				if mod.Status == "NOT IMPLEMENTED" {
					icon = m.theme.IconSkip()
					rowStyle = m.theme.ModuleRowPending
				} else if mod.Err != nil || mod.Status == "FAILED" {
					icon = m.theme.IconCross()
					rowStyle = m.theme.BadgeAlert
				} else {
					icon = theme.GlyphCheck
					rowStyle = m.theme.ModuleRowDone
				}
				hitsStr = fmt.Sprintf("%2dh", mod.Findings)
				if mod.Duration > 0 {
					if mod.Duration < time.Second {
						durStr = fmt.Sprintf("%3dms", mod.Duration.Milliseconds())
					} else {
						durStr = fmt.Sprintf("%4.1fs", mod.Duration.Seconds())
					}
				} else {
					durStr = "  ok"
				}
			} else {
				icon = theme.GlyphUnselected
				rowStyle = m.theme.ModuleRowPending
				hitsStr = " -- "
				durStr = "wait"
			}

			truncName := runewidth.Truncate(name, nameColWidth, "…")
			namePad := nameColWidth - runewidth.StringWidth(truncName)
			if namePad > 0 {
				truncName += strings.Repeat(" ", namePad)
			}

			line := fmt.Sprintf("%s %s %s %s",
				icon,
				rowStyle.Render(truncName),
				m.theme.PillNeutral.Render(hitsStr),
				m.theme.FindingTimestamp.Render(durStr),
			)
			b.WriteString(line + "\n")
		}
	}

	content := b.String()
	box := m.theme.FlightDeckLeftPane.Width(width)
	if height > 0 {
		box = box.Height(height)
	}
	return box.Render(content)
}

// renderInspectorDock renders the bottom forensic inspector dock with detailed provenance and runbook.
func (m Model) renderInspectorDock(sel *report.Finding, width int) string {
	var b strings.Builder

	if sel == nil {
		cleanMsg := fmt.Sprintf("%s SYSTEM BASELINE SECURE — No malicious implants or anomalies detected. Monitoring host integrity...", theme.GlyphClean)
		if m.filterQuery != "" {
			cleanMsg = fmt.Sprintf("◈ Filter active: %s — No finding selected in filtered feed.", m.filterQuery)
		}
		b.WriteString(m.theme.InspectorTitle.Render(fmt.Sprintf("%s FORENSIC INSPECTOR DOCK", theme.GlyphBrand)) + "\n")
		b.WriteString(m.theme.StatValueSafe.Render(cleanMsg))
		return m.theme.InspectorBox.Width(width).Render(b.String())
	}

	report.PopulateFindingDetails(sel)

	// Line 1: Header with Glyph, Severity Badge, Title, Score Meter, and Rule Name
	score := findingScore(*sel)
	if score <= 0 {
		switch sel.Severity {
		case report.SeverityAlert, report.SeverityCritical:
			score = 90
		case report.SeverityWarning, report.SeverityHigh:
			score = 70
		case report.SeverityNotice, report.SeverityMedium:
			score = 35
		default:
			score = 10
		}
	}
	scoreMeter := m.theme.RenderThreatScoreMeter(score, 10)
	header := fmt.Sprintf("%s FORENSIC DOCK: %s %s  %s  •  Rule: %s",
		theme.GlyphBrand,
		m.theme.SeverityBadge(sel.Severity),
		m.theme.InspectorTitle.Render(sel.Title),
		scoreMeter,
		sel.RuleName,
	)
	b.WriteString(header + "\n")

	// Line 2: Target Path & Provenance Metadata
	targetLine := fmt.Sprintf("Target: %s", m.theme.InspectorTarget.Render(sel.Path))
	var metaParts []string
	if sel.Module != "" {
		metaParts = append(metaParts, fmt.Sprintf("Module: %s", sel.Module))
	}
	if sel.EvidenceRecord != nil {
		metaParts = append(metaParts, fmt.Sprintf("Evidence: %s", sel.EvidenceRecord.EvidenceStrength))
	}
	if sel.Confidence != "" {
		metaParts = append(metaParts, fmt.Sprintf("Confidence: %s", sel.Confidence))
	}
	if len(metaParts) > 0 {
		targetLine += "  │  " + m.theme.FindingTimestamp.Render(strings.Join(metaParts, "  •  "))
	}
	b.WriteString(targetLine + "\n")

	// Line 3: Hashes (SHA-256 or MD5)
	sha256 := sel.Hashes["SHA256"]
	if sha256 == "" {
		sha256 = sel.Hashes["MD5"]
	}
	if sha256 != "" {
		b.WriteString(fmt.Sprintf("Digest: %s\n", m.theme.InspectorHash.Render("SHA-256: "+sha256)))
	}

	// Line 4: Actionable Containment Command & Hotkeys
	cmd := ""
	for _, step := range sel.Remediation {
		if strings.Contains(step, "`") {
			start := strings.Index(step, "`")
			end := strings.LastIndex(step, "`")
			if end > start {
				cmd = step[start+1 : end]
				break
			}
		}
	}
	if cmd == "" && len(sel.Remediation) > 0 {
		cmd = sel.Remediation[0]
	}

	if cmd != "" {
		cmdBox := m.theme.InspectorCmd.Render("RUNBOOK [c]: " + cmd)
		b.WriteString(cmdBox + "  " + m.theme.FindingTimestamp.Render("[Enter: Full Dossier  p: Path  y/h: Hash  c: Cmd]"))
	} else if len(sel.MITRE) > 0 {
		mitreText := fmt.Sprintf("MITRE: %s %s (%s)", sel.MITRE[0].Tactic, sel.MITRE[0].Technique, sel.MITRE[0].TechniqueName)
		b.WriteString(m.theme.BadgeNotice.Render(mitreText) + "  " + m.theme.FindingTimestamp.Render("[Enter: Full Dossier  p: Path  y/h: Hash]"))
	} else {
		b.WriteString(m.theme.FindingTimestamp.Render("Press [Enter] for full threat dossier  •  [p] Yank path  •  [y/h] Yank hash"))
	}

	return m.theme.InspectorBox.Width(width).Render(b.String())
}

func (m Model) renderBrandHeader(width int, statusText string) string {
	brandPrefix := "✦ "
	if m.theme.ASCII {
		brandPrefix = "* "
	}
	gradientLogo := m.theme.RenderGradientText(brandPrefix+"A E T H E R", "#0284C7", "#38BDF8", "#F8FAFC")
	title := gradientLogo + "  " + m.theme.BrandTagline.Render(":: DEFENSIVE LINUX THREAT HUNTING ENGINE")

	targetPath := "Root Filesystem (/)"
	if len(m.paths) > 0 {
		targetPath = strings.Join(m.paths, ", ")
		if len(targetPath) > 35 {
			targetPath = "..." + targetPath[len(targetPath)-32:]
		}
	}

	yaraBadge := "[YARA: OFF]"
	if yara.IsCompiledIn() {
		yaraBadge = "[YARA: ON]"
	}

	infoRow := fmt.Sprintf("Host: %s  │  Target: %s  │  Elapsed: %s  │  Workers: %d  │  %s  │  %s",
		m.hostname, targetPath, m.formatDuration(m.elapsed), m.threads, yaraBadge, statusText)

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
	label := "[CLEAN & SECURE]"
	var fillStyle lipgloss.Style

	if alerts > 0 {
		percent = 100
		hasDirect := false
		for _, f := range m.findings {
			if f.Severity == report.SeverityAlert || f.Severity == report.SeverityCritical {
				if (f.EvidenceRecord != nil && f.EvidenceRecord.EvidenceStrength == report.StrengthDirect) ||
					f.Verdict == report.VerdictMalicious ||
					f.Confidence == report.ConfidenceHigh {
					hasDirect = true
					break
				}
			}
		}
		if hasDirect {
			label = "[DIRECT COMPROMISE]"
		} else {
			label = "[CORROBORATED ANOMALY]"
		}
		fillStyle = m.theme.StatValueAlert
	} else if warnings > 0 {
		if warnings > 2 {
			percent = 75
			label = "[CORROBORATED ANOMALY]"
		} else {
			percent = 50
			label = "[CONTEXTUAL SUSPICION]"
		}
		fillStyle = m.theme.StatValueWarn
	} else {
		noticeCount := 0
		for _, f := range m.findings {
			if f.Severity == report.SeverityNotice || f.Severity == report.SeverityLow {
				noticeCount++
			}
		}
		if noticeCount > 0 {
			percent = 25
			label = "[AUDIT NOTICE]"
			fillStyle = m.theme.StatValueNotice
		} else {
			percent = 0
			label = "[CLEAN & SECURE]"
			fillStyle = m.theme.StatValueSafe
		}
	}

	filled := (percent * gaugeWidth) / 100
	empty := gaugeWidth - filled
	if empty < 0 {
		empty = 0
	}

	filledChar := "█"
	emptyChar := "░"
	if m.theme.ASCII {
		filledChar = "#"
		emptyChar = "-"
	}

	bar := fillStyle.Render(strings.Repeat(filledChar, filled)) + m.theme.FindingTimestamp.Render(strings.Repeat(emptyChar, empty))
	return fmt.Sprintf("Threat Level: [%s] %s", bar, fillStyle.Render(label))
}

func (m Model) renderSparkline(samples []float64) string {
	if len(samples) == 0 {
		return "      "
	}
	blocks := []rune{' ', '▂', '▃', '▄', '▅', '▆', '▇', '█'}
	max := 1.0
	for _, v := range samples {
		if v > max {
			max = v
		}
	}
	var b strings.Builder
	for _, v := range samples {
		idx := int((v / max) * 7)
		if idx < 0 {
			idx = 0
		} else if idx > 7 {
			idx = 7
		}
		b.WriteRune(blocks[idx])
	}
	return m.theme.KeyHint.Render(b.String())
}

func (m Model) renderDonutChart(alerts, warnings, notices, safe int) string {
	if m.theme.NoColor {
		return "[DONUT]\n" + fmt.Sprintf("A:%d W:%d S:%d", alerts, warnings, safe)
	}

	total := alerts + warnings + notices + safe
	if total <= 0 {
		total = 1
		safe = 1
	}

	// 8 perimeter segments in clockwise order:
	// 0: Top (▀), 1: Top-Right (▜), 2: Right (▐), 3: Bottom-Right (▟),
	// 4: Bottom (▄), 5: Bottom-Left (▙), 6: Left (▌), 7: Top-Left (▛)
	numAlerts := int(float64(alerts) / float64(total) * 8.0)
	if alerts > 0 && numAlerts == 0 {
		numAlerts = 1
	}
	numWarns := int(float64(warnings) / float64(total) * 8.0)
	if warnings > 0 && numWarns == 0 {
		numWarns = 1
	}
	numNotices := int(float64(notices) / float64(total) * 8.0)
	if notices > 0 && numNotices == 0 {
		numNotices = 1
	}

	// Clamp total non-safe segments to at most 8
	if numAlerts+numWarns+numNotices > 8 {
		overflow := (numAlerts + numWarns + numNotices) - 8
		if numNotices >= overflow {
			numNotices -= overflow
		} else {
			overflow -= numNotices
			numNotices = 0
			if numWarns >= overflow {
				numWarns -= overflow
			} else {
				numWarns = 0
			}
		}
	}

	styles := make([]lipgloss.Style, 8)
	for i := 0; i < 8; i++ {
		if i < numAlerts {
			styles[i] = m.theme.StatValueAlert
		} else if i < numAlerts+numWarns {
			styles[i] = m.theme.StatValueWarn
		} else if i < numAlerts+numWarns+numNotices {
			styles[i] = m.theme.StatValueNotice
		} else {
			styles[i] = m.theme.StatValueSafe
		}
	}

	centerChar := "✓"
	centerStyle := m.theme.StatValueSafe
	if alerts > 0 {
		centerChar = "!"
		centerStyle = m.theme.StatValueAlert
	} else if warnings > 0 {
		centerChar = "?"
		centerStyle = m.theme.StatValueWarn
	} else if notices > 0 {
		centerChar = "*"
		centerStyle = m.theme.StatValueNotice
	}

	r1 := fmt.Sprintf("%s%s%s", styles[7].Render("▛"), styles[0].Render("▀"), styles[1].Render("▜"))
	r2 := fmt.Sprintf("%s%s%s", styles[6].Render("▌"), centerStyle.Render(centerChar), styles[2].Render("▐"))
	r3 := fmt.Sprintf("%s%s%s", styles[5].Render("▙"), styles[4].Render("▄"), styles[3].Render("▟"))

	return fmt.Sprintf("%s\n%s\n%s", r1, r2, r3)
}

func (m Model) renderExecutiveSummaryMatrix(width int, alerts, warnings, notices, infos int, filesScanned int64) string {
	cleanFiles := filesScanned - int64(alerts) - int64(warnings)
	if cleanFiles < 0 {
		cleanFiles = 0
	}

	donut := m.renderDonutChart(alerts, warnings, notices, int(cleanFiles))
	border := lipgloss.RoundedBorder()
	if m.theme.ASCII {
		border = theme.ASCIIBorder
	}

	donutBox := lipgloss.NewStyle().
		Border(border).
		BorderForeground(theme.ColorBorderLit).
		Background(theme.ColorSurface).
		Padding(0, 1).
		Align(lipgloss.Center).
		Render(fmt.Sprintf("%s\n%s", m.theme.KeyHint.Render("DONUT"), donut))

	colWidth := (width - 18) / 3
	if colWidth < 18 {
		colWidth = 18
	}

	maliciousBox := lipgloss.NewStyle().
		Border(border).
		BorderForeground(theme.ColorAlert).
		Background(theme.ColorSurface).
		Padding(0, 1).
		Width(colWidth)

	suspiciousBox := lipgloss.NewStyle().
		Border(border).
		BorderForeground(theme.ColorWarning).
		Background(theme.ColorSurface).
		Padding(0, 1).
		Width(colWidth)

	safeBox := lipgloss.NewStyle().
		Border(border).
		BorderForeground(theme.ColorNotice).
		Background(theme.ColorSurface).
		Padding(0, 1).
		Width(colWidth)

	malText := fmt.Sprintf("%s\n%s\n%s",
		m.theme.StatValueAlert.Render(fmt.Sprintf("%s MALICIOUS (%d)", m.theme.IconAlert(), alerts)),
		m.theme.FindingRowNormal.Render(fmt.Sprintf("%d Confirmed Threat(s)", alerts)),
		m.theme.FindingTimestamp.Render("Backdoors & Implants"),
	)
	if alerts == 0 {
		malText = fmt.Sprintf("%s\n%s\n%s",
			m.theme.StatValueAlert.Render(fmt.Sprintf("%s MALICIOUS (0)", m.theme.IconAlert())),
			m.theme.FindingTimestamp.Render("0 Active Threats"),
			m.theme.FindingTimestamp.Render("No Backdoors Found"),
		)
	}

	suspText := fmt.Sprintf("%s\n%s\n%s",
		m.theme.StatValueWarn.Render(fmt.Sprintf("%s SUSPICIOUS (%d)", m.theme.IconWarn(), warnings+notices)),
		m.theme.FindingRowNormal.Render(fmt.Sprintf("%d Warn / %d Notice", warnings, notices)),
		m.theme.FindingTimestamp.Render("Anomalies / Autostarts"),
	)

	safeText := fmt.Sprintf("%s\n%s\n%s",
		m.theme.StatValueSafe.Render(fmt.Sprintf("%s SAFE ASSETS (%s)", m.theme.IconClean(), m.formatNumber(cleanFiles))),
		m.theme.FindingRowNormal.Render(fmt.Sprintf("%s Files Verified Clean", m.formatNumber(cleanFiles))),
		m.theme.FindingTimestamp.Render("Baseline Intact"),
	)

	cols := lipgloss.JoinHorizontal(lipgloss.Top,
		donutBox, " ",
		maliciousBox.Render(malText), " ",
		suspiciousBox.Render(suspText), " ",
		safeBox.Render(safeText),
	)

	return cols
}

func formatPathCol(p string, width int) string {
	w := runewidth.StringWidth(p)
	if w <= width {
		return p + strings.Repeat(" ", width-w)
	}
	if width <= 12 {
		return runewidth.Truncate(p, width, "…")
	}
	base := filepath.Base(p)
	baseW := runewidth.StringWidth(base)
	if baseW+8 <= width {
		prefixW := width - baseW - 5
		if prefixW < 3 {
			prefixW = 3
		}
		prefix := runewidth.Truncate(p, prefixW, "")
		res := fmt.Sprintf("%s.../%s", prefix, base)
		pad := width - runewidth.StringWidth(res)
		if pad > 0 {
			res += strings.Repeat(" ", pad)
		}
		return res
	}
	tailLen := width - 3
	tail := ""
	if tailLen > 0 && len(p) >= tailLen {
		tail = p[len(p)-tailLen:]
	}
	res := "..." + tail
	pad := width - runewidth.StringWidth(res)
	if pad > 0 {
		res += strings.Repeat(" ", pad)
	}
	return res
}

// splitPaneMinWidth is the total width at which the findings feed and threat
// preview attempt a side-by-side split instead of stacked sections.
const splitPaneMinWidth = 110

// Feed table floors: how much room the path and reason columns need before
// rows wrap and break the table grid. The compact variant is used by the
// split-pane layout, where the feed shares width with the preview.
const (
	feedTableFixedOverhead = 40
	compactMinInnerWidth   = feedTableFixedOverhead + 12 + 10 // 62
	normalMinInnerWidth    = feedTableFixedOverhead + 18 + 14 // 72
)

func (m Model) renderFindingsFeed(width int) string {
	sel := m.SelectedFinding()

	// Decide whether the wide side-by-side layout fits: the feed pane must
	// hold the compact table without wrapping.
	splitPane := false
	feedWidth, previewWidth := 0, 0
	if sel != nil && width >= splitPaneMinWidth {
		feedWidth = width * 62 / 100
		if feedWidth-6 >= compactMinInnerWidth {
			previewWidth = width - feedWidth
			splitPane = true
		}
	}

	maxVisible := 5
	if m.height > 26 {
		maxVisible = 7
	}
	if splitPane && m.height > 30 {
		// The split pane reclaims the vertical space the stacked preview
		// used to consume, so show more feed rows when the window allows.
		maxVisible = 10
	}

	feedInner, _ := m.renderFeedInner(width, maxVisible, false)

	if !splitPane {
		feedBox := m.theme.CardBox.Width(width).Render(feedInner)
		if sel == nil {
			return feedBox
		}
		previewInner, _ := m.previewContent(sel, width)
		previewBox := m.theme.CardActive.Width(width).Render(previewInner)
		return feedBox + "\n" + previewBox
	}

	narrowInner, _ := m.renderFeedInner(feedWidth, maxVisible, true)
	previewInner, _ := m.previewContent(sel, previewWidth)

	// Measure the true rendered height of each pane's content (including any
	// wrapped lines) so the bordered boxes bottom-align regardless of wrap
	// behavior inside either pane.
	feedMeasure := lipgloss.NewStyle().Width(feedWidth).Render(narrowInner)
	previewMeasure := lipgloss.NewStyle().Width(previewWidth).Render(previewInner)
	paneHeight := lipgloss.Height(feedMeasure)
	if h := lipgloss.Height(previewMeasure); h > paneHeight {
		paneHeight = h
	}

	feedBox := m.theme.CardBox.Width(feedWidth).Height(paneHeight).Render(narrowInner)
	previewBox := m.theme.CardActive.Width(previewWidth).Height(paneHeight).Render(previewInner)
	return lipgloss.JoinHorizontal(lipgloss.Top, feedBox, previewBox)
}

// renderFeedInner renders the findings feed content (section header, table
// header, and the visible row window) and reports its rendered line count.
// In compact mode (split-pane layout) the path and reason column floors
// shrink so the full table still fits inside the narrower feed pane.
func (m Model) renderFeedInner(width, maxVisible int, compact bool) (string, int) {
	list := m.currentList()

	var b strings.Builder
	header := fmt.Sprintf("Findings Feed (%d total", len(m.findings))
	if m.filterQuery != "" {
		header += fmt.Sprintf(", %d matched filter %q", len(list), m.filterQuery)
	} else {
		switch m.sortBy {
		case sortBySeverity:
			header += " · worst-first"
		case sortByArrival:
			header += " · arrival order"
		}
	}
	header += "):"
	b.WriteString(m.theme.SectionHeader.Render(header) + "\n\n")

	if len(list) == 0 {
		if m.filterQuery != "" {
			b.WriteString(m.theme.StatValueSafe.Render(fmt.Sprintf("  No findings match filter %q. Press [Esc] to clear the query.", m.filterQuery)) + "\n")
		} else {
			b.WriteString(m.theme.StatValueSafe.Render("  ✓ No security indicators or anomalies detected. All inspected files verified clean.") + "\n")
		}
		return b.String(), strings.Count(b.String(), "\n")
	}

	// Calculate inner usable width inside CardBox (accounting for borders and padding)
	innerWidth := width - 6
	if innerWidth < 64 {
		innerWidth = 64
	}

	// Dynamic column layout
	// prefix: 2 | badge: 9 | space: 1 | ts: 8 | div1: 3 | mod: 11 | div2: 3 | div3: 3 = 40 runes
	fixedOverhead := feedTableFixedOverhead
	availForPathReason := innerWidth - fixedOverhead
	if availForPathReason < 24 {
		availForPathReason = 24
	}

	// Column floors adapt to the layout: the split-pane feed pane is compact
	// (path 12 / reason 10), the full-width stacked layout gets roomier ones.
	minPath, minReason := 18, 14
	if compact {
		minPath, minReason = 12, 10
	}

	pathWidth := availForPathReason * 42 / 100
	if pathWidth < minPath {
		pathWidth = minPath
	}
	reasonWidth := availForPathReason - pathWidth
	if reasonWidth < minReason {
		reasonWidth = minReason
	}

	// Table Column Header row
	div := m.theme.Divider.Render("│")
	tblHeader := fmt.Sprintf("  %s %s %s %-11s %s %-*s %s %-*s",
		m.theme.TableHead.Render("SEVERITY "),
		m.theme.TableHead.Render("  TIME  "),
		div,
		m.theme.TableHead.Render("MODULE"),
		div,
		pathWidth, m.theme.TableHead.Render(runewidth.Truncate("TARGET PATH", pathWidth, "…")),
		div,
		reasonWidth, m.theme.TableHead.Render(runewidth.Truncate("OBSERVED EVIDENCE / DETAILS", reasonWidth, "…")),
	)
	b.WriteString(tblHeader + "\n")
	sepLine := strings.Repeat("─", innerWidth)
	b.WriteString(m.theme.Divider.Render(sepLine) + "\n")

	// Vertical window is computed by the caller (stacked vs split-pane layouts
	// expose different amounts of vertical room for the feed).
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
			if m.theme.ASCII {
				prefix = m.theme.ActiveRail.Render("> ")
			} else {
				prefix = m.theme.ActiveRail.Render(theme.GlyphActiveRail + " ")
			}
		}

		pathStr := formatPathCol(f.Path, pathWidth)
		reasonStr := runewidth.Truncate(f.Reason, reasonWidth, "…")
		reasonPad := reasonWidth - runewidth.StringWidth(reasonStr)
		if reasonPad > 0 {
			reasonStr += strings.Repeat(" ", reasonPad)
		}

		line := fmt.Sprintf("%s%s %s %s %-11s %s %s %s %s",
			prefix,
			badge,
			m.theme.FindingTimestamp.Render(ts),
			div,
			m.theme.FindingModule.Render(runewidth.Truncate(f.Module, 11, "")),
			div,
			m.theme.FindingPath.Render(pathStr),
			div,
			m.theme.FindingReason.Render(reasonStr),
		)

		if i == m.selectedIndex {
			b.WriteString(m.theme.FindingRowSelected.Render(line) + "\n")
		} else {
			b.WriteString(m.theme.FindingRowNormal.Render(line) + "\n")
		}
	}

	return b.String(), strings.Count(b.String(), "\n")
}

// previewContent renders the live quick-preview body for the selected finding
// and reports its rendered line count.
func (m Model) previewContent(sel *report.Finding, width int) (string, int) {
	report.PopulateFindingDetails(sel)

	textWidth := width - 20
	if textWidth < 12 {
		textWidth = 12
	}

	var p strings.Builder
	pTitle := fmt.Sprintf("%s THREAT PREVIEW  •  %s  %s", theme.GlyphBrand, m.theme.SeverityBadge(sel.Severity), m.theme.BrandTitle.Render(sel.Title))
	p.WriteString(pTitle + "\n")

	p.WriteString(fmt.Sprintf("  %s %s\n",
		m.theme.ModalFieldKey.Render("Target File: "),
		m.theme.FindingPath.Render(sel.Path),
	))

	var metaTokens []string
	if score := findingScore(*sel); score > 0 {
		metaTokens = append(metaTokens, fmt.Sprintf("Score: %d/100", score))
	}
	if len(sel.MITRE) > 0 {
		metaTokens = append(metaTokens, fmt.Sprintf("MITRE: %s", sel.MITRE[0].Technique))
	}
	if sel.ConfidenceRationale != "" {
		metaTokens = append(metaTokens, sel.ConfidenceRationale)
	}
	if len(metaTokens) > 0 {
		p.WriteString(fmt.Sprintf("  %s %s\n",
			m.theme.ModalFieldKey.Render("Attributes:  "),
			m.theme.KeyHint.Render(runewidth.Truncate(strings.Join(metaTokens, "  │  "), textWidth, "…")),
		))
	}

	if sel.Why != "" {
		whyText := runewidth.Truncate(sel.Why, textWidth, "…")
		p.WriteString(fmt.Sprintf("  %s %s\n",
			m.theme.ModalFieldKey.Render("Assessment:  "),
			m.theme.FindingRowNormal.Render(whyText),
		))
	}
	if len(sel.Remediation) > 0 {
		remText := runewidth.Truncate(sel.Remediation[0], textWidth, "…")
		p.WriteString(fmt.Sprintf("  %s %s\n",
			m.theme.ModalFieldKey.Render("Containment: "),
			m.theme.FindingReason.Render(remText),
		))
	}
	p.WriteString("  " + m.theme.ModalFieldKey.Render("Actions:     ") +
		m.theme.KeyHint.Render("[Enter]") + m.theme.FindingReason.Render(" Dossier  •  ") +
		m.theme.KeyHint.Render("[y]") + m.theme.FindingReason.Render(" Path  •  ") +
		m.theme.KeyHint.Render("[h]") + m.theme.FindingReason.Render(" Hash  •  ") +
		m.theme.KeyHint.Render("[r]") + m.theme.FindingReason.Render(" Runbook  •  ") +
		m.theme.KeyHint.Render("[n/N]") + m.theme.FindingReason.Render(" Alert  •  ") +
		m.theme.KeyHint.Render("[?]") + m.theme.FindingReason.Render(" Shortcuts"))

	return p.String(), strings.Count(p.String(), "\n")
}

func (m Model) renderDetailModal() string {
	f := m.SelectedFinding()
	if f == nil {
		return m.renderDashboard()
	}

	report.PopulateFindingDetails(f)

	modalWidth := 78
	if m.width > 86 {
		modalWidth = m.width - 8
	}
	if modalWidth > 100 {
		modalWidth = 100
	}

	var b strings.Builder
	badge := m.theme.SeverityBadge(f.Severity)
	title := fmt.Sprintf("%s FORENSIC THREAT DOSSIER :: %s %s", theme.GlyphBrand, badge, f.Title)
	b.WriteString(m.theme.ModalHeader.Render(title) + "\n\n")

	// Render Tab Navigation Bar
	tabTitles := []string{"[1] Assessment", "[2] Artifact", "[3] MITRE ATT&CK", "[4] Remediation"}
	var tabsRow strings.Builder
	for i, tTitle := range tabTitles {
		if i == m.activeTab {
			tabsRow.WriteString(m.theme.TabActive.Render(" "+tTitle+" ") + "  ")
		} else {
			tabsRow.WriteString(m.theme.TabInactive.Render(" "+tTitle+" ") + "  ")
		}
	}
	b.WriteString(tabsRow.String() + "\n\n")

	// Render Active Tab Content into buffer for scrollable viewport
	var content strings.Builder
	switch m.activeTab {
	case 0: // Assessment
		content.WriteString(m.theme.SubSectionHeader.Render("EXECUTIVE THREAT ASSESSMENT & REASONING") + "\n")
		content.WriteString(fmt.Sprintf("%s %s\n", m.theme.ModalFieldKey.Render("Detection Rule:"), f.RuleName))
		content.WriteString(fmt.Sprintf("%s %s\n", m.theme.ModalFieldKey.Render("Security Module:"), f.Module))
		content.WriteString(fmt.Sprintf("%s %s  │  %s %s (Confidence: %s)\n",
			m.theme.ModalFieldKey.Render("Alert Severity:"), f.Severity,
			m.theme.ModalFieldKey.Render("Verdict:"), f.Verdict, f.Confidence))
		if f.ConfidenceRationale != "" {
			content.WriteString(fmt.Sprintf("%s %s\n", m.theme.ModalFieldKey.Render("Rationale:     "), f.ConfidenceRationale))
		}
		if f.EvidenceRecord != nil && len(f.EvidenceRecord.ContributingDetectors) > 0 {
			content.WriteString(fmt.Sprintf("%s %s\n", m.theme.ModalFieldKey.Render("Corroboration: "), strings.Join(f.EvidenceRecord.ContributingDetectors, ", ")))
		}
		if f.Why != "" {
			content.WriteString(fmt.Sprintf("\n%s\n%s\n", m.theme.ModalFieldKey.Render("Why This Pattern Is Dangerous:"), f.Why))
		}

	case 1: // Artifact Details
		content.WriteString(m.theme.SubSectionHeader.Render("FORENSIC ARTIFACT & HOST EVIDENCE") + "\n")
		content.WriteString(fmt.Sprintf("%s %s\n", m.theme.ModalFieldKey.Render("Target File Path:"), f.Path))
		content.WriteString(fmt.Sprintf("%s %s\n", m.theme.ModalFieldKey.Render("Detection Time:  "), f.Timestamp.Format(time.RFC3339)))
		if f.EvidenceRecord != nil {
			content.WriteString(fmt.Sprintf("%s %s  │  %s %s\n",
				m.theme.ModalFieldKey.Render("Package Status:  "), f.EvidenceRecord.PackageStatus,
				m.theme.ModalFieldKey.Render("Context Profile:"), f.EvidenceRecord.ContextProfile))
		}
		if f.Evidence != "" {
			content.WriteString(fmt.Sprintf("\n%s\n  %s\n", m.theme.ModalFieldKey.Render("Matched Evidence:"), f.Evidence))
		}
		if len(f.Hashes) > 0 {
			content.WriteString(fmt.Sprintf("\n%s\n", m.theme.ModalFieldKey.Render("Cryptographic Hashes:")))
			for k, v := range f.Hashes {
				content.WriteString(fmt.Sprintf("  • %-8s %s\n", k+":", v))
			}
		}

	case 2: // MITRE ATT&CK
		content.WriteString(m.theme.SubSectionHeader.Render("MITRE ATT&CK FRAMEWORK CLASSIFICATION") + "\n")
		if len(f.MITRE) == 0 {
			content.WriteString("  No MITRE ATT&CK techniques mapped to this finding.\n")
		} else {
			for _, mit := range f.MITRE {
				content.WriteString(fmt.Sprintf("  • %s %s :: %s\n",
					m.theme.KeyHint.Render("["+mit.Technique+"]"),
					m.theme.ModalFieldKey.Render(mit.Tactic),
					mit.TechniqueName))
			}
		}

	case 3: // Remediation Plan
		content.WriteString(m.theme.SubSectionHeader.Render("RECOMMENDED CONTAINMENT & REMEDIATION PLAN") + "\n")
		if len(f.Remediation) == 0 {
			content.WriteString("  No specific remediation steps required for this finding.\n")
		} else {
			for idx, step := range f.Remediation {
				content.WriteString(fmt.Sprintf("  %d. %s\n", idx+1, step))
			}
		}
	}

	// Viewport window calculation
	lines := strings.Split(content.String(), "\n")
	maxVisible := m.height - 12
	if maxVisible < 5 {
		maxVisible = 5
	}

	scrollY := m.modalScrollY
	if scrollY > len(lines)-maxVisible {
		scrollY = len(lines) - maxVisible
	}
	if scrollY < 0 {
		scrollY = 0
	}

	visibleEnd := scrollY + maxVisible
	if visibleEnd > len(lines) {
		visibleEnd = len(lines)
	}

	for i := scrollY; i < visibleEnd; i++ {
		b.WriteString(lines[i] + "\n")
	}

	if len(lines) > maxVisible {
		scrollIndicator := fmt.Sprintf("▲ [Scroll: Line %d-%d of %d  •  Use j/k, PgUp/PgDn, g/G] ▼",
			scrollY+1, visibleEnd, len(lines))
		b.WriteString(m.theme.KeyHint.Render(scrollIndicator) + "\n")
	} else {
		b.WriteString("\n")
	}

	footer := fmt.Sprintf("%s Tab   %s Scroll   %s Path   %s Hash   %s Cmd   %s Close",
		m.theme.KeyHint.Render("[Tab/1-4]"),
		m.theme.KeyHint.Render("[j/k]"),
		m.theme.KeyHint.Render("[y]"),
		m.theme.KeyHint.Render("[h]"),
		m.theme.KeyHint.Render("[c]"),
		m.theme.KeyHint.Render("[Esc]"),
	)
	b.WriteString(m.theme.FindingTimestamp.Render(footer))

	box := m.theme.ModalBox.Width(modalWidth).Render(b.String())
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
}

// renderQuitConfirm renders the guarded-quit confirmation shown while a scan
// is still in flight and [q] was pressed.
func (m Model) renderQuitConfirm() string {
	w := 64
	if m.width > 80 {
		w = m.width - 20
	}
	if w > 72 {
		w = 72
	}

	var b strings.Builder
	b.WriteString(m.theme.ModalHeader.Render("◆  SCAN IN PROGRESS — ABORT?") + "\n\n")
	b.WriteString(m.theme.FindingRowNormal.Render("Quitting now stops all detection modules mid-flight.") + "\n")
	b.WriteString(m.theme.FindingRowNormal.Render("Findings gathered so far stay on screen but no final") + "\n")
	b.WriteString(m.theme.FindingRowNormal.Render("report is written.") + "\n\n")
	b.WriteString("\n" + m.theme.KeyHint.Render("[y]") + m.theme.FindingReason.Render(" Abort & quit      ") +
		m.theme.KeyHint.Render("[n]") + m.theme.FindingReason.Render(" Continue scanning      ") +
		m.theme.KeyHint.Render("[Esc]") + m.theme.FindingReason.Render(" Continue"))

	box := m.theme.CommandPalette.Width(w).Render(b.String())
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
}

func (m Model) renderCommandPalette() string {
	w := 78
	if m.width > 86 {
		w = m.width - 8
	}
	if w > 94 {
		w = 94
	}

	var b strings.Builder
	b.WriteString(m.theme.ModalHeader.Render("◈  AETHER FORENSIC COMMAND CENTER") + "\n\n")

	// Search Input Box
	searchPrompt := fmt.Sprintf("  ◈ Filter Actions: %s█", m.paletteQuery)
	b.WriteString(m.theme.SubSectionHeader.Render(searchPrompt) + "\n\n")

	actions := m.getFilteredPaletteActions()
	if len(actions) == 0 {
		b.WriteString(m.theme.FindingRowNormal.Render("  No matching actions found. Use backspace to widen search query.") + "\n")
	} else {
		maxItems := 10
		if len(actions) < maxItems {
			maxItems = len(actions)
		}
		for i := 0; i < maxItems; i++ {
			act := actions[i]
			paddedKey := runewidth.FillRight(act.Key, 14)
			line := fmt.Sprintf("  %s %s — %s", m.theme.KeyHint.Render(paddedKey), act.Title, act.Description)
			if i == m.paletteSelectedIndex {
				b.WriteString(m.theme.FindingRowSelected.Render("▶ " + line) + "\n")
			} else {
				b.WriteString("  " + line + "\n")
			}
		}
		if len(actions) > maxItems {
			b.WriteString(m.theme.FindingTimestamp.Render(fmt.Sprintf("  ... and %d more actions (use ↓ to scroll)", len(actions)-maxItems)) + "\n")
		}
	}

	b.WriteString("\n" + m.theme.KeyHint.Render("[Enter] Execute  [↑/↓] Navigate  [Type] Filter  [Esc/?] Dismiss"))

	box := m.theme.CommandPalette.Width(w).Render(b.String())
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
		if cov.TotalEligible() > 0 {
			coverageSuffix = fmt.Sprintf(" [PARTIAL AUDIT: %.1f%% (%s / %s files)]",
				cov.CoveragePercentage(),
				m.formatNumber(cov.FilesScanned),
				m.formatNumber(cov.TotalEligible()),
			)
		} else {
			coverageSuffix = " (PARTIAL COVERAGE)"
		}
	} else if cov.TotalEligible() > 0 {
		coverageSuffix = fmt.Sprintf(" [COVERAGE: %.1f%% (%s / %s files)]",
			cov.CoveragePercentage(),
			m.formatNumber(cov.FilesScanned),
			m.formatNumber(cov.TotalEligible()),
		)
	}

	var verdictBanner string
	switch {
	case verdict == events.VerdictCompromised || alerts > 0:
		riskGauge := m.renderRiskGauge(cardWidth, alerts, warnings)
		verdictBanner = m.theme.VerdictCompromised.Width(cardWidth).Render(
			fmt.Sprintf("%s VERDICT: SYSTEM COMPROMISED%s\nActive threats or high-confidence compromise indicators detected (%d MALICIOUS ALERT(S)).\n%s", m.theme.IconAlert(), coverageSuffix, alerts, riskGauge),
		)
	case verdict == events.VerdictSuspicious || warnings > 0 || notices > 0:
		riskGauge := m.renderRiskGauge(cardWidth, alerts, warnings)
		verdictBanner = m.theme.VerdictSuspicious.Width(cardWidth).Render(
			fmt.Sprintf("%s VERDICT: SUSPICIOUS ANOMALIES IDENTIFIED%s\nSecurity anomalies or unverified persistence hooks detected (%d Warnings, %d Notices).\n%s", m.theme.IconWarn(), coverageSuffix, warnings, notices, riskGauge),
		)
	default:
		riskGauge := m.renderRiskGauge(cardWidth, 0, 0)
		verdictBanner = m.theme.VerdictClean.Width(cardWidth).Render(
			fmt.Sprintf("%s VERDICT: SYSTEM CLEAN & SECURE%s\nNo known indicators of compromise, backdoors, webshells, or anomalous artifacts identified.\n%s", m.theme.IconClean(), coverageSuffix, riskGauge),
		)
	}
	b.WriteString(verdictBanner + "\n")

	// 3. 3-Column Executive Summary Matrix Card
	summaryMatrix := m.renderExecutiveSummaryMatrix(cardWidth, alerts, warnings, notices, infos, m.filesScanned)
	b.WriteString(summaryMatrix + "\n")

	// 4. Detailed Telemetry & Coverage Card
	var stats strings.Builder
	titleTelemetry := "◈  F O R E N S I C   T E L E M E T R Y   &   A U D I T   M E T R I C S"
	if m.theme.ASCII {
		titleTelemetry = "[STATS] FORENSIC TELEMETRY & AUDIT METRICS"
	}
	stats.WriteString(m.theme.SectionHeader.Render(titleTelemetry) + "\n\n")

	// Row 1: Primary Metrics Badges with spacious breathing room
	covText := fmt.Sprintf(" %s %s Inspected ", m.theme.IconFile(), m.formatNumber(m.filesScanned))
	if cov.TotalEligible() > 0 {
		covText = fmt.Sprintf(" %s Coverage: %.1f%% (%s / %s) ",
			m.theme.IconFile(),
			cov.CoveragePercentage(),
			m.formatNumber(cov.FilesScanned),
			m.formatNumber(cov.TotalEligible()),
		)
	}
	metricsRow := fmt.Sprintf("  %s   %s   %s   %s   %s   %s",
		m.theme.PillNeutral.Render(covText),
		m.theme.PillNeutral.Render(fmt.Sprintf(" %s %s Elapsed ", m.theme.IconTime(), m.formatDuration(m.elapsed))),
		m.theme.PillAlert.Render(fmt.Sprintf(" %s %d Alerts ", m.theme.IconAlert(), alerts)),
		m.theme.PillWarn.Render(fmt.Sprintf(" %s %d Warnings ", m.theme.IconWarn(), warnings)),
		m.theme.PillNotice.Render(fmt.Sprintf(" %s %d Notices ", m.theme.IconNotice(), notices)),
		m.theme.PillInfo.Render(fmt.Sprintf(" %s %d Infos ", m.theme.IconInfo(), infos)),
	)
	stats.WriteString(metricsRow + "\n")

	// Row 2: Clean Skipped Breakdown (only show non-zero items)
	if cov.TotalSkipped() > 0 {
		var skippedParts []string
		if cov.SkippedPermission > 0 {
			skippedParts = append(skippedParts, fmt.Sprintf("%d Perm Denied", cov.SkippedPermission))
		}
		if cov.SkippedOversize > 0 {
			skippedParts = append(skippedParts, fmt.Sprintf("%d Oversize", cov.SkippedOversize))
		}
		if cov.SkippedNotRegular > 0 {
			skippedParts = append(skippedParts, fmt.Sprintf("%d Non-Regular", cov.SkippedNotRegular))
		}
		if cov.SkippedExcluded > 0 {
			skippedParts = append(skippedParts, fmt.Sprintf("%d Excluded", cov.SkippedExcluded))
		}
		if cov.SkippedVanished > 0 {
			skippedParts = append(skippedParts, fmt.Sprintf("%d Vanished", cov.SkippedVanished))
		}
		stats.WriteString(fmt.Sprintf("\n  %s %s: %s\n",
			m.theme.FindingTimestamp.Render(m.theme.IconSkip()),
			m.theme.FindingTimestamp.Render(fmt.Sprintf("Skipped (%d)", cov.TotalSkipped())),
			m.theme.FindingTimestamp.Render(strings.Join(skippedParts, "  •  ")),
		))
	}

	// YARA Engine Status
	if m.finishEvent != nil && m.finishEvent.YARAActive {
		yCov := m.finishEvent.YARACoverage
		rulesCount := 0
		filesCount := int64(0)
		if yCov != nil {
			rulesCount = yCov.RulesLoaded
			filesCount = yCov.FilesScanned
		}
		stats.WriteString(fmt.Sprintf("\n  %s %s\n",
			m.theme.FindingTimestamp.Render(m.theme.IconBolt()),
			m.theme.FindingTimestamp.Render(fmt.Sprintf("Detection Engine: YARA-X ACTIVE (%d Rules Loaded  •  %d Files Evaluated)", rulesCount, filesCount)),
		))
	} else {
		stats.WriteString(fmt.Sprintf("\n  %s %s\n",
			m.theme.FindingTimestamp.Render(m.theme.IconBolt()),
			m.theme.FindingTimestamp.Render("Detection Engine: Pure-Go Native Heuristics Only (YARA-X Disabled / CGO-Free)"),
		))
	}

	// Row 3: Curated Top Triggered Rules with Proportional Horizontal Bars
	if m.finishEvent != nil && len(m.finishEvent.TopRules) > 0 {
		stats.WriteString(m.renderTopRulesBars(cardWidth, m.finishEvent.TopRules))
	}
	b.WriteString(m.theme.CardBox.Width(cardWidth).Render(stats.String()) + "\n")

	// 5. Findings Feed Table + Live Preview
	b.WriteString(m.renderFindingsFeed(cardWidth) + "\n")

	// 6. Navigation Footer
	footerText := fmt.Sprintf("%s Nav   %s Dossier   %s Filter   %s Yank   %s Shortcuts   %s Exit",
		m.theme.KeyHint.Render("[j/k]"),
		m.theme.KeyHint.Render("[Enter]"),
		m.theme.KeyHint.Render("[/]"),
		m.theme.KeyHint.Render("[y/h/c]"),
		m.theme.KeyHint.Render("[?]"),
		m.theme.KeyHint.Render("[q]"),
	)
	if m.isFiltering {
		footerText = fmt.Sprintf("Search Filter: %s█  (Press [Enter] to apply, [Esc] to cancel)", m.filterQuery)
	} else if m.filterQuery != "" {
		footerText = fmt.Sprintf("Filter: %s (%s Clear)   %s Nav   %s Dossier   %s Yank Cmd",
			m.formatFilterSummary(),
			m.theme.KeyHint.Render("[Esc]"),
			m.theme.KeyHint.Render("[j/k]"),
			m.theme.KeyHint.Render("[Enter]"),
			m.theme.KeyHint.Render("[c]"),
		)
	}
	b.WriteString(m.theme.StatusBar.Width(cardWidth).Render(footerText))

	return m.theme.AppContainer.Render(b.String())
}

// formatFilterSummary formats active filter chips and search terms for status bar presentation.
func (m Model) formatFilterSummary() string {
	qf := ParseQueryFilter(m.filterQuery)
	var parts []string
	if qf.Severity != "" {
		parts = append(parts, m.theme.StatValueAlert.Render("[SEV:"+strings.ToUpper(qf.Severity)+"]"))
	}
	if qf.Module != "" {
		parts = append(parts, m.theme.StatValueWarn.Render("[MOD:"+strings.ToUpper(qf.Module)+"]"))
	}
	if qf.Path != "" {
		parts = append(parts, m.theme.StatValueNotice.Render("[PATH:"+qf.Path+"]"))
	}
	if qf.Rule != "" {
		parts = append(parts, m.theme.StatValueNotice.Render("[RULE:"+qf.Rule+"]"))
	}
	if qf.FreeText != "" {
		parts = append(parts, fmt.Sprintf("%q", qf.FreeText))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%q", m.filterQuery)
	}
	return strings.Join(parts, " ")
}

func (m Model) renderProgressBar(width int) string {
	if width < 5 {
		return ""
	}
	progressRatio := 0.0
	totalMods := len(m.moduleOrder)
	if totalMods > 0 {
		completed := 0
		for _, mod := range m.activeModules {
			if mod.Finished {
				completed++
			}
		}
		progressRatio = float64(completed) / float64(totalMods)
	}
	if m.scanFinished {
		progressRatio = 1.0
	}

	trackWidth := width - 7
	if trackWidth < 5 {
		trackWidth = 5
	}

	if m.theme.ASCII {
		filled := int(progressRatio * float64(trackWidth))
		if filled > trackWidth {
			filled = trackWidth
		}
		var b strings.Builder
		for i := 0; i < filled; i++ {
			if i == filled-1 && filled < trackWidth {
				b.WriteByte('>')
			} else {
				b.WriteByte('=')
			}
		}
		for i := filled; i < trackWidth; i++ {
			b.WriteByte(' ')
		}
		gaugeStyle := m.theme.StatValueNotice
		return fmt.Sprintf("[%s %3.0f%%]", gaugeStyle.Render(b.String()), progressRatio*100)
	}

	bar := theme.RenderFractionalBar(trackWidth, progressRatio, m.theme.StatValueNotice, m.theme.FindingTimestamp, false)
	return fmt.Sprintf("[%s %3.0f%%]", bar, progressRatio*100)
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

// formatRuleShortName trims noisy prefixes to provide clean rule identification.
func formatRuleShortName(ruleName string) string {
	shortName := ruleName
	shortName = strings.TrimPrefix(shortName, "Persistence_System_")
	shortName = strings.TrimPrefix(shortName, "Persistence_")
	shortName = strings.TrimPrefix(shortName, "Script_")
	shortName = strings.TrimPrefix(shortName, "Process_")
	shortName = strings.TrimPrefix(shortName, "Linux_")
	return shortName
}

// renderTopRulesBars renders curated top triggered detection rules with responsive layout
// and proportional horizontal mini-bars.
func (m Model) renderTopRulesBars(cardWidth int, topRules []report.RuleSummary) string {
	if len(topRules) == 0 {
		return ""
	}
	var sb strings.Builder
	title := "🏷️ Top Detections:"
	if m.theme.ASCII {
		title = "[TOP] Top Detections:"
	}
	sb.WriteString(fmt.Sprintf("\n  %s  ", m.theme.SubSectionHeader.Render(title)))

	if cardWidth < theme.TierCompact {
		// Compact tier: render as compact horizontal chips
		maxRules := 3
		displayed := 0
		for idx, tr := range topRules {
			if idx >= maxRules {
				break
			}
			shortName := formatRuleShortName(tr.RuleName)
			chip := m.theme.PillNeutral.Render(fmt.Sprintf("[%s: %d]", shortName, tr.Count))
			sb.WriteString(chip + " ")
			displayed++
		}
		if len(topRules) > displayed {
			remaining := len(topRules) - displayed
			sb.WriteString(m.theme.FindingTimestamp.Render(fmt.Sprintf("(+%d more)", remaining)))
		}
		sb.WriteString("\n")
		return sb.String()
	}

	// Standard (80-110) or Wide (>110) tier: proportional horizontal mini-bars
	sb.WriteString("\n")
	maxRules := 4
	if cardWidth > theme.TierStandard {
		maxRules = 6
	}
	if len(topRules) < maxRules {
		maxRules = len(topRules)
	}

	maxCount := 1
	for i := 0; i < maxRules; i++ {
		if topRules[i].Count > maxCount {
			maxCount = topRules[i].Count
		}
	}

	barMaxLen := 20
	if cardWidth > theme.TierStandard {
		barMaxLen = 30
	} else if cardWidth < 90 {
		barMaxLen = 14
	}

	fillChar := '█'
	emptyChar := '░'
	bullet := "•"
	if m.theme.ASCII {
		fillChar = '#'
		emptyChar = '-'
		bullet = "*"
	}

	for i := 0; i < maxRules; i++ {
		tr := topRules[i]
		shortName := formatRuleShortName(tr.RuleName)
		if len(shortName) > 22 {
			shortName = shortName[:19] + "..."
		}

		filledLen := int(float64(tr.Count) / float64(maxCount) * float64(barMaxLen))
		if filledLen < 1 && tr.Count > 0 {
			filledLen = 1
		}
		if filledLen > barMaxLen {
			filledLen = barMaxLen
		}
		emptyLen := barMaxLen - filledLen

		var barFilled string
		switch tr.Severity {
		case report.SeverityAlert:
			barFilled = m.theme.StatValueAlert.Render(strings.Repeat(string(fillChar), filledLen))
		case report.SeverityWarning:
			barFilled = m.theme.StatValueWarn.Render(strings.Repeat(string(fillChar), filledLen))
		case report.SeverityNotice:
			barFilled = m.theme.StatValueNotice.Render(strings.Repeat(string(fillChar), filledLen))
		default:
			barFilled = m.theme.PillInfo.Render(strings.Repeat(string(fillChar), filledLen))
		}
		barEmpty := m.theme.FindingTimestamp.Render(strings.Repeat(string(emptyChar), emptyLen))

		sb.WriteString(fmt.Sprintf("  %s %-22s %s%s %s\n",
			m.theme.FindingTimestamp.Render(bullet),
			shortName,
			barFilled,
			barEmpty,
			m.theme.FindingTimestamp.Render(fmt.Sprintf("(%d)", tr.Count)),
		))
	}

	if len(topRules) > maxRules {
		remaining := len(topRules) - maxRules
		sb.WriteString(fmt.Sprintf("    %s\n", m.theme.FindingTimestamp.Render(fmt.Sprintf("(+%d additional detection rules)", remaining))))
	}

	return sb.String()
}
