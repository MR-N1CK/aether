package htmlreport

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aether/internal/events"
	"aether/internal/report"
)

//go:embed assets/report.css
var reportCSS string

//go:embed assets/app.js
var reportJS string

// HTMLReportData encapsulates all scan metadata, metrics, and findings for the HTML report.
type HTMLReportData struct {
	Version           string
	Commit            string
	BuildDate         string
	BinaryName        string
	Hostname          string
	ScanMode          string
	StartTime         time.Time
	Duration          time.Duration
	TargetPaths       []string
	Excludes          []string
	Threads           int
	MaxFileSize       int64
	Verdict           events.Verdict
	VerdictReason     string
	Partial           bool
	RedactHosts       bool
	MaxReportFindings int

	TotalFindings int
	Alerts        int
	Warnings      int
	Notices       int
	Infos         int
	FilesScanned  int64
	AffectedFiles int

	Coverage            events.CoverageStats
	ModulesRun          []events.ModuleFinished
	ModulesNotRun       []string
	StartupNotices      []string
	ProcessCoverage     *events.ProcessCoverageStats
	PersistenceCoverage *events.PersistenceCoverageStats
	UsersCoverage       *events.UsersCoverageStats
	NetworkCoverage     *events.NetworkCoverageStats
	KernelCoverage      *events.KernelCoverageStats
	YARACoverage        *events.YARACoverageStats
	YARAActive          bool
	YARAStatus          string

	TopRules             []report.RuleSummary
	Findings             []report.Finding
	AcknowledgedWarnings []report.Finding

	// Executive Assessment & Real-World Profiling
	SystemPosture     string
	PostureRationale  string
	RemediationPlan   []RemediationAction
	DurationBreakdown map[string]string
}

// RemediationAction represents an executive action recommendation.
type RemediationAction struct {
	Priority    int    `json:"priority"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Command     string `json:"command,omitempty"`
}

// GenerateNonce creates a cryptographically secure base64-encoded nonce (18 bytes -> 24 base64 chars).
func GenerateNonce() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random nonce: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

type mitreTechniqueItem struct {
	ID    string
	Name  string
	Count int
}

type mitreTacticGroup struct {
	Tactic     string
	TotalCount int
	Techniques []mitreTechniqueItem
}

func aggregateMITRE(findings []report.Finding) []mitreTacticGroup {
	standardOrder := []string{
		"Initial Access",
		"Execution",
		"Persistence",
		"Privilege Escalation",
		"Defense Evasion",
		"Credential Access",
		"Discovery",
		"Lateral Movement",
		"Collection",
		"Command and Control",
		"Exfiltration",
		"Impact",
	}

	tacticMap := make(map[string]map[string]*mitreTechniqueItem)
	for _, tactic := range standardOrder {
		tacticMap[tactic] = make(map[string]*mitreTechniqueItem)
	}

	for _, f := range findings {
		for _, m := range f.MITRE {
			tactic := strings.TrimSpace(m.Tactic)
			if tactic == "" {
				continue
			}
			techID := strings.TrimSpace(m.Technique)
			techName := strings.TrimSpace(m.TechniqueName)
			if techID == "" {
				continue
			}

			if _, ok := tacticMap[tactic]; !ok {
				tacticMap[tactic] = make(map[string]*mitreTechniqueItem)
			}

			if item, exists := tacticMap[tactic][techID]; exists {
				item.Count++
			} else {
				tacticMap[tactic][techID] = &mitreTechniqueItem{
					ID:    techID,
					Name:  techName,
					Count: 1,
				}
			}
		}
	}

	var result []mitreTacticGroup
	for _, tactic := range standardOrder {
		techMap := tacticMap[tactic]
		if len(techMap) == 0 {
			continue
		}
		var techs []mitreTechniqueItem
		total := 0
		for _, item := range techMap {
			techs = append(techs, *item)
			total += item.Count
		}
		sort.Slice(techs, func(i, j int) bool {
			if techs[i].Count != techs[j].Count {
				return techs[i].Count > techs[j].Count
			}
			return techs[i].ID < techs[j].ID
		})
		result = append(result, mitreTacticGroup{
			Tactic:     tactic,
			TotalCount: total,
			Techniques: techs,
		})
	}

	for tactic, techMap := range tacticMap {
		isStandard := false
		for _, st := range standardOrder {
			if st == tactic {
				isStandard = true
				break
			}
		}
		if isStandard || len(techMap) == 0 {
			continue
		}
		var techs []mitreTechniqueItem
		total := 0
		for _, item := range techMap {
			techs = append(techs, *item)
			total += item.Count
		}
		sort.Slice(techs, func(i, j int) bool {
			return techs[i].Count > techs[j].Count
		})
		result = append(result, mitreTacticGroup{
			Tactic:     tactic,
			TotalCount: total,
			Techniques: techs,
		})
	}

	return result
}

// canonicalSeverity folds the extended severity vocabulary onto the four canonical
// report bands the HTML report styles and filters. Without this fold, findings
// carrying CRITICAL/HIGH/MEDIUM/LOW render unstyled badges and become unreachable
// by the ALERT/WARNING/NOTICE/INFO filter pills.
func canonicalSeverity(s report.Severity) report.Severity {
	switch s {
	case report.SeverityCritical:
		return report.SeverityAlert
	case report.SeverityHigh:
		return report.SeverityWarning
	case report.SeverityMedium:
		return report.SeverityNotice
	case report.SeverityLow:
		return report.SeverityInfo
	default:
		return s
	}
}

// RenderStackedCoverageSVG renders a proportional horizontal stacked bar chart
// visually displaying inspected files vs itemized skip categories (permissions, oversize, excluded, non-regular).
func RenderStackedCoverageSVG(cov events.CoverageStats, width, height int) string {
	if width <= 0 {
		width = 800
	}
	if height <= 0 {
		height = 24
	}

	total := cov.TotalEligible()
	if total <= 0 {
		total = cov.FilesScanned
	}

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf(`<svg class="coverage-bar-svg" viewBox="0 0 %d %d" width="100%%" height="%d" preserveAspectRatio="none" role="img" aria-label="Audit coverage distribution bar: inspected files vs skipped reasons">`+"\n", width, height, height))
	buf.WriteString(fmt.Sprintf(`  <defs><clipPath id="coverage-bar-clip"><rect x="0" y="0" width="%d" height="%d" rx="6" ry="6"/></clipPath></defs>`+"\n", width, height))

	if total <= 0 {
		buf.WriteString(fmt.Sprintf(`  <g clip-path="url(#coverage-bar-clip)"><rect x="0" y="0" width="%d" height="%d" fill="#334155"><title>No eligible files encountered</title></rect></g>`+"\n", width, height))
		buf.WriteString("</svg>")
		return buf.String()
	}

	inspected := cov.FilesScanned
	if inspected < 0 {
		inspected = 0
	}
	perm := cov.SkippedPermission
	oversize := cov.SkippedOversize
	excluded := cov.SkippedExcluded + cov.SkippedNotRegular + cov.SkippedVanished + cov.SkippedTimeout

	segments := []struct {
		name  string
		count int64
		color string
	}{
		{"Inspected", inspected, "#34d399"},
		{"Permission Denied", perm, "#fbbf24"},
		{"Oversize", oversize, "#8b5cf6"},
		{"Excluded / Other", excluded, "#64748b"},
	}

	buf.WriteString(`  <g clip-path="url(#coverage-bar-clip)">` + "\n")
	currX := 0.0
	for _, seg := range segments {
		if seg.count <= 0 {
			continue
		}
		pct := (float64(seg.count) / float64(total)) * 100.0
		segWidth := (float64(seg.count) / float64(total)) * float64(width)
		buf.WriteString(fmt.Sprintf(`    <rect x="%.2f" y="0" width="%.2f" height="%d" fill="%s"><title>%s: %d (%.1f%%)</title></rect>`+"\n",
			currX, segWidth, height, seg.color, html.EscapeString(seg.name), seg.count, pct))
		currX += segWidth
	}
	buf.WriteString("  </g>\n")
	buf.WriteString("</svg>")
	return buf.String()
}

func renderStackedCoverageSVG(cov events.CoverageStats, width, height int) string {
	return RenderStackedCoverageSVG(cov, width, height)
}

// renderDonutSVG renders the severity distribution donut for the report header.
// Track and center-label colors resolve through CSS classes so both color themes
// keep contrast; the segment strokes are theme-invariant verdict/ severity colors.
func renderDonutSVG(alerts, warnings, notices, infos int, verdict events.Verdict) string {
	total := alerts + warnings + notices + infos
	var buf bytes.Buffer
	buf.WriteString(`<svg class="donut-svg" width="140" height="140" viewBox="0 0 160 160" aria-label="Severity Distribution Donut Chart">` + "\n")

	if total == 0 {
		buf.WriteString(`  <circle cx="80" cy="80" r="52" fill="none" stroke="#34d399" stroke-width="14" stroke-opacity="0.8"/>` + "\n")
		buf.WriteString(`  <text class="donut-center-text" x="80" y="74" text-anchor="middle" font-size="22" font-weight="800" fill="#34d399">0</text>` + "\n")
		buf.WriteString(`  <text class="donut-center-muted" x="80" y="92" text-anchor="middle" font-size="9" font-weight="700" letter-spacing="1">CLEAN</text>` + "\n")
		buf.WriteString(`</svg>`)
		return buf.String()
	}

	circumference := 2.0 * 3.141592653589793 * 52.0
	buf.WriteString(`  <circle class="donut-track" cx="80" cy="80" r="52" fill="none" stroke-width="14"/>` + "\n")

	slices := []struct {
		count int
		color string
	}{
		{alerts, "#f43f5e"},
		{warnings, "#fbbf24"},
		{notices, "#38bdf8"},
		{infos, "#94a3b8"},
	}

	offset := 0.0
	for _, sl := range slices {
		if sl.count <= 0 {
			continue
		}
		length := (float64(sl.count) / float64(total)) * circumference
		remaining := circumference - length
		dashoffset := -offset
		buf.WriteString(fmt.Sprintf(`  <circle class="donut-segment" cx="80" cy="80" r="52" fill="none" stroke="%s" stroke-width="14" stroke-dasharray="%.2f %.2f" stroke-dashoffset="%.2f" transform="rotate(-90 80 80)"/>`+"\n",
			sl.color, length, remaining, dashoffset))
		offset += length
	}

	verdictColor := "#34d399"
	verdictLabel := "CLEAN"
	switch verdict {
	case events.VerdictCompromised:
		verdictColor = "#f43f5e"
		verdictLabel = "ALERT"
	case events.VerdictSuspicious:
		verdictColor = "#fbbf24"
		verdictLabel = "SUSPECT"
	}

	buf.WriteString(fmt.Sprintf(`  <text class="donut-center-text" x="80" y="74" text-anchor="middle" font-size="22" font-weight="800">%d</text>`+"\n", total))
	buf.WriteString(fmt.Sprintf(`  <text class="donut-center-muted" x="80" y="92" text-anchor="middle" font-size="9" font-weight="700" fill="%s" letter-spacing="1">%s</text>`+"\n", verdictColor, verdictLabel))
	buf.WriteString(`</svg>`)
	return buf.String()
}

// killchainStage describes one adversarial stage strip node.
type killchainStage struct {
	tactic string // exact MITRE tactic name as used by detections
	label  string // compact display label inside/under the node
}

var killchainOrder = []killchainStage{
	{"Initial Access", "INITIAL ACCESS"},
	{"Execution", "EXECUTION"},
	{"Persistence", "PERSISTENCE"},
	{"Privilege Escalation", "PRIV. ESCAL."},
	{"Defense Evasion", "DEF. EVASION"},
	{"Credential Access", "CRED. ACCESS"},
	{"Discovery", "DISCOVERY"},
	{"Lateral Movement", "LAT. MOVEMENT"},
	{"Collection", "COLLECTION"},
	{"Command and Control", "CMD AND CTRL"},
	{"Exfiltration", "EXFILTRATION"},
	{"Impact", "IMPACT"},
}

// renderKillchainSVG renders the horizontal adversary kill-chain strip:
// one node per kill-chain stage, filled when any finding maps to that
// tactic. It is a narrative summary for analysts — ATT&CK tactics are not a
// strict sequential chain, so stage ordering is illustrative, not official.
// Colors resolve through CSS classes so both themes keep contrast.
func renderKillchainSVG(groups []mitreTacticGroup) string {
	countByTactic := make(map[string]int, len(groups))
	for _, g := range groups {
		countByTactic[g.Tactic] = g.TotalCount
	}

	const (
		nodeW   = 86.0
		nodeH   = 46.0
		gap     = 12.0
		startY  = 22.0
		marginX = 10.0
	)
	viewW := marginX*2 + float64(len(killchainOrder))*(nodeW+gap) - gap
	viewH := 108.0

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf(`<svg class="killchain-svg" viewBox="0 0 %.0f %.0f" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Adversary kill-chain stage coverage: which MITRE tactic stages have detections">`+"\n", viewW, viewH))
	buf.WriteString(`  <desc>Each rounded node is one kill-chain stage; a filled node with a count means findings mapped to that tactic, a hollow node means none.</desc>` + "\n")

	for i, stage := range killchainOrder {
		x := marginX + float64(i)*(nodeW+gap)
		count := countByTactic[stage.tactic]

		// Connector arrow from this node to the next.
		if i < len(killchainOrder)-1 {
			ax0 := x + nodeW + 2
			ax1 := x + nodeW + gap - 3
			midY := startY + nodeH/2
			buf.WriteString(fmt.Sprintf(`  <path class="kill-arrow" d="M %.0f %.0f L %.0f %.0f"/><path class="kill-arrow-head" transform="translate(%.0f,%.0f) scale(0.9)" d="M -5 -4 L 1 0 L -5 4 z"/>`+"\n",
				ax0, midY, ax1, midY, ax1+2, midY))
		}

		nodeClass := "kill-node-none"
		stageClass := "kill-stage"
		countText := fmt.Sprintf("%d", count)
		if count > 5 {
			nodeClass = "kill-node-hit kill-intensity-hot"
		} else if count >= 2 {
			nodeClass = "kill-node-hit kill-intensity-mid"
		} else if count >= 1 {
			nodeClass = "kill-node-hit kill-intensity-low"
		} else {
			stageClass += " kill-stage-none"
			countText = "—"
		}
		buf.WriteString(fmt.Sprintf(`  <g class="%s"><title>%s — %d finding(s)</title>`+"\n", stageClass, html.EscapeString(stage.tactic), count))
		buf.WriteString(fmt.Sprintf(`    <rect class="%s" x="%.0f" y="%.0f" width="%.0f" height="%.0f" rx="9" ry="9"/>`+"\n",
			nodeClass, x, startY, nodeW, nodeH))
		buf.WriteString(fmt.Sprintf(`    <text class="kill-count" x="%.0f" y="%.0f" text-anchor="middle">%s</text>`+"\n",
			x+nodeW/2, startY+21, countText))
		buf.WriteString(fmt.Sprintf(`    <text class="kill-abbr" x="%.0f" y="%.0f" text-anchor="middle">%s</text>`+"\n",
			x+nodeW/2, startY+38, stage.label))
		buf.WriteString("  </g>\n")
	}

	buf.WriteString(`</svg>`)
	return buf.String()
}

// GenerateHTMLReport produces a standalone, air-gapped, zero-remote-resource HTML report.
func GenerateHTMLReport(data HTMLReportData) ([]byte, error) {
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, err
	}

	if data.MaxReportFindings <= 0 {
		data.MaxReportFindings = 5000
	}

	// Prepare data for JSON embedding (ensuring findings cap is applied cleanly)
	totalFindingsCount := len(data.Findings)
	cappedFindings := data.Findings
	isCapped := false
	if len(cappedFindings) > data.MaxReportFindings {
		cappedFindings = cappedFindings[:data.MaxReportFindings]
		isCapped = true
	}

	type jsonFinding struct {
		Index               int                    `json:"index"`
		Timestamp           string                 `json:"timestamp"`
		Module              string                 `json:"module"`
		Severity            string                 `json:"severity"`
		Confidence          string                 `json:"confidence"`
		Verdict             string                 `json:"verdict"`
		ConfidenceRationale string                 `json:"confidence_rationale,omitempty"`
		EvidenceRecord      *report.EvidenceRecord `json:"evidence_record,omitempty"`
		Title               string                 `json:"title"`
		Path                string                 `json:"path"`
		LineNumber          int                    `json:"line_number,omitempty"`
		Reason              string                 `json:"reason"`
		RuleName            string                 `json:"rule_name"`
		Evidence            string                 `json:"evidence,omitempty"`
		Why                 string                 `json:"why,omitempty"`
		Remediation         []string               `json:"remediation,omitempty"`
		MITRE               []report.MITREMapping  `json:"mitre,omitempty"`
		Count               int                    `json:"count"`
		Paths               []string               `json:"paths,omitempty"`
		Hashes              map[string]string      `json:"hashes,omitempty"`
		Metadata            map[string]interface{} `json:"metadata,omitempty"`
	}

	jsonFindingsList := make([]jsonFinding, len(cappedFindings))
	for i, f := range cappedFindings {
		report.PopulateFindingDetails(&f)
		ts := f.Timestamp.Format(time.RFC3339)
		if f.Timestamp.IsZero() {
			ts = data.StartTime.Format(time.RFC3339)
		}
		jsonFindingsList[i] = jsonFinding{
			Index:               i + 1,
			Timestamp:           ts,
			Module:              f.Module,
			Severity:            string(canonicalSeverity(f.Severity)),
			Confidence:          string(f.Confidence),
			Verdict:             string(f.Verdict),
			ConfidenceRationale: f.ConfidenceRationale,
			EvidenceRecord:      f.EvidenceRecord,
			Title:               f.Title,
			Path:                f.Path,
			LineNumber:          f.LineNumber,
			Reason:              f.Reason,
			RuleName:            f.RuleName,
			Evidence:            f.Evidence,
			Why:                 f.Why,
			Remediation:         f.Remediation,
			MITRE:               f.MITRE,
			Count:               f.Count,
			Paths:               f.Paths,
			Hashes:              f.Hashes,
			Metadata:            f.Metadata,
		}
	}

	clientPayload := map[string]interface{}{
		"hostname":        report.FormatRedactedHostname(data.Hostname, data.RedactHosts),
		"verdict":         string(data.Verdict),
		"total_count":     totalFindingsCount,
		"displayed_count": len(jsonFindingsList),
		"is_capped":       isCapped,
		"max_cap":         data.MaxReportFindings,
		"findings":        jsonFindingsList,
	}

	rawJSON, err := json.Marshal(clientPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal report findings JSON: %w", err)
	}

	// Escape '<', '>', '&' for secure embedding in application/json script block
	escapedJSON := strings.ReplaceAll(string(rawJSON), "<", "\\u003c")
	escapedJSON = strings.ReplaceAll(escapedJSON, ">", "\\u003e")
	escapedJSON = strings.ReplaceAll(escapedJSON, "&", "\\u0026")

	var buf bytes.Buffer
	buf.WriteString("<!DOCTYPE html>\n")
	buf.WriteString("<html lang=\"en\" data-theme=\"dark\">\n")
	buf.WriteString("<head>\n")
	buf.WriteString("  <meta charset=\"utf-8\">\n")
	buf.WriteString("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n")
	buf.WriteString("  <meta name=\"referrer\" content=\"no-referrer\">\n")
	buf.WriteString("  <title>Aether Threat Hunting Report - " + html.EscapeString(report.FormatRedactedHostname(data.Hostname, data.RedactHosts)) + "</title>\n")

	// Strict CSP: script-src 'nonce-<NONCE>' only (no 'strict-dynamic'), default-src 'none', style-src 'unsafe-inline', img-src data:, base-uri 'none', form-action 'none'
	buf.WriteString(fmt.Sprintf("  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-%s'; img-src data:; base-uri 'none'; form-action 'none';\">\n", nonce))

	buf.WriteString("  <style>\n")
	buf.WriteString(reportCSS)
	buf.WriteString("\n  </style>\n")
	buf.WriteString("</head>\n")
	buf.WriteString("<body>\n")
	buf.WriteString("  <div class=\"bg-aurora\" aria-hidden=\"true\"><div class=\"aurora-a\"></div><div class=\"aurora-b\"></div><div class=\"bg-grid\"></div></div>\n")

	// 1. Header & Export Strip
	buf.WriteString("  <header class=\"header-container\">\n")
	buf.WriteString("    <div class=\"header-left\">\n")
	buf.WriteString("      <div class=\"logo-wrap\">\n")
	buf.WriteString(aetherInlineSVG)
	buf.WriteString("        <div class=\"logo-titles\">\n")
	buf.WriteString("          <h1>AETHER</h1>\n")
	buf.WriteString("          <span class=\"subtitle\">Linux Threat Hunting & Compromise Detection</span>\n")
	buf.WriteString("        </div>\n")
	buf.WriteString("      </div>\n")
	buf.WriteString("    </div>\n")
	buf.WriteString("    <div class=\"header-right\">\n")
	if data.RedactHosts {
		buf.WriteString("      <span class=\"badge-redacted\" title=\"IPs, usernames, hostnames, and home directories have been masked\">REDACTED MODE</span>\n")
	}
	buf.WriteString("      <button id=\"btn-export-csv\" class=\"btn\" aria-label=\"Export findings to CSV\" title=\"Export findings to CSV\">\n")
	buf.WriteString("        <span>Export CSV</span>\n")
	buf.WriteString("      </button>\n")
	buf.WriteString("      <button id=\"btn-export-json\" class=\"btn\" aria-label=\"Export full findings and coverage telemetry to JSON\" title=\"Export full findings and coverage telemetry to JSON\">\n")
	buf.WriteString("        <span>Export JSON</span>\n")
	buf.WriteString("      </button>\n")
	buf.WriteString("      <button id=\"btn-export-triage\" class=\"btn\" aria-label=\"Export a POSIX shell evidence-gathering triage script for all findings\" title=\"Export a triage shell script that gathers evidence (stat/hashes/listings) for these findings on the target host\">\n")
	buf.WriteString("        <span>Export Triage Script</span>\n")
	buf.WriteString("      </button>\n")
	buf.WriteString("      <button id=\"btn-print\" class=\"btn\" aria-label=\"Print or save report as PDF\" title=\"Print or save report as PDF\">\n")
	buf.WriteString("        <span>Print Report</span>\n")
	buf.WriteString("      </button>\n")
	buf.WriteString("      <button id=\"theme-toggle\" class=\"btn btn-theme\" aria-label=\"Toggle dark or light color theme\">\n")
	buf.WriteString("        <span id=\"theme-icon\">☀️</span> <span id=\"theme-label\">Theme</span>\n")
	buf.WriteString("      </button>\n")
	buf.WriteString("    </div>\n")
	buf.WriteString("  </header>\n\n")

	buf.WriteString("  <main class=\"main-container\">\n")

	// Compute MITRE aggregation once over capped findings for gauge, kill-chain, and matrix
	mitreGroups := aggregateMITRE(cappedFindings)

	// 2. Executive Assessment & Posture Dashboard
	// 2a. Verdict Banner
	verdictClass := "verdict-clean"
	verdictTitle := "CLEAN"
	switch data.Verdict {
	case events.VerdictCompromised:
		verdictClass = "verdict-compromised"
		verdictTitle = "COMPROMISED"
	case events.VerdictSuspicious:
		verdictClass = "verdict-suspicious"
		verdictTitle = "SUSPICIOUS"
	}
	buf.WriteString("    <section class=\"card verdict-card " + verdictClass + "\" aria-label=\"Scan Verdict\">\n")
	buf.WriteString("      <div class=\"verdict-header\">\n")
	buf.WriteString("        <span class=\"verdict-badge\">" + verdictTitle + "</span>\n")
	if data.Partial {
		buf.WriteString("        <span class=\"badge-partial\" title=\"Partial coverage due to uninspected items or non-root execution\">PARTIAL COVERAGE</span>\n")
	}
	buf.WriteString("      </div>\n")
	verdictReason := data.VerdictReason
	if verdictReason == "" {
		verdictReason = "Scan completed successfully."
	}
	buf.WriteString("      <div class=\"verdict-reason\">" + html.EscapeString(verdictReason) + "</div>\n")
	buf.WriteString("    </section>\n\n")

	// 2b. Executive System Assessment & Remediation Card
	if data.SystemPosture != "" {
		postureClass := "posture-safe"
		postureDisplay := strings.ToUpper(strings.ReplaceAll(data.SystemPosture, "_", " "))
		switch strings.ToUpper(data.SystemPosture) {
		case "HIGH_RISK", "HIGH RISK":
			postureClass = "posture-high-risk"
		case "ATTENTION_REQUIRED", "ATTENTION REQUIRED":
			postureClass = "posture-attention"
		case "LIMITED_VISIBILITY", "LIMITED VISIBILITY":
			postureClass = "posture-limited-visibility"
		case "SAFE":
			postureClass = "posture-safe"
		}

		buf.WriteString("    <section class=\"card posture-card " + postureClass + "\" aria-label=\"Executive System Assessment\">\n")
		buf.WriteString("      <div class=\"posture-header\">\n")
		buf.WriteString("        <div class=\"posture-badge-wrap\">\n")
		buf.WriteString("          <span class=\"posture-label\">Executive Posture:</span>\n")
		buf.WriteString("          <span class=\"posture-badge " + postureClass + "\">" + html.EscapeString(postureDisplay) + "</span>\n")
		buf.WriteString("        </div>\n")
		if data.PostureRationale != "" {
			buf.WriteString("        <div class=\"posture-rationale\">" + html.EscapeString(data.PostureRationale) + "</div>\n")
		}
		buf.WriteString("      </div>\n")

		if len(data.RemediationPlan) > 0 {
			buf.WriteString("      <div class=\"posture-remediation\">\n")
			buf.WriteString("        <h3 class=\"posture-subhead\">Prioritized Remediation Actions</h3>\n")
			buf.WriteString("        <ol class=\"action-list\">\n")
			for _, act := range data.RemediationPlan {
				buf.WriteString(fmt.Sprintf("          <li class=\"action-item priority-%d\">\n", act.Priority))
				buf.WriteString(fmt.Sprintf("            <div class=\"action-item-header\"><span class=\"action-priority-badge\">Priority %d</span> <strong class=\"action-title\">%s</strong></div>\n", act.Priority, html.EscapeString(act.Title)))
				if act.Description != "" {
					buf.WriteString(fmt.Sprintf("            <div class=\"action-desc\">%s</div>\n", html.EscapeString(act.Description)))
				}
				if act.Command != "" {
					buf.WriteString(fmt.Sprintf("            <div class=\"action-cmd-wrap\"><code>%s</code></div>\n", html.EscapeString(act.Command)))
				}
				buf.WriteString("          </li>\n")
			}
			buf.WriteString("        </ol>\n")
			buf.WriteString("      </div>\n")
		}

		buf.WriteString("    </section>\n\n")
	}

	// 2c. Metric / Counter Cards & Donut Chart
	buf.WriteString("    <section class=\"executive-metrics-grid\" aria-label=\"Severity Breakdown\">\n")
	buf.WriteString("      <div class=\"card donut-card\" aria-label=\"Visual Severity Gauge\">\n")
	buf.WriteString("        <div class=\"donut-chart-wrap\">\n")
	buf.WriteString(renderDonutSVG(data.Alerts, data.Warnings, data.Notices, data.Infos, data.Verdict))
	buf.WriteString("        </div>\n")
	buf.WriteString("        <div class=\"donut-legend\">\n")
	buf.WriteString(fmt.Sprintf("          <div class=\"legend-row\"><span class=\"legend-dot dot-alert\"></span><span class=\"legend-label\">Alerts</span><strong class=\"legend-val\">%d</strong></div>\n", data.Alerts))
	buf.WriteString(fmt.Sprintf("          <div class=\"legend-row\"><span class=\"legend-dot dot-warn\"></span><span class=\"legend-label\">Warnings</span><strong class=\"legend-val\">%d</strong></div>\n", data.Warnings))
	buf.WriteString(fmt.Sprintf("          <div class=\"legend-row\"><span class=\"legend-dot dot-notice\"></span><span class=\"legend-label\">Notices</span><strong class=\"legend-val\">%d</strong></div>\n", data.Notices))
	buf.WriteString(fmt.Sprintf("          <div class=\"legend-row\"><span class=\"legend-dot dot-info\"></span><span class=\"legend-label\">Infos</span><strong class=\"legend-val\">%d</strong></div>\n", data.Infos))
	buf.WriteString("        </div>\n")
	buf.WriteString("      </div>\n")
	buf.WriteString("      <div class=\"counters-grid\">\n")
	buf.WriteString(fmt.Sprintf("        <div class=\"card counter-card\"><span class=\"counter-num\">%d</span><span class=\"counter-lbl\">Total Findings</span></div>\n", data.TotalFindings))
	buf.WriteString(fmt.Sprintf("        <div class=\"card counter-card sev-alert\"><span class=\"counter-num\">%d</span><span class=\"counter-lbl\">Alerts</span></div>\n", data.Alerts))
	buf.WriteString(fmt.Sprintf("        <div class=\"card counter-card sev-warning\"><span class=\"counter-num\">%d</span><span class=\"counter-lbl\">Warnings</span></div>\n", data.Warnings))
	buf.WriteString(fmt.Sprintf("        <div class=\"card counter-card sev-notice\"><span class=\"counter-num\">%d</span><span class=\"counter-lbl\">Notices</span></div>\n", data.Notices))
	buf.WriteString(fmt.Sprintf("        <div class=\"card counter-card sev-info\"><span class=\"counter-num\">%d</span><span class=\"counter-lbl\">Infos</span></div>\n", data.Infos))
	covEligible := data.Coverage.TotalEligible()
	if covEligible > 0 {
		buf.WriteString(fmt.Sprintf("        <div class=\"card counter-card\"><span class=\"counter-num\">%d</span><span class=\"counter-lbl\">Files Scanned (%.1f%% of %d)</span></div>\n", data.FilesScanned, data.Coverage.CoveragePercentage(), covEligible))
	} else {
		buf.WriteString(fmt.Sprintf("        <div class=\"card counter-card\"><span class=\"counter-num\">%d</span><span class=\"counter-lbl\">Files Scanned</span></div>\n", data.FilesScanned))
	}
	buf.WriteString("      </div>\n")
	buf.WriteString("    </section>\n\n")

	// 2d. Adversary Kill-Chain Coverage Strip
	buf.WriteString("    <section class=\"card section-card killchain-section\" aria-label=\"Adversary Kill-Chain Coverage\">\n")
	buf.WriteString("      <h2 class=\"section-title\">Adversary Kill-Chain Coverage</h2>\n")
	buf.WriteString("      <span class=\"subtitle\">Stage nodes highlight wherever observations map onto each kill-chain tactic; hollow nodes had no findings.</span>\n")
	buf.WriteString("      <div class=\"killchain-wrap\">\n" + renderKillchainSVG(mitreGroups) + "\n      </div>\n")
	buf.WriteString("    </section>\n\n")

	// 3. Forensic Audit Coverage & Subsystem Health Section
	buf.WriteString("    <section class=\"card section-card\" aria-label=\"Coverage and Inspection Details\">\n")
	buf.WriteString("      <h2 class=\"section-title\">Inspection Coverage & Subsystems</h2>\n")

	// Proportional Stacked Coverage Bar & Legend
	buf.WriteString("      <div class=\"coverage-bar-wrap\">\n")
	buf.WriteString("        " + renderStackedCoverageSVG(data.Coverage, 800, 24) + "\n")
	covTotal := data.Coverage.TotalEligible()
	if covTotal <= 0 {
		covTotal = data.Coverage.FilesScanned
	}
	if covTotal > 0 {
		buf.WriteString("        <div class=\"coverage-bar-legend\">\n")
		covInspected := data.Coverage.FilesScanned
		if covInspected == 0 && data.FilesScanned > 0 {
			covInspected = data.FilesScanned
		}
		inspectedPct := (float64(covInspected) / float64(covTotal)) * 100.0
		buf.WriteString(fmt.Sprintf("          <div class=\"cov-legend-item\"><span class=\"cov-legend-dot cov-dot-inspected\"></span><span>Inspected: <strong>%d</strong> (%.1f%%)</span></div>\n", covInspected, inspectedPct))
		if data.Coverage.SkippedPermission > 0 {
			permPct := (float64(data.Coverage.SkippedPermission) / float64(covTotal)) * 100.0
			buf.WriteString(fmt.Sprintf("          <div class=\"cov-legend-item\"><span class=\"cov-legend-dot cov-dot-permission\"></span><span>Perm Denied: <strong>%d</strong> (%.1f%%)</span></div>\n", data.Coverage.SkippedPermission, permPct))
		}
		if data.Coverage.SkippedOversize > 0 {
			overPct := (float64(data.Coverage.SkippedOversize) / float64(covTotal)) * 100.0
			buf.WriteString(fmt.Sprintf("          <div class=\"cov-legend-item\"><span class=\"cov-legend-dot cov-dot-oversize\"></span><span>Oversize: <strong>%d</strong> (%.1f%%)</span></div>\n", data.Coverage.SkippedOversize, overPct))
		}
		excludedCount := data.Coverage.SkippedExcluded + data.Coverage.SkippedNotRegular + data.Coverage.SkippedVanished + data.Coverage.SkippedTimeout
		if excludedCount > 0 {
			exclPct := (float64(excludedCount) / float64(covTotal)) * 100.0
			buf.WriteString(fmt.Sprintf("          <div class=\"cov-legend-item\"><span class=\"cov-legend-dot cov-dot-excluded\"></span><span>Excluded/Other: <strong>%d</strong> (%.1f%%)</span></div>\n", excludedCount, exclPct))
		}
		buf.WriteString("        </div>\n")
	}
	buf.WriteString("      </div>\n")

	// Skipped & Coverage Stats
	covEligible = data.Coverage.TotalEligible()
	covInspected := data.Coverage.FilesScanned
	if covInspected == 0 && data.FilesScanned > 0 {
		covInspected = data.FilesScanned
	}
	if covEligible > 0 {
		buf.WriteString("      <div class=\"skipped-summary\" style=\"margin-bottom: 8px;\">\n")
		buf.WriteString(fmt.Sprintf("        <span>Audit Coverage: <strong>%.1f%%</strong> (%d of %d eligible files inspected)</span>\n",
			data.Coverage.CoveragePercentage(),
			covInspected,
			covEligible,
		))
		buf.WriteString("      </div>\n")
	}
	if data.Coverage.TotalSkipped() > 0 {
		buf.WriteString("      <div class=\"skipped-summary\">\n")
		buf.WriteString(fmt.Sprintf("        <span>Files Skipped: <strong>%d</strong> (Oversize: %d, Perm Denied: %d, Vanished: %d, Non-Regular: %d, Excluded: %d)</span>\n",
			data.Coverage.TotalSkipped(),
			data.Coverage.SkippedOversize,
			data.Coverage.SkippedPermission,
			data.Coverage.SkippedVanished,
			data.Coverage.SkippedNotRegular,
			data.Coverage.SkippedExcluded,
		))
		buf.WriteString("      </div>\n")
	}

	// Oversize Files List
	if len(data.Coverage.OversizeFiles) > 0 {
		buf.WriteString("      <details class=\"cov-details\">\n")
		buf.WriteString(fmt.Sprintf("        <summary>Oversize Files Skipped (%d files exceeding --max-filesize)</summary>\n", len(data.Coverage.OversizeFiles)))
		buf.WriteString("        <ul class=\"file-list\">\n")
		for _, of := range data.Coverage.OversizeFiles {
			buf.WriteString(fmt.Sprintf("          <li><code>%s</code> <span class=\"text-muted\">(%d bytes)</span></li>\n", html.EscapeString(of.Path), of.Size))
		}
		buf.WriteString("        </ul>\n")
		buf.WriteString("      </details>\n")
	}

	// Unreadable Persistence Paths List
	if data.PersistenceCoverage != nil && len(data.PersistenceCoverage.UnreadablePaths) > 0 {
		buf.WriteString("      <details class=\"cov-details\">\n")
		buf.WriteString(fmt.Sprintf("        <summary>Inaccessible Persistence Paths (%d paths)</summary>\n", len(data.PersistenceCoverage.UnreadablePaths)))
		buf.WriteString("        <ul class=\"file-list\">\n")
		for _, up := range data.PersistenceCoverage.UnreadablePaths {
			buf.WriteString(fmt.Sprintf("          <li><code>%s</code>: <span class=\"text-muted\">%s</span></li>\n", html.EscapeString(up.Path), html.EscapeString(up.Reason)))
		}
		buf.WriteString("        </ul>\n")
		buf.WriteString("      </details>\n")
	}

	// Masked Persistence Units List
	if data.PersistenceCoverage != nil && len(data.PersistenceCoverage.MaskedPaths) > 0 {
		buf.WriteString("      <details class=\"cov-details\">\n")
		buf.WriteString(fmt.Sprintf("        <summary>Masked Persistence Units (%d units /dev/null)</summary>\n", len(data.PersistenceCoverage.MaskedPaths)))
		buf.WriteString("        <ul class=\"file-list\">\n")
		for _, mp := range data.PersistenceCoverage.MaskedPaths {
			buf.WriteString(fmt.Sprintf("          <li><code>%s</code></li>\n", html.EscapeString(mp)))
		}
		buf.WriteString("        </ul>\n")
		buf.WriteString("      </details>\n")
	}

	// Modules Run Table
	if len(data.ModulesRun) > 0 {
		buf.WriteString("      <div class=\"table-wrap\">\n")
		buf.WriteString("        <table class=\"data-table coverage-table\">\n")
		buf.WriteString("          <thead>\n")
		buf.WriteString("            <tr><th>Module</th><th>Duration</th><th>Inspected</th><th>Findings</th><th>Status</th></tr>\n")
		buf.WriteString("          </thead>\n")
		buf.WriteString("          <tbody>\n")
		for _, m := range data.ModulesRun {
			statusBadge := "<span class=\"status-ok\">OK</span>"
			if m.Status == "FAILED" || m.Err != nil {
				statusBadge = "<span class=\"status-failed\">FAILED</span>"
			} else if m.Status == "NOT IMPLEMENTED" {
				statusBadge = "<span class=\"status-skip\">SKIPPED</span>"
			}
			buf.WriteString(fmt.Sprintf("            <tr><td><strong>%s</strong></td><td>%v</td><td>%d</td><td>%d</td><td>%s</td></tr>\n",
				html.EscapeString(m.ModuleName),
				m.Duration.Round(time.Millisecond),
				m.InspectedCount,
				m.FindingsCount,
				statusBadge,
			))
		}
		buf.WriteString("          </tbody>\n")
		buf.WriteString("        </table>\n")
		buf.WriteString("      </div>\n")
	}

	// Modules Not Run
	if len(data.ModulesNotRun) > 0 {
		buf.WriteString("      <div class=\"notice-block warn-block\">\n")
		buf.WriteString("        <strong>Modules Not Run:</strong> " + html.EscapeString(strings.Join(data.ModulesNotRun, "; ")) + "\n")
		buf.WriteString("      </div>\n")
	}

	// Startup Notices
	if len(data.StartupNotices) > 0 {
		buf.WriteString("      <div class=\"notice-block info-block\">\n")
		buf.WriteString("        <strong>Startup Notices:</strong>\n        <ul>\n")
		for _, sn := range data.StartupNotices {
			buf.WriteString("          <li>" + html.EscapeString(sn) + "</li>\n")
		}
		buf.WriteString("        </ul>\n      </div>\n")
	}

	// Subsystem Duration Breakdown
	if len(data.DurationBreakdown) > 0 {
		buf.WriteString("      <div class=\"posture-timing\">\n")
		buf.WriteString("        <h3 class=\"posture-subhead\">Subsystem Duration Breakdown</h3>\n")
		buf.WriteString("        <div class=\"timing-grid\">\n")
		knownKeys := []struct {
			Key   string
			Label string
		}{
			{"filesystem_walk", "Filesystem Walk"},
			{"hashing", "Hashing"},
			{"heuristics", "Heuristics"},
			{"yara", "YARA-X Engine"},
			{"process", "Process Inspection"},
			{"network", "Network Sockets"},
			{"correlation", "Evidence Correlation"},
			{"total_duration", "Total Duration"},
		}
		renderedKeys := make(map[string]bool)
		for _, item := range knownKeys {
			if durVal, ok := data.DurationBreakdown[item.Key]; ok {
				renderedKeys[item.Key] = true
				buf.WriteString(fmt.Sprintf("          <div class=\"timing-item\"><span class=\"timing-label\">%s</span><strong class=\"timing-val\">%s</strong></div>\n",
					html.EscapeString(item.Label), html.EscapeString(durVal)))
			}
		}
		var extraKeys []string
		for k := range data.DurationBreakdown {
			if !renderedKeys[k] {
				extraKeys = append(extraKeys, k)
			}
		}
		sort.Strings(extraKeys)
		for _, k := range extraKeys {
			buf.WriteString(fmt.Sprintf("          <div class=\"timing-item\"><span class=\"timing-label\">%s</span><strong class=\"timing-val\">%s</strong></div>\n",
				html.EscapeString(k), html.EscapeString(data.DurationBreakdown[k])))
		}
		buf.WriteString("        </div>\n")
		buf.WriteString("      </div>\n")
	}

	// Subsystem breakdown notes
	if data.KernelCoverage != nil {
		taintDesc := data.KernelCoverage.TaintSeverity
		if len(data.KernelCoverage.TaintFlags) > 0 {
			taintDesc = fmt.Sprintf("%s, %s", data.KernelCoverage.TaintSeverity, strings.Join(data.KernelCoverage.TaintFlags, "+"))
		} else if taintDesc == "" {
			taintDesc = "clean"
		}
		buf.WriteString(fmt.Sprintf("      <div class=\"subsystem-note\"><strong>Kernel:</strong> Modules Inspected: %d, Taint: %d (%s), Modprobe Files: %d</div>\n",
			data.KernelCoverage.LoadedModulesInspected, data.KernelCoverage.TaintValue, html.EscapeString(taintDesc), data.KernelCoverage.ModprobeFilesInspected))
	}
	if data.NetworkCoverage != nil {
		buf.WriteString(fmt.Sprintf("      <div class=\"subsystem-note\"><strong>Network:</strong> Sockets: %d (TCP Listeners: %d, UDP Listeners: %d, Established: %d, Raw/Packet: %d)</div>\n",
			data.NetworkCoverage.SocketsInspected, data.NetworkCoverage.TCPListeners, data.NetworkCoverage.UDPListeners, data.NetworkCoverage.EstablishedConnections, data.NetworkCoverage.RawPacketSockets))
	}
	if data.UsersCoverage != nil {
		shadowStr := "readable"
		if data.UsersCoverage.ShadowGapNonRoot {
			shadowStr = "unreadable (non-root)"
		} else if !data.UsersCoverage.ShadowReadable {
			shadowStr = "unreadable"
		}
		buf.WriteString(fmt.Sprintf("      <div class=\"subsystem-note\"><strong>Users:</strong> Accounts: %d (System: %d), Shadow: %s, Duplicate UIDs: %d</div>\n",
			data.UsersCoverage.AccountsInspected, data.UsersCoverage.SystemAccounts, shadowStr, data.UsersCoverage.DuplicateUIDs))
	}

	// Top Rules Section (Curated Detection Rules)
	if len(data.TopRules) > 0 {
		buf.WriteString("      <div class=\"top-rules-wrap\" style=\"margin-top: 14px;\">\n")
		buf.WriteString("        <h3 class=\"posture-subhead\">Top Triggered Rules</h3>\n")
		buf.WriteString("        <div class=\"table-wrap\">\n")
		buf.WriteString("          <table class=\"data-table\">\n")
		buf.WriteString("            <thead>\n")
		buf.WriteString("              <tr><th>Rule Name</th><th>Severity</th><th>Count</th><th>Acknowledged</th></tr>\n")
		buf.WriteString("            </thead>\n")
		buf.WriteString("            <tbody>\n")
		for _, tr := range data.TopRules {
			badgeClass := "sev-" + strings.ToLower(string(canonicalSeverity(tr.Severity)))
			ackStr := "No"
			if tr.Acknowledged {
				ackStr = "Yes"
			}
			buf.WriteString(fmt.Sprintf("              <tr><td><code>%s</code></td><td><span class=\"badge %s\">%s</span></td><td><strong>%d</strong></td><td>%s</td></tr>\n",
				html.EscapeString(tr.RuleName),
				badgeClass,
				html.EscapeString(string(canonicalSeverity(tr.Severity))),
				tr.Count,
				ackStr,
			))
		}
		buf.WriteString("            </tbody>\n")
		buf.WriteString("          </table>\n")
		buf.WriteString("        </div>\n")
		buf.WriteString("      </div>\n")
	}

	buf.WriteString("    </section>\n\n")

	// 4. Adversarial MITRE ATT&CK Matrix Heat-Map Section
	buf.WriteString("    <section class=\"card section-card\" id=\"mitre-matrix-section\" aria-label=\"MITRE ATT&CK Matrix\">\n")
	buf.WriteString("      <div class=\"mitre-matrix-header\">\n")
	buf.WriteString("        <div class=\"mitre-titles\">\n")
	buf.WriteString("          <h2 class=\"section-title\">MITRE ATT&CK&reg; Heat-Map Matrix</h2>\n")
	buf.WriteString("          <span class=\"subtitle\">Enterprise adversarial tactics observed across inspected subsystems</span>\n")
	buf.WriteString("        </div>\n")
	buf.WriteString("      </div>\n")

	if len(mitreGroups) > 0 {
		buf.WriteString("      <div class=\"mitre-matrix-grid\">\n")
		for _, grp := range mitreGroups {
			buf.WriteString("        <div class=\"tactic-col\">\n")
			buf.WriteString(fmt.Sprintf("          <div class=\"tactic-header\"><span class=\"tactic-name\">%s</span><span class=\"tactic-count\">%d</span></div>\n",
				html.EscapeString(grp.Tactic), grp.TotalCount))
			buf.WriteString("          <div class=\"tactic-techniques\">\n")
			for _, tech := range grp.Techniques {
				chipTitle := fmt.Sprintf("%s: %s (%d detections)", tech.ID, tech.Name, tech.Count)
				buf.WriteString(fmt.Sprintf("            <button class=\"btn-tech-chip\" data-tech-id=\"%s\" title=\"%s\"><span class=\"chip-id\">%s</span><span class=\"chip-count\">%d</span></button>\n",
					html.EscapeString(tech.ID),
					html.EscapeString(chipTitle),
					html.EscapeString(tech.ID+" "+tech.Name),
					tech.Count,
				))
			}
			buf.WriteString("          </div>\n")
			buf.WriteString("        </div>\n")
		}
		buf.WriteString("      </div>\n")
	} else {
		buf.WriteString("      <div class=\"mitre-clean-card\">\n")
		buf.WriteString("        <span class=\"mitre-clean-icon\">✔</span>\n")
		buf.WriteString("        <div class=\"mitre-clean-text\">\n")
		buf.WriteString("          <strong>Zero Active MITRE ATT&CK&reg; Adversarial Techniques Detected</strong>\n")
		buf.WriteString("          <p>No malicious persistence, privilege escalation, credential theft, or execution artifacts were observed across inspected subsystems.</p>\n")
		buf.WriteString("        </div>\n")
		buf.WriteString("      </div>\n")
	}
	buf.WriteString("    </section>\n\n")

	// 5. Scan Execution Metadata & Provenance Card
	buf.WriteString("    <section class=\"card meta-card\" aria-label=\"Scan Execution Metadata\">\n")
	buf.WriteString("      <div class=\"meta-grid\">\n")
	buf.WriteString("        <div class=\"meta-item\"><span class=\"meta-label\">Host:</span> <strong class=\"meta-val\">" + html.EscapeString(report.FormatRedactedHostname(data.Hostname, data.RedactHosts)) + "</strong></div>\n")
	buf.WriteString("        <div class=\"meta-item\"><span class=\"meta-label\">Scan Mode:</span> <strong class=\"meta-val badge-mode\">" + html.EscapeString(strings.ToUpper(data.ScanMode)) + "</strong></div>\n")
	buf.WriteString("        <div class=\"meta-item\"><span class=\"meta-label\">Started:</span> <span class=\"meta-val\">" + html.EscapeString(data.StartTime.Format("2006-01-02 15:04 MST")) + "</span></div>\n")
	buf.WriteString("        <div class=\"meta-item\"><span class=\"meta-label\">Duration:</span> <span class=\"meta-val\">" + html.EscapeString(data.Duration.Round(time.Millisecond).String()) + "</span></div>\n")
	verStr := "v" + data.Version
	if data.Commit != "" && data.Commit != "none" {
		verStr += " (" + data.Commit + ")"
	}
	buf.WriteString("        <div class=\"meta-item\"><span class=\"meta-label\">Aether Version:</span> <span class=\"meta-val\">" + html.EscapeString(verStr) + "</span></div>\n")
	buf.WriteString("        <div class=\"meta-item\"><span class=\"meta-label\">Threads / Max Size:</span> <span class=\"meta-val\">" + fmt.Sprintf("%d threads / %d MB", data.Threads, data.MaxFileSize/(1024*1024)) + "</span></div>\n")
	yaraBadgeClass := "badge-yara-disabled"
	yaraBadgeText := "DISABLED (Native Heuristics Only)"
	if data.YARAActive {
		yaraBadgeClass = "badge-yara-active"
		yaraBadgeText = "ACTIVE (" + data.YARAStatus + ")"
	} else if data.YARAStatus != "" {
		yaraBadgeText = data.YARAStatus
	}
	buf.WriteString("        <div class=\"meta-item\"><span class=\"meta-label\">YARA Engine:</span> <span class=\"meta-val\"><span class=\"" + yaraBadgeClass + "\">" + html.EscapeString(yaraBadgeText) + "</span></span></div>\n")
	buf.WriteString("      </div>\n")
	if len(data.TargetPaths) > 0 {
		buf.WriteString("      <div class=\"meta-paths\"><span class=\"meta-label\">Target Paths:</span> <code>" + html.EscapeString(strings.Join(data.TargetPaths, ", ")) + "</code></div>\n")
	}
	buf.WriteString("    </section>\n\n")

	// 6. Detailed Findings Dossier Section
	buf.WriteString("    <section class=\"card section-card print-break-before\" aria-label=\"Scan Findings\">\n")
	buf.WriteString("      <div class=\"findings-header\">\n")
	buf.WriteString("        <h2 class=\"section-title\">Scan Findings</h2>\n")
	buf.WriteString("        <div class=\"findings-stats-line\" id=\"findings-count-summary\"></div>\n")
	buf.WriteString("      </div>\n")

	// Capping Notice Banner if capped
	if isCapped {
		buf.WriteString(fmt.Sprintf("      <div class=\"capping-banner\" id=\"capping-banner\" role=\"alert\">◆ Showing <strong>%d</strong> of <strong>%d</strong> total findings (configured cap: %d; see JSON output for full dataset).</div>\n",
			len(jsonFindingsList), totalFindingsCount, data.MaxReportFindings))
	}

	// Filter Controls
	buf.WriteString("      <div class=\"filter-bar\">\n")
	buf.WriteString("        <div class=\"search-wrap\">\n")
	buf.WriteString("          <input type=\"search\" id=\"search-input\" class=\"input-search\" placeholder=\"Search findings (Press '/' or Cmd+K)...\" aria-label=\"Search findings\">\n")
	buf.WriteString("        </div>\n")
	buf.WriteString("        <div class=\"filter-group\">\n")
	buf.WriteString("          <label for=\"module-filter\" class=\"filter-label\">Module:</label>\n")
	buf.WriteString("          <select id=\"module-filter\" class=\"select-filter\" aria-label=\"Filter findings by module\">\n")
	buf.WriteString("            <option value=\"\">All Modules</option>\n")
	buf.WriteString("            <option value=\"filesystem\">filesystem</option>\n")
	buf.WriteString("            <option value=\"process\">process</option>\n")
	buf.WriteString("            <option value=\"persistence\">persistence</option>\n")
	buf.WriteString("            <option value=\"users\">users</option>\n")
	buf.WriteString("            <option value=\"network\">network</option>\n")
	buf.WriteString("            <option value=\"kernel\">kernel</option>\n")
	buf.WriteString("            <option value=\"yara\">yara</option>\n")
	buf.WriteString("          </select>\n")
	buf.WriteString("        </div>\n")
	buf.WriteString("        <div class=\"filter-pills\" role=\"radiogroup\" aria-label=\"Filter findings by severity\">\n")
	buf.WriteString("          <button class=\"btn-pill active\" data-sev=\"ALL\" aria-pressed=\"true\">All</button>\n")
	buf.WriteString("          <button class=\"btn-pill\" data-sev=\"ALERT\" aria-pressed=\"false\">Alert</button>\n")
	buf.WriteString("          <button class=\"btn-pill\" data-sev=\"WARNING\" aria-pressed=\"false\">Warning</button>\n")
	buf.WriteString("          <button class=\"btn-pill\" data-sev=\"NOTICE\" aria-pressed=\"false\">Notice</button>\n")
	buf.WriteString("          <button class=\"btn-pill\" data-sev=\"INFO\" aria-pressed=\"false\">Info</button>\n")
	buf.WriteString("        </div>\n")
	buf.WriteString("      </div>\n")

	// Table Container
	// Sortable header: data-key selects the JS sort column; the indicator
	// span is updated via textContent only (no innerHTML).
	sortableTh := func(label, key, width string) string {
		w := ""
		if width != "" {
			w = fmt.Sprintf(" style=\"%s\"", width)
		}
		return fmt.Sprintf("              <th class=\"sortable\" data-key=\"%s\"%s tabindex=\"0\" role=\"columnheader\" aria-sort=\"none\" aria-label=\"Sort findings by %s\"><span class=\"th-label\">%s</span><span class=\"th-sort-ind\" aria-hidden=\"true\">&#8597;</span></th>\n",
			key, w, html.EscapeString(label), html.EscapeString(label))
	}
	buf.WriteString("      <div class=\"table-wrap findings-table-wrap\">\n")
	buf.WriteString("        <table class=\"data-table findings-table\" id=\"findings-table\">\n")
	buf.WriteString("          <thead>\n")
	buf.WriteString("            <tr>\n")
	buf.WriteString(sortableTh("Severity", "severity", "width: 90px;"))
	buf.WriteString(sortableTh("Module", "module", "width: 110px;"))
	buf.WriteString(sortableTh("Path / Target", "path", ""))
	buf.WriteString(sortableTh("Rule Name", "rule_name", ""))
	buf.WriteString(sortableTh("Reason", "reason", ""))
	buf.WriteString(sortableTh("Timestamp", "timestamp", "width: 110px;"))
	buf.WriteString("            </tr>\n")
	buf.WriteString("          </thead>\n")
	buf.WriteString("          <tbody id=\"findings-tbody\">\n")
	buf.WriteString("            <!-- Populated securely via JavaScript DOM nodes -->\n")
	buf.WriteString("          </tbody>\n")
	buf.WriteString("        </table>\n")
	buf.WriteString("        <div id=\"empty-state\" class=\"empty-state\" style=\"display: none;\">No findings match the selected filters.</div>\n")
	buf.WriteString("      </div>\n")
	buf.WriteString("    </section>\n\n")

	buf.WriteString("  </main>\n\n")

	// 8. Finding Detail Slide-Over Drawer
	buf.WriteString("  <div id=\"detail-drawer-overlay\" class=\"drawer-overlay\" style=\"display:none;\" aria-hidden=\"true\">\n")
	buf.WriteString("    <aside id=\"detail-drawer\" class=\"drawer\" role=\"dialog\" aria-modal=\"true\" aria-label=\"Finding Details\">\n")
	buf.WriteString("      <div class=\"drawer-header\">\n")
	buf.WriteString("        <div class=\"drawer-header-left\">\n")
	buf.WriteString("          <span id=\"drawer-index-badge\" class=\"badge\"></span>\n")
	buf.WriteString("          <h3 id=\"drawer-title\">Finding Details</h3>\n")
	buf.WriteString("        </div>\n")
	buf.WriteString("        <div class=\"drawer-header-nav\">\n")
	buf.WriteString("          <button id=\"drawer-prev\" class=\"btn btn-sm\" aria-label=\"Previous finding\">&larr; Prev</button>\n")
	buf.WriteString("          <button id=\"drawer-next\" class=\"btn btn-sm\" aria-label=\"Next finding\">Next &rarr;</button>\n")
	buf.WriteString("          <button id=\"drawer-close\" class=\"btn btn-close\" aria-label=\"Close details dialog\">&times;</button>\n")
	buf.WriteString("        </div>\n")
	buf.WriteString("      </div>\n")
	buf.WriteString("      <div id=\"drawer-body\" class=\"drawer-body\">\n")
	buf.WriteString("        <!-- Populated via safe DOM manipulation -->\n")
	buf.WriteString("      </div>\n")
	buf.WriteString("    </aside>\n")
	buf.WriteString("  </div>\n\n")

	// Footer
	buf.WriteString("  <footer class=\"footer-container\">\n")
	buf.WriteString("    <span>Generated by Aether " + html.EscapeString(data.Version) + " &bull; Forensic threat hunting & compromise assessment report</span>\n")
	buf.WriteString("  </footer>\n\n")

	// 9. Raw JSON Data Script Block (Strict Nonce + Escaped '<')
	buf.WriteString(fmt.Sprintf("  <script id=\"aether-data\" type=\"application/json\" nonce=\"%s\">\n", nonce))
	buf.WriteString(escapedJSON)
	buf.WriteString("\n  </script>\n\n")

	// 10. Inline JavaScript (Strict Nonce + Pure textContent/createElement DOM manipulation)
	buf.WriteString(fmt.Sprintf("  <script nonce=\"%s\">\n", nonce))
	buf.WriteString(reportJS)
	buf.WriteString("\n  </script>\n")

	buf.WriteString("</body>\n")
	buf.WriteString("</html>\n")

	return buf.Bytes(), nil
}

// WriteHTMLReport atomically writes an HTML report to targetPath via a temporary file with mode 0600.
func WriteHTMLReport(targetPath string, reportData HTMLReportData) error {
	cleanPath := filepath.Clean(targetPath)

	// Refuse writing to symlink
	if fi, err := os.Lstat(cleanPath); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write HTML report to symlink: %s", cleanPath)
		}
	}

	content, err := GenerateHTMLReport(reportData)
	if err != nil {
		return fmt.Errorf("failed to generate HTML report: %w", err)
	}

	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create directory for HTML report: %w", err)
	}

	tmpFile, err := os.CreateTemp(dir, ".aether-report-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary report file: %w", err)
	}
	tmpName := tmpFile.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmpFile.Chmod(0600); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to set report file permissions: %w", err)
	}

	if _, err := tmpFile.Write(content); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to write HTML report content: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to sync HTML report: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary HTML report: %w", err)
	}

	if err := os.Rename(tmpName, cleanPath); err != nil {
		if copyErr := copyFile(tmpName, cleanPath); copyErr != nil {
			return fmt.Errorf("failed to replace destination report file: %w (copy err: %v)", err, copyErr)
		}
	}
	tmpName = "" // Prevent defer cleanup

	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := in.WriteTo(out); err != nil {
		return err
	}
	return out.Sync()
}

// Inline SVG Icon for Aether (Shield with scanning crosshairs)
const aetherInlineSVG = `<svg class="aether-logo" width="36" height="36" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <polygon points="50,5 90,25 90,65 50,95 10,65 10,25" stroke="#38bdf8" stroke-width="6" fill="#0f172a"/>
  <polygon points="50,18 78,32 78,60 50,82 22,60 22,32" stroke="#0284c7" stroke-width="4" fill="#0369a1" fill-opacity="0.2"/>
  <circle cx="50" cy="48" r="14" stroke="#38bdf8" stroke-width="4" fill="none"/>
  <line x1="50" y1="26" x2="50" y2="70" stroke="#38bdf8" stroke-width="3"/>
  <line x1="28" y1="48" x2="72" y2="48" stroke="#38bdf8" stroke-width="3"/>
</svg>`

// CSS Stylesheet for Aether Report

// Pure Vanilla JavaScript for Findings Table Interaction & Detail Drawer
// NOTE: Must strictly use document.createElement / document.createTextNode / textContent only (NO innerHTML, outerHTML, insertAdjacentHTML).
