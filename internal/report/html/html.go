package htmlreport

import (
	"bytes"
	"crypto/rand"
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

// renderDonutSVG renders the severity distribution donut for the report header.
// Track and center-label colors resolve through CSS classes so both color themes
// keep contrast; the segment strokes are theme-invariant verdict/ severity colors.
func renderDonutSVG(alerts, warnings, notices, infos int, verdict events.Verdict) string {
	total := alerts + warnings + notices + infos
	var buf bytes.Buffer
	buf.WriteString(`<svg class="donut-svg" width="140" height="140" viewBox="0 0 160 160" aria-label="Severity Distribution Donut Chart">` + "\n")

	if total == 0 {
		buf.WriteString(`  <circle cx="80" cy="80" r="52" fill="none" stroke="#10b981" stroke-width="14" stroke-opacity="0.8"/>` + "\n")
		buf.WriteString(`  <text class="donut-center-text" x="80" y="74" text-anchor="middle" font-size="22" font-weight="800" fill="#10b981">0</text>` + "\n")
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
		{alerts, "#ef4444"},
		{warnings, "#f59e0b"},
		{notices, "#38bdf8"},
		{infos, "#9ca3af"},
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

	verdictColor := "#10b981"
	verdictLabel := "CLEAN"
	switch verdict {
	case events.VerdictCompromised:
		verdictColor = "#ef4444"
		verdictLabel = "ALERT"
	case events.VerdictSuspicious:
		verdictColor = "#f59e0b"
		verdictLabel = "SUSPECT"
	}

	buf.WriteString(fmt.Sprintf(`  <text class="donut-center-text" x="80" y="74" text-anchor="middle" font-size="22" font-weight="800">%d</text>`+"\n", total))
	buf.WriteString(fmt.Sprintf(`  <text class="donut-center-muted" x="80" y="92" text-anchor="middle" font-size="9" font-weight="700" fill="%s" letter-spacing="1">%s</text>`+"\n", verdictColor, verdictLabel))
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
	buf.WriteString("  <title>Aether Threat Hunting Report - " + html.EscapeString(report.FormatRedactedHostname(data.Hostname, data.RedactHosts)) + "</title>\n")

	// Strict CSP: script-src 'nonce-<NONCE>' only (no 'strict-dynamic'), default-src 'none', style-src 'unsafe-inline', img-src data:, base-uri 'none', form-action 'none'
	buf.WriteString(fmt.Sprintf("  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-%s'; img-src data:; base-uri 'none'; form-action 'none';\">\n", nonce))

	buf.WriteString("  <style>\n")
	buf.WriteString(htmlReportCSS)
	buf.WriteString("\n  </style>\n")
	buf.WriteString("</head>\n")
	buf.WriteString("<body>\n")

	// 1. Header
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
	buf.WriteString("      <button id=\"btn-print\" class=\"btn\" aria-label=\"Print or save report as PDF\" title=\"Print or save report as PDF\">\n")
	buf.WriteString("        <span>Print Report</span>\n")
	buf.WriteString("      </button>\n")
	buf.WriteString("      <button id=\"theme-toggle\" class=\"btn btn-theme\" aria-label=\"Toggle dark or light color theme\">\n")
	buf.WriteString("        <span id=\"theme-icon\">☀️</span> <span id=\"theme-label\">Theme</span>\n")
	buf.WriteString("      </button>\n")
	buf.WriteString("    </div>\n")
	buf.WriteString("  </header>\n\n")

	buf.WriteString("  <main class=\"main-container\">\n")

	// 2. Scan Metadata Meta Card
	buf.WriteString("    <section class=\"card meta-card\" aria-label=\"Scan Execution Metadata\">\n")
	buf.WriteString("      <div class=\"meta-grid\">\n")
	buf.WriteString("        <div class=\"meta-item\"><span class=\"meta-label\">Host:</span> <strong class=\"meta-val\">" + html.EscapeString(report.FormatRedactedHostname(data.Hostname, data.RedactHosts)) + "</strong></div>\n")
	buf.WriteString("        <div class=\"meta-item\"><span class=\"meta-label\">Scan Mode:</span> <strong class=\"meta-val badge-mode\">" + html.EscapeString(strings.ToUpper(data.ScanMode)) + "</strong></div>\n")
	buf.WriteString("        <div class=\"meta-item\"><span class=\"meta-label\">Started:</span> <span class=\"meta-val\">" + html.EscapeString(data.StartTime.Format(time.RFC3339)) + "</span></div>\n")
	buf.WriteString("        <div class=\"meta-item\"><span class=\"meta-label\">Duration:</span> <span class=\"meta-val\">" + html.EscapeString(data.Duration.Round(time.Millisecond).String()) + "</span></div>\n")
	verStr := "v" + data.Version
	if data.Commit != "" && data.Commit != "none" {
		verStr += " (" + data.Commit + ")"
	}
	buf.WriteString("        <div class=\"meta-item\"><span class=\"meta-label\">Aether Version:</span> <span class=\"meta-val\">" + html.EscapeString(verStr) + "</span></div>\n")
	buf.WriteString("        <div class=\"meta-item\"><span class=\"meta-label\">Threads / Max Size:</span> <span class=\"meta-val\">" + fmt.Sprintf("%d threads / %d MB", data.Threads, data.MaxFileSize/(1024*1024)) + "</span></div>\n")
	buf.WriteString("      </div>\n")
	if len(data.TargetPaths) > 0 {
		buf.WriteString("      <div class=\"meta-paths\"><span class=\"meta-label\">Target Paths:</span> <code>" + html.EscapeString(strings.Join(data.TargetPaths, ", ")) + "</code></div>\n")
	}
	buf.WriteString("    </section>\n\n")

	// 3. Verdict Banner
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

	// 3b. Executive System Assessment & Remediation Card
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

		buf.WriteString("    </section>\n\n")
	}

	// 4. Metric / Counter Cards & Donut Chart
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
	buf.WriteString(fmt.Sprintf("        <div class=\"card counter-card\"><span class=\"counter-num\">%d</span><span class=\"counter-lbl\">Files Scanned</span></div>\n", data.FilesScanned))
	buf.WriteString("      </div>\n")
	buf.WriteString("    </section>\n\n")

	// 4b. MITRE ATT&CK Matrix Heat-Map Section
	mitreGroups := aggregateMITRE(cappedFindings)
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
		buf.WriteString("        <span class=\"mitre-clean-icon\">🛡️</span>\n")
		buf.WriteString("        <div class=\"mitre-clean-text\">\n")
		buf.WriteString("          <strong>Zero Active MITRE ATT&CK&reg; Adversarial Techniques Detected</strong>\n")
		buf.WriteString("          <p>No malicious persistence, privilege escalation, credential theft, or execution artifacts were observed across inspected subsystems.</p>\n")
		buf.WriteString("        </div>\n")
		buf.WriteString("      </div>\n")
	}
	buf.WriteString("    </section>\n\n")

	// 5. Coverage & Inspection Health Section
	buf.WriteString("    <section class=\"card section-card\" aria-label=\"Coverage and Inspection Details\">\n")
	buf.WriteString("      <h2 class=\"section-title\">Inspection Coverage & Subsystems</h2>\n")

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

	// Skipped & Coverage Stats
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

	buf.WriteString("    </section>\n\n")

	// 6. Top Rules Section
	if len(data.TopRules) > 0 {
		buf.WriteString("    <section class=\"card section-card\" aria-label=\"Top Triggered Rules\">\n")
		buf.WriteString("      <h2 class=\"section-title\">Top Triggered Rules</h2>\n")
		buf.WriteString("      <div class=\"table-wrap\">\n")
		buf.WriteString("        <table class=\"data-table\">\n")
		buf.WriteString("          <thead>\n")
		buf.WriteString("            <tr><th>Rule Name</th><th>Severity</th><th>Count</th><th>Acknowledged</th></tr>\n")
		buf.WriteString("          </thead>\n")
		buf.WriteString("          <tbody>\n")
		for _, tr := range data.TopRules {
			badgeClass := "sev-" + strings.ToLower(string(canonicalSeverity(tr.Severity)))
			ackStr := "No"
			if tr.Acknowledged {
				ackStr = "Yes"
			}
			buf.WriteString(fmt.Sprintf("            <tr><td><code>%s</code></td><td><span class=\"badge %s\">%s</span></td><td><strong>%d</strong></td><td>%s</td></tr>\n",
				html.EscapeString(tr.RuleName),
				badgeClass,
				html.EscapeString(string(canonicalSeverity(tr.Severity))),
				tr.Count,
				ackStr,
			))
		}
		buf.WriteString("          </tbody>\n")
		buf.WriteString("        </table>\n")
		buf.WriteString("      </div>\n")
		buf.WriteString("    </section>\n\n")
	}

	// 7. Filterable Findings Table Section
	buf.WriteString("    <section class=\"card section-card\" aria-label=\"Scan Findings\">\n")
	buf.WriteString("      <div class=\"findings-header\">\n")
	buf.WriteString("        <h2 class=\"section-title\">Scan Findings</h2>\n")
	buf.WriteString("        <div class=\"findings-stats-line\" id=\"findings-count-summary\"></div>\n")
	buf.WriteString("      </div>\n")

	// Capping Notice Banner if capped
	if isCapped {
		buf.WriteString(fmt.Sprintf("      <div class=\"capping-banner\" id=\"capping-banner\" role=\"alert\">⚠️ Showing <strong>%d</strong> of <strong>%d</strong> total findings (configured cap: %d; see JSON output for full dataset).</div>\n",
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
	buf.WriteString("      <div class=\"table-wrap findings-table-wrap\">\n")
	buf.WriteString("        <table class=\"data-table findings-table\" id=\"findings-table\">\n")
	buf.WriteString("          <thead>\n")
	buf.WriteString("            <tr>\n")
	buf.WriteString("              <th style=\"width: 90px;\">Severity</th>\n")
	buf.WriteString("              <th style=\"width: 100px;\">Module</th>\n")
	buf.WriteString("              <th>Path / Target</th>\n")
	buf.WriteString("              <th>Rule Name</th>\n")
	buf.WriteString("              <th>Reason</th>\n")
	buf.WriteString("              <th style=\"width: 110px;\">Timestamp</th>\n")
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
	buf.WriteString(htmlReportJS)
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
const htmlReportCSS = `
:root {
  --bg-main: #0b0f19;
  --bg-card: #111827;
  --bg-surface: #1f2937;
  --bg-hover: #374151;
  --border-color: #374151;
  --text-main: #f3f4f6;
  --text-muted: #9ca3af;
  --accent: #38bdf8;
  --accent-glow: rgba(56, 189, 248, 0.15);
  
  --sev-alert-bg: rgba(239, 68, 68, 0.18);
  --sev-alert-border: #ef4444;
  --sev-alert-text: #fca5a5;

  --sev-warn-bg: rgba(245, 158, 11, 0.18);
  --sev-warn-border: #f59e0b;
  --sev-warn-text: #fcd34d;

  --sev-notice-bg: rgba(56, 189, 248, 0.18);
  --sev-notice-border: #38bdf8;
  --sev-notice-text: #7dd3fc;

  --sev-info-bg: rgba(156, 163, 175, 0.18);
  --sev-info-border: #9ca3af;
  --sev-info-text: #d1d5db;

  --verdict-clean-border: #10b981;
  --verdict-clean-bg: rgba(16, 185, 129, 0.12);
  --verdict-clean-text: #34d399;

  --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji";
  --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
}

[data-theme="light"] {
  --bg-main: #f8fafc;
  --bg-card: #ffffff;
  --bg-surface: #f1f5f9;
  --bg-hover: #e2e8f0;
  --border-color: #cbd5e1;
  --text-main: #0f172a;
  --text-muted: #64748b;
  --accent: #0284c7;
  --accent-glow: rgba(2, 132, 199, 0.1);

  --sev-alert-bg: #fee2e2;
  --sev-alert-border: #dc2626;
  --sev-alert-text: #991b1b;

  --sev-warn-bg: #fef3c7;
  --sev-warn-border: #d97706;
  --sev-warn-text: #92400e;

  --sev-notice-bg: #e0f2fe;
  --sev-notice-border: #0284c7;
  --sev-notice-text: #075985;

  --sev-info-bg: #f1f5f9;
  --sev-info-border: #64748b;
  --sev-info-text: #334155;

  --verdict-clean-border: #059669;
  --verdict-clean-bg: #d1fae5;
  --verdict-clean-text: #065f46;
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background-color: var(--bg-main);
  color: var(--text-main);
  font-family: var(--font-sans);
  font-size: 14px;
  line-height: 1.5;
  padding: 0 16px 40px;
}

code, pre {
  font-family: var(--font-mono);
  font-size: 12px;
}

.header-container {
  position: sticky;
  top: 0;
  z-index: 50;
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  background-color: rgba(11, 15, 25, 0.88);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 20px;
  border-bottom: 1px solid var(--border-color);
  margin: 0 -16px 20px;
  flex-wrap: wrap;
  gap: 12px;
}

[data-theme="light"] .header-container {
  background-color: rgba(248, 250, 252, 0.88);
}

.logo-wrap {
  display: flex;
  align-items: center;
  gap: 12px;
}

.logo-titles h1 {
  font-size: 20px;
  letter-spacing: 2px;
  font-weight: 800;
  color: var(--accent);
  line-height: 1.1;
}

.logo-titles .subtitle {
  font-size: 11px;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.header-right {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 10px;
}

.badge-redacted {
  background-color: #831843;
  color: #fbcfe8;
  border: 1px solid #db2777;
  padding: 4px 10px;
  border-radius: 6px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.5px;
}

.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background-color: var(--bg-surface);
  color: var(--text-main);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  padding: 6px 12px;
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s ease;
  user-select: none;
}
.btn:hover { background-color: var(--bg-hover); border-color: var(--accent); }
.btn:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

.main-container {
  max-width: 1280px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.card {
  background-color: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 16px;
  box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}

.meta-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 12px;
}

.meta-item { display: flex; flex-direction: column; gap: 2px; }
.meta-label { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
.meta-val { font-size: 13px; word-break: break-all; }
.meta-paths { margin-top: 10px; padding-top: 8px; border-top: 1px solid var(--border-color); font-size: 12px; }

.badge-mode {
  display: inline-block;
  background: var(--bg-surface);
  border: 1px solid var(--border-color);
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 11px;
}

.verdict-card {
  border-left: 6px solid var(--verdict-clean-border);
  background-color: var(--verdict-clean-bg);
  padding: 16px 20px;
}

.verdict-card.verdict-clean { border-left-color: var(--verdict-clean-border); background: var(--verdict-clean-bg); }
.verdict-card.verdict-suspicious { border-left-color: var(--sev-warn-border); background: var(--sev-warn-bg); }
.verdict-card.verdict-compromised { border-left-color: var(--sev-alert-border); background: var(--sev-alert-bg); }

.verdict-header { display: flex; align-items: center; gap: 12px; margin-bottom: 6px; }
.verdict-badge {
  font-size: 16px;
  font-weight: 800;
  letter-spacing: 1px;
}
.verdict-clean .verdict-badge { color: var(--verdict-clean-text); }
.verdict-suspicious .verdict-badge { color: var(--sev-warn-text); }
.verdict-compromised .verdict-badge { color: var(--sev-alert-text); }

.badge-partial {
  font-size: 11px;
  font-weight: 700;
  padding: 2px 8px;
  border-radius: 4px;
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  color: var(--text-muted);
}

.verdict-reason {
  font-size: 14px;
  font-weight: 500;
}

/* Executive Metrics & Donut Chart */
.executive-metrics-grid {
  display: grid;
  grid-template-columns: 280px 1fr;
  gap: 16px;
  align-items: stretch;
}
@media (max-width: 860px) {
  .executive-metrics-grid {
    grid-template-columns: 1fr;
  }
}

.donut-card {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 18px 14px;
  gap: 14px;
}
.donut-chart-wrap {
  display: flex;
  justify-content: center;
  align-items: center;
}
.donut-segment {
  transform-origin: 80px 80px;
  transition: stroke-dashoffset 0.8s cubic-bezier(0.16, 1, 0.3, 1), stroke-dasharray 0.8s cubic-bezier(0.16, 1, 0.3, 1);
}
@media (prefers-reduced-motion: reduce) {
  .donut-segment {
    transition: none !important;
    animation: none !important;
  }
}
.donut-track {
  stroke: #1f2937;
}
.donut-center-text {
  fill: #f3f4f6;
}
.donut-center-muted {
  fill: #9ca3af;
}
[data-theme="light"] .donut-track {
  stroke: #e5e7eb;
}
[data-theme="light"] .donut-center-text {
  fill: #111827;
}
[data-theme="light"] .donut-center-muted {
  fill: #6b7280;
}
.search-highlight {
  background-color: rgba(245, 158, 11, 0.35);
  color: #fcd34d;
  font-weight: 700;
  border-radius: 2px;
  padding: 0 2px;
}
[data-theme="light"] .search-highlight {
  background-color: #fef08a;
  color: #854d0e;
}
.code-block-lines {
  padding: 6px 0;
  overflow-x: auto;
}
.code-line-row {
  display: flex;
  line-height: 1.6;
}
.code-line-num {
  width: 38px;
  padding-right: 10px;
  text-align: right;
  color: var(--text-muted);
  user-select: none;
  border-right: 1px solid var(--border-color);
  margin-right: 10px;
  flex-shrink: 0;
  font-family: var(--font-mono);
  font-size: 11px;
}
.code-line-text {
  white-space: pre-wrap;
  word-break: break-all;
  color: var(--text-main);
  font-family: var(--font-mono);
  font-size: 12px;
}
.donut-legend {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px 12px;
  width: 100%;
  font-size: 11.5px;
}
.legend-row {
  display: flex;
  align-items: center;
  gap: 6px;
}
.legend-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  display: inline-block;
  flex-shrink: 0;
}
.dot-alert { background: var(--sev-alert-border); }
.dot-warn { background: var(--sev-warn-border); }
.dot-notice { background: var(--sev-notice-border); }
.dot-info { background: var(--sev-info-border); }
.legend-label { color: var(--text-muted); font-size: 11px; flex: 1; }
.legend-val { color: var(--text-main); font-weight: 700; font-family: var(--font-mono); }

.counters-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: 12px;
}

.counter-card {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding: 14px 10px;
}
.counter-num { font-size: 24px; font-weight: 800; line-height: 1.1; }
.counter-lbl { font-size: 11px; text-transform: uppercase; color: var(--text-muted); margin-top: 4px; letter-spacing: 0.5px; }

.sev-alert .counter-num { color: var(--sev-alert-border); }
.sev-warning .counter-num { color: var(--sev-warn-border); }
.sev-notice .counter-num { color: var(--sev-notice-border); }
.sev-info .counter-num { color: var(--sev-info-border); }

.section-title {
  font-size: 15px;
  font-weight: 700;
  margin-bottom: 4px;
  color: var(--accent);
}

/* MITRE ATT&CK Matrix Grid */
.mitre-matrix-header {
  margin-bottom: 12px;
}
.mitre-matrix-header .subtitle {
  font-size: 11.5px;
  color: var(--text-muted);
}
.mitre-matrix-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 12px;
}
.tactic-col {
  background: var(--bg-surface);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.tactic-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 11.5px;
  font-weight: 700;
  color: var(--text-main);
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 6px;
  letter-spacing: 0.3px;
}
.tactic-count {
  font-size: 10px;
  background: var(--sev-alert-bg);
  color: var(--sev-alert-text);
  border: 1px solid var(--sev-alert-border);
  border-radius: 10px;
  padding: 1px 6px;
  font-weight: 800;
}
.tactic-techniques {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.btn-tech-chip {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  color: var(--accent);
  border-radius: 4px;
  padding: 5px 8px;
  font-size: 11px;
  text-align: left;
  cursor: pointer;
  transition: all 0.15s ease;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 6px;
}
.btn-tech-chip:hover {
  border-color: var(--accent);
  background: var(--bg-hover);
}
.chip-id {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.chip-count {
  font-size: 10px;
  color: var(--text-muted);
  background: var(--bg-surface);
  padding: 1px 5px;
  border-radius: 3px;
  font-weight: 700;
}
.mitre-clean-card {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 18px 20px;
  background: var(--verdict-clean-bg);
  border: 1px solid var(--verdict-clean-border);
  border-radius: 6px;
}
.mitre-clean-icon {
  font-size: 28px;
  line-height: 1;
}
.mitre-clean-text strong {
  display: block;
  font-size: 13.5px;
  color: var(--verdict-clean-text);
  margin-bottom: 4px;
}
.mitre-clean-text p {
  font-size: 12px;
  color: var(--text-muted);
}

.table-wrap {
  overflow-x: auto;
  border: 1px solid var(--border-color);
  border-radius: 6px;
}

.data-table {
  width: 100%;
  border-collapse: collapse;
  text-align: left;
  font-size: 13px;
}

.data-table th, .data-table td {
  padding: 8px 12px;
  border-bottom: 1px solid var(--border-color);
}

.data-table th {
  background-color: var(--bg-surface);
  font-weight: 600;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-muted);
}

.data-table tbody tr:last-child td { border-bottom: none; }
.data-table tbody tr:hover { background-color: var(--bg-hover); }

.badge {
  display: inline-block;
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  border: 1px solid transparent;
}
.badge.sev-alert { background: var(--sev-alert-bg); border-color: var(--sev-alert-border); color: var(--sev-alert-text); }
.badge.sev-warning { background: var(--sev-warn-bg); border-color: var(--sev-warn-border); color: var(--sev-warn-text); }
.badge.sev-notice { background: var(--sev-notice-bg); border-color: var(--sev-notice-border); color: var(--sev-notice-text); }
.badge.sev-info { background: var(--sev-info-bg); border-color: var(--sev-info-border); color: var(--sev-info-text); }

.status-ok { color: var(--verdict-clean-text); font-weight: 700; font-size: 11px; }
.status-failed { color: var(--sev-alert-border); font-weight: 700; font-size: 11px; }
.status-skip { color: var(--text-muted); font-weight: 600; font-size: 11px; }

.notice-block {
  padding: 10px 14px;
  border-radius: 6px;
  margin-top: 12px;
  font-size: 12px;
}
.notice-block.warn-block { background: var(--sev-warn-bg); border: 1px solid var(--sev-warn-border); color: var(--sev-warn-text); }
.notice-block.info-block { background: var(--bg-surface); border: 1px solid var(--border-color); color: var(--text-main); }
.notice-block ul { margin-left: 20px; margin-top: 4px; }

.skipped-summary { margin-top: 10px; font-size: 12px; color: var(--text-muted); }
.subsystem-note { margin-top: 8px; font-size: 12px; }

.cov-details {
  margin-top: 10px;
  border: 1px solid var(--border-color);
  border-radius: 6px;
  padding: 8px 12px;
  background: var(--bg-surface);
}
.cov-details summary { font-weight: 600; cursor: pointer; font-size: 12px; outline: none; }
.cov-details .file-list { margin-top: 8px; margin-left: 20px; font-size: 12px; max-height: 200px; overflow-y: auto; }

.findings-header {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  flex-wrap: wrap;
  gap: 8px;
}
.findings-stats-line { font-size: 12px; color: var(--text-muted); }

.capping-banner {
  background-color: var(--sev-warn-bg);
  border: 1px solid var(--sev-warn-border);
  color: var(--sev-warn-text);
  padding: 8px 12px;
  border-radius: 6px;
  font-size: 12px;
  margin-bottom: 12px;
}

.filter-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: center;
  margin-bottom: 12px;
}
.search-wrap { flex: 1 1 250px; }
.input-search {
  width: 100%;
  background: var(--bg-surface);
  border: 1px solid var(--border-color);
  color: var(--text-main);
  padding: 6px 12px;
  border-radius: 6px;
  font-size: 13px;
}
.input-search:focus { outline: 2px solid var(--accent); border-color: transparent; }

.filter-group { display: flex; align-items: center; gap: 6px; }
.filter-label { font-size: 12px; color: var(--text-muted); }
.select-filter {
  background: var(--bg-surface);
  border: 1px solid var(--border-color);
  color: var(--text-main);
  padding: 5px 8px;
  border-radius: 6px;
  font-size: 12px;
}

.filter-pills { display: flex; gap: 4px; }
.btn-pill {
  background: var(--bg-surface);
  border: 1px solid var(--border-color);
  color: var(--text-muted);
  border-radius: 4px;
  padding: 4px 8px;
  font-size: 11px;
  font-weight: 600;
  cursor: pointer;
}
.btn-pill.active {
  background: var(--accent);
  color: #0b0f19;
  border-color: var(--accent);
}

.findings-table tbody tr { cursor: pointer; }
.findings-table tbody tr:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }

.empty-state {
  text-align: center;
  padding: 30px;
  color: var(--text-muted);
  font-size: 13px;
}

/* Slide-over Threat Drawer */
.drawer-overlay {
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  background-color: rgba(0, 0, 0, 0.65);
  z-index: 100;
  display: flex;
  justify-content: flex-end;
}
.drawer {
  background: var(--bg-card);
  width: 100%;
  max-width: 620px;
  height: 100%;
  border-left: 1px solid var(--border-color);
  display: flex;
  flex-direction: column;
  box-shadow: -6px 0 24px rgba(0, 0, 0, 0.4);
}
.drawer-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 20px;
  border-bottom: 1px solid var(--border-color);
  gap: 12px;
}
.drawer-header-left {
  display: flex;
  align-items: center;
  gap: 10px;
  overflow: hidden;
}
.drawer-header-left h3 {
  font-size: 15px;
  color: var(--text-main);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.drawer-header-nav {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-shrink: 0;
}
.btn-sm {
  padding: 4px 8px;
  font-size: 11px;
}
.btn-sm:disabled {
  opacity: 0.35;
  cursor: not-allowed;
}
.btn-close {
  background: transparent;
  border: none;
  font-size: 24px;
  line-height: 1;
  color: var(--text-muted);
  cursor: pointer;
  padding: 0 4px;
}
.btn-close:hover { color: var(--text-main); }
.drawer-body {
  padding: 20px;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 16px;
  font-size: 13px;
}

.drawer-card {
  background: var(--bg-surface);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  padding: 14px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.drawer-card-title {
  font-size: 11.5px;
  font-weight: 700;
  text-transform: uppercase;
  color: var(--accent);
  letter-spacing: 0.5px;
}
.drawer-badges-row {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
}
.badge-conf {
  background: rgba(56, 189, 248, 0.15);
  color: #7dd3fc;
  border: 1px solid #38bdf8;
}
.badge-verd {
  background: rgba(245, 158, 11, 0.15);
  color: #fcd34d;
  border: 1px solid #f59e0b;
}

.threat-callout {
  border-radius: 6px;
  padding: 10px 14px;
  margin-top: 4px;
}
.threat-callout-alert { background: var(--sev-alert-bg); border: 1px solid var(--sev-alert-border); color: var(--sev-alert-text); }
.threat-callout-warning { background: var(--sev-warn-bg); border: 1px solid var(--sev-warn-border); color: var(--sev-warn-text); }
.threat-callout-notice { background: var(--sev-notice-bg); border: 1px solid var(--sev-notice-border); color: var(--sev-notice-text); }
.threat-callout-info { background: var(--sev-info-bg); border: 1px solid var(--sev-info-border); color: var(--sev-info-text); }
.callout-title { font-weight: 700; font-size: 11px; text-transform: uppercase; margin-bottom: 4px; letter-spacing: 0.5px; }
.callout-text { font-size: 12.5px; line-height: 1.45; color: var(--text-main); }

.drawer-field { display: flex; flex-direction: column; gap: 4px; }
.drawer-field-label { font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700; letter-spacing: 0.5px; }
.field-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 2px;
}
.btn-copy-sm {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  color: var(--accent);
  border-radius: 4px;
  padding: 2px 8px;
  font-size: 10px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s;
}
.btn-copy-sm:hover {
  border-color: var(--accent);
  background: var(--bg-hover);
}
.btn-copy-xs {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  color: var(--accent);
  border-radius: 3px;
  padding: 1px 6px;
  font-size: 9.5px;
  font-weight: 600;
  cursor: pointer;
  flex-shrink: 0;
}
.btn-copied {
  background: #064e3b !important;
  color: #34d399 !important;
  border-color: #10b981 !important;
}

.code-block {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  padding: 10px 12px;
  font-family: var(--font-mono);
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
}

.hash-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.hash-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 4px;
  padding: 5px 8px;
  gap: 8px;
}
.hash-code {
  font-size: 11px;
  word-break: break-all;
  color: var(--text-muted);
}

.mitre-chips-grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: 6px;
}
.mitre-item-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 4px;
  padding: 8px 10px;
  display: flex;
  flex-direction: column;
  gap: 3px;
}
.mitre-top-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.mitre-tech-id {
  font-family: var(--font-mono);
  font-weight: 700;
  color: var(--accent);
  font-size: 11.5px;
}
.mitre-tactic-name {
  font-size: 10px;
  text-transform: uppercase;
  color: var(--text-muted);
  font-weight: 600;
}
.mitre-tech-name {
  font-size: 12px;
  color: var(--text-main);
}

.cmd-box {
  display: flex;
  justify-content: space-between;
  align-items: center;
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 4px;
  padding: 6px 10px;
  gap: 8px;
}
.cmd-box code {
  color: var(--accent);
  font-size: 11.5px;
  word-break: break-all;
}
.remediation-steps {
  margin-left: 18px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.remediation-step {
  font-size: 12.5px;
  color: var(--text-main);
}
.step-desc {
  line-height: 1.4;
}
.drawer-text-block {
  font-size: 13px;
  color: var(--text-main);
  line-height: 1.45;
}

.footer-container {
  max-width: 1280px;
  margin: 30px auto 0;
  padding-top: 16px;
  border-top: 1px solid var(--border-color);
  text-align: center;
  font-size: 12px;
  color: var(--text-muted);
}

@media print {
  body { background: #ffffff !important; color: #000000 !important; padding: 0 !important; }
  .card { border: 1px solid #cccccc !important; box-shadow: none !important; break-inside: avoid; }
  .header-container { position: static !important; background: transparent !important; margin: 0 0 20px 0 !important; padding: 0 !important; border-bottom: 2px solid #000 !important; }
  .header-right, .filter-bar, .capping-banner, .btn, #theme-toggle, #btn-export-csv, #btn-print { display: none !important; }
  .drawer-overlay { display: none !important; }
  .data-table th { background: #eeeeee !important; color: #000000 !important; }
  .data-table td, .data-table th { border-bottom: 1px solid #dddddd !important; }
  .badge { border: 1px solid #000000 !important; color: #000000 !important; background: transparent !important; }
  .executive-metrics-grid { display: block !important; }
  .donut-card { display: none !important; }
  .counters-grid { display: grid !important; grid-template-columns: repeat(6, 1fr) !important; }
}

@media (max-width: 640px) {
  .header-container { flex-direction: column; align-items: flex-start; }
  .counters-grid { grid-template-columns: repeat(2, 1fr); }
  .filter-pills { flex-wrap: wrap; }
}

/* Executive Posture & Subsystem Timing Styles */
.posture-card {
  margin-top: -8px;
  border-left: 6px solid var(--accent);
  background-color: var(--bg-card);
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.posture-card.posture-safe { border-left-color: var(--verdict-clean-border); }
.posture-card.posture-attention { border-left-color: var(--sev-warn-border); }
.posture-card.posture-high-risk { border-left-color: var(--sev-alert-border); }
.posture-card.posture-limited-visibility { border-left-color: #8b5cf6; }

.posture-header { display: flex; flex-direction: column; gap: 6px; }
.posture-badge-wrap { display: flex; align-items: center; gap: 10px; }
.posture-label { font-size: 12px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
.posture-badge {
  font-size: 13px;
  font-weight: 800;
  padding: 3px 10px;
  border-radius: 4px;
  letter-spacing: 0.5px;
}
.posture-badge.posture-safe { background: var(--verdict-clean-bg); color: var(--verdict-clean-text); border: 1px solid var(--verdict-clean-border); }
.posture-badge.posture-attention { background: var(--sev-warn-bg); color: var(--sev-warn-text); border: 1px solid var(--sev-warn-border); }
.posture-badge.posture-high-risk { background: var(--sev-alert-bg); color: var(--sev-alert-text); border: 1px solid var(--sev-alert-border); }
.posture-badge.posture-limited-visibility { background: rgba(139, 92, 246, 0.15); color: #c4b5fd; border: 1px solid #8b5cf6; }

.posture-rationale { font-size: 13.5px; color: var(--text-main); line-height: 1.4; }
.posture-subhead { font-size: 12.5px; font-weight: 700; text-transform: uppercase; color: var(--accent); margin-bottom: 8px; letter-spacing: 0.5px; }

.action-list { list-style: none; display: flex; flex-direction: column; gap: 8px; margin: 0; padding: 0; }
.action-item {
  background: var(--bg-surface);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  padding: 10px 14px;
}
.action-item-header { display: flex; align-items: center; gap: 10px; margin-bottom: 4px; }
.action-priority-badge {
  font-size: 10.5px;
  font-weight: 700;
  padding: 1px 6px;
  border-radius: 3px;
  background: var(--bg-hover);
  color: var(--text-main);
  border: 1px solid var(--border-color);
}
.action-item.priority-1 .action-priority-badge { background: var(--sev-alert-bg); color: var(--sev-alert-text); border-color: var(--sev-alert-border); }
.action-item.priority-2 .action-priority-badge { background: var(--sev-warn-bg); color: var(--sev-warn-text); border-color: var(--sev-warn-border); }
.action-title { font-size: 13px; color: var(--text-main); }
.action-desc { font-size: 12.5px; color: var(--text-muted); margin-bottom: 4px; }
.action-cmd-wrap code {
  display: block;
  padding: 6px 10px;
  background: var(--bg-main);
  border-radius: 4px;
  border: 1px solid var(--border-color);
  color: var(--accent);
}

.timing-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 8px;
}
.timing-item {
  background: var(--bg-surface);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  padding: 8px 12px;
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.timing-label { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
.timing-val { font-size: 13px; font-family: var(--font-mono); color: var(--text-main); }
`

// Pure Vanilla JavaScript for Findings Table Interaction & Detail Drawer
// NOTE: Must strictly use document.createElement / document.createTextNode / textContent only (NO innerHTML, outerHTML, insertAdjacentHTML).
const htmlReportJS = `
(function() {
  'use strict';

  var dataElement = document.getElementById('aether-data');
  if (!dataElement) return;

  var reportData = {};
  try {
    reportData = JSON.parse(dataElement.textContent || '{}');
  } catch (e) {
    reportData = { findings: [] };
  }

  var allFindings = reportData.findings || [];
  var currentSeverity = 'ALL';
  var currentModule = '';
  var currentSearch = '';
  var currentFilteredFindings = [];
  var currentFilteredIndex = -1;

  var tbody = document.getElementById('findings-tbody');
  var emptyState = document.getElementById('empty-state');
  var countSummary = document.getElementById('findings-count-summary');
  var searchInput = document.getElementById('search-input');
  var moduleFilter = document.getElementById('module-filter');
  var pills = document.querySelectorAll('.btn-pill');
  var themeToggle = document.getElementById('theme-toggle');
  var themeIcon = document.getElementById('theme-icon');
  var drawerOverlay = document.getElementById('detail-drawer-overlay');
  var drawerClose = document.getElementById('drawer-close');
  var drawerBody = document.getElementById('drawer-body');
  var drawerPrev = document.getElementById('drawer-prev');
  var drawerNext = document.getElementById('drawer-next');
  var btnExportCSV = document.getElementById('btn-export-csv');
  var btnExportJSON = document.getElementById('btn-export-json');
  var btnPrint = document.getElementById('btn-print');
  var activeRow = null;

  // 1. Theme Management
  function initTheme() {
    var saved = localStorage.getItem('aether-theme');
    if (!saved) {
      if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
        saved = 'light';
      } else {
        saved = 'dark';
      }
    }
    setTheme(saved);
  }

  function setTheme(t) {
    document.documentElement.setAttribute('data-theme', t);
    localStorage.setItem('aether-theme', t);
    if (themeIcon) {
      themeIcon.textContent = (t === 'light') ? '🌙' : '☀️';
    }
  }

  if (themeToggle) {
    themeToggle.addEventListener('click', function() {
      var current = document.documentElement.getAttribute('data-theme') || 'dark';
      var next = (current === 'dark') ? 'light' : 'dark';
      setTheme(next);
    });
  }

  initTheme();

  // 2. Safe DOM Helpers
  function clearChildren(node) {
    while (node && node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function el(tag, classNames, text) {
    var e = document.createElement(tag);
    if (classNames) {
      classNames.split(' ').forEach(function(c) {
        if (c) e.classList.add(c);
      });
    }
    if (text !== undefined && text !== null) {
      e.textContent = String(text);
    }
    return e;
  }

  function createBadge(sev) {
    var span = document.createElement('span');
    span.classList.add('badge');
    var sLower = (sev || 'info').toLowerCase();
    span.classList.add('sev-' + sLower);
    span.textContent = sev || 'INFO';
    return span;
  }

  // Safe DOM text node highlighter (strictly zero unsafe DOM manipulation)
  function appendHighlightedText(parent, text, term) {
    if (!text) return;
    if (!term) {
      parent.appendChild(document.createTextNode(text));
      return;
    }
    var lowerText = text.toLowerCase();
    var lowerTerm = term.toLowerCase();
    var startIndex = 0;
    var matchIndex = lowerText.indexOf(lowerTerm, startIndex);
    if (matchIndex === -1) {
      parent.appendChild(document.createTextNode(text));
      return;
    }
    while (matchIndex !== -1) {
      if (matchIndex > startIndex) {
        parent.appendChild(document.createTextNode(text.substring(startIndex, matchIndex)));
      }
      var mark = document.createElement('mark');
      mark.className = 'search-highlight';
      mark.textContent = text.substring(matchIndex, matchIndex + term.length);
      parent.appendChild(mark);
      startIndex = matchIndex + term.length;
      matchIndex = lowerText.indexOf(lowerTerm, startIndex);
    }
    if (startIndex < text.length) {
      parent.appendChild(document.createTextNode(text.substring(startIndex)));
    }
  }

  // Line-numbered code block with copy integrity
  function renderCodeBlockWithLines(text) {
    var container = el('div', 'code-block code-block-lines');
    var lines = (text || '').split('\n');
    lines.forEach(function(line, idx) {
      var row = el('div', 'code-line-row');
      var num = el('span', 'code-line-num', idx + 1);
      var content = el('span', 'code-line-text', line || ' ');
      row.appendChild(num);
      row.appendChild(content);
      container.appendChild(row);
    });
    return container;
  }

  // 3. Clipboard Copy Helpers
  function copyText(text, btn) {
    if (!text) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function() {
        showCopied(btn);
      }).catch(function() {
        fallbackCopy(text, btn);
      });
    } else {
      fallbackCopy(text, btn);
    }
  }

  function fallbackCopy(text, btn) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    try {
      document.execCommand('copy');
      showCopied(btn);
    } catch (err) {}
    document.body.removeChild(ta);
  }

  function showCopied(btn) {
    if (!btn) return;
    var orig = btn.textContent;
    btn.textContent = '✓ Copied';
    btn.classList.add('btn-copied');
    setTimeout(function() {
      btn.textContent = orig;
      btn.classList.remove('btn-copied');
    }, 1800);
  }

  // 4. CSV Export
  function exportCSV() {
    var headers = ["Index", "Severity", "Confidence", "Module", "Rule", "Path", "Reason", "Why", "MITRE", "SHA256", "Timestamp"];
    var rows = [headers];
    allFindings.forEach(function(f, i) {
      var mitreStr = (f.mitre || []).map(function(m) {
        return (m.technique || '') + ' ' + (m.technique_name || '');
      }).join('; ');
      var sha256 = (f.hashes && f.hashes['SHA256']) ? f.hashes['SHA256'] : '';
      var row = [
        String(f.index || (i + 1)),
        f.severity || '',
        f.confidence || '',
        f.module || '',
        f.rule_name || '',
        f.path || '',
        f.reason || '',
        f.why || '',
        mitreStr,
        sha256,
        f.timestamp || ''
      ];
      rows.push(row.map(function(val) {
        var s = String(val).replace(/"/g, '""');
        return '"' + s + '"';
      }));
    });
    var csvStr = rows.map(function(r) { return r.join(','); }).join('\r\n');
    var blob = new Blob([csvStr], { type: 'text/csv;charset=utf-8;' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.setAttribute('href', url);
    var hostStr = (reportData.hostname || 'hunt').replace(/[^a-zA-Z0-9_-]/g, '_');
    a.setAttribute('download', 'aether-threat-dossier-' + hostStr + '.csv');
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  if (btnExportCSV) {
    btnExportCSV.addEventListener('click', exportCSV);
  }

  function exportJSON() {
    var jsonStr = JSON.stringify(reportData, null, 2);
    var blob = new Blob([jsonStr], { type: 'application/json;charset=utf-8;' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.setAttribute('href', url);
    var hostStr = (reportData.hostname || 'hunt').replace(/[^a-zA-Z0-9_-]/g, '_');
    a.setAttribute('download', 'aether-threat-dossier-' + hostStr + '.json');
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  if (btnExportJSON) {
    btnExportJSON.addEventListener('click', exportJSON);
  }

  if (btnPrint) {
    btnPrint.addEventListener('click', function() {
      window.print();
    });
  }

  // 5. Render Findings Table
  function renderTable() {
    clearChildren(tbody);

    var filtered = allFindings.filter(function(f) {
      if (currentSeverity !== 'ALL' && f.severity !== currentSeverity) {
        return false;
      }
      if (currentModule && f.module !== currentModule) {
        return false;
      }
      if (currentSearch) {
        var term = currentSearch.toLowerCase();
        var matchPath = f.path && f.path.toLowerCase().indexOf(term) !== -1;
        var matchRule = f.rule_name && f.rule_name.toLowerCase().indexOf(term) !== -1;
        var matchReason = f.reason && f.reason.toLowerCase().indexOf(term) !== -1;
        var matchModule = f.module && f.module.toLowerCase().indexOf(term) !== -1;
        var matchWhy = f.why && f.why.toLowerCase().indexOf(term) !== -1;
        var matchMitre = (f.mitre || []).some(function(m) {
          return (m.technique && m.technique.toLowerCase().indexOf(term) !== -1) ||
                 (m.tactic && m.tactic.toLowerCase().indexOf(term) !== -1) ||
                 (m.technique_name && m.technique_name.toLowerCase().indexOf(term) !== -1);
        });
        if (!matchPath && !matchRule && !matchReason && !matchModule && !matchWhy && !matchMitre) {
          return false;
        }
      }
      return true;
    });

    currentFilteredFindings = filtered;

    if (countSummary) {
      countSummary.textContent = 'Showing ' + filtered.length + ' of ' + allFindings.length + ' items';
    }

    if (filtered.length === 0) {
      if (emptyState) emptyState.style.display = 'block';
      return;
    } else {
      if (emptyState) emptyState.style.display = 'none';
    }

    filtered.forEach(function(f, idx) {
      var tr = document.createElement('tr');
      tr.setAttribute('tabindex', '0');
      tr.setAttribute('role', 'button');
      tr.setAttribute('aria-label', 'View details for finding in ' + (f.path || f.rule_name));

      // Severity column
      var tdSev = document.createElement('td');
      tdSev.appendChild(createBadge(f.severity));
      tr.appendChild(tdSev);

      // Module column
      var tdMod = document.createElement('td');
      var modStrong = document.createElement('strong');
      modStrong.textContent = f.module || '';
      tdMod.appendChild(modStrong);
      tr.appendChild(tdMod);

      // Path column
      var tdPath = document.createElement('td');
      var codePath = document.createElement('code');
      appendHighlightedText(codePath, f.path || '', currentSearch);
      tdPath.appendChild(codePath);
      tr.appendChild(tdPath);

      // Rule Name column
      var tdRule = document.createElement('td');
      var codeRule = document.createElement('code');
      appendHighlightedText(codeRule, f.rule_name || '', currentSearch);
      tdRule.appendChild(codeRule);
      tr.appendChild(tdRule);

      // Reason column
      var tdReason = document.createElement('td');
      appendHighlightedText(tdReason, f.reason || '', currentSearch);
      tr.appendChild(tdReason);

      // Timestamp column
      var tdTime = document.createElement('td');
      var timeStr = f.timestamp || '';
      if (timeStr.length > 19) {
        timeStr = timeStr.substring(11, 19);
      }
      tdTime.textContent = timeStr;
      tr.appendChild(tdTime);

      // Row Interaction
      function onRowSelect() {
        activeRow = tr;
        currentFilteredIndex = idx;
        renderDrawerFinding(f);
        openDrawer();
      }

      tr.addEventListener('click', onRowSelect);
      tr.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' || e.key === ' ' || e.keyCode === 13 || e.keyCode === 32) {
          e.preventDefault();
          onRowSelect();
        }
      });

      tbody.appendChild(tr);
    });
  }

  // 6. Detail Drawer Rendering
  function renderDrawerFinding(f) {
    clearChildren(drawerBody);

    var drawerTitle = document.getElementById('drawer-title');
    var drawerIndexBadge = document.getElementById('drawer-index-badge');

    if (drawerTitle) {
      drawerTitle.textContent = f.title || f.rule_name || 'Finding Details';
    }
    if (drawerIndexBadge) {
      drawerIndexBadge.textContent = (currentFilteredIndex >= 0) ? (currentFilteredIndex + 1) + ' / ' + currentFilteredFindings.length : '';
      drawerIndexBadge.className = 'badge sev-' + (f.severity || 'info').toLowerCase();
    }
    if (drawerPrev) {
      drawerPrev.disabled = (currentFilteredIndex <= 0);
    }
    if (drawerNext) {
      drawerNext.disabled = (currentFilteredIndex >= currentFilteredFindings.length - 1);
    }

    // 1. Threat Assessment Card
    var assessCard = el('div', 'drawer-card');
    assessCard.appendChild(el('h4', 'drawer-card-title', 'Threat Assessment'));

    var badgesWrap = el('div', 'drawer-badges-row');
    badgesWrap.appendChild(createBadge(f.severity));
    if (f.confidence) {
      var confBadge = el('span', 'badge badge-conf', 'CONFIDENCE: ' + f.confidence);
      if (f.confidence_rationale) {
        confBadge.setAttribute('title', f.confidence_rationale);
      }
      badgesWrap.appendChild(confBadge);
    }
    if (f.verdict) {
      badgesWrap.appendChild(el('span', 'badge badge-verd', 'VERDICT: ' + f.verdict));
    }
    assessCard.appendChild(badgesWrap);

    if (f.why) {
      var callout = el('div', 'threat-callout threat-callout-' + (f.severity || 'info').toLowerCase());
      callout.appendChild(el('div', 'callout-title', 'Forensic Rationale (Why Dangerous)'));
      callout.appendChild(el('div', 'callout-text', f.why));
      assessCard.appendChild(callout);
    }
    drawerBody.appendChild(assessCard);

    // 2. Forensic Evidence & Artifacts Card
    var evidCard = el('div', 'drawer-card');
    evidCard.appendChild(el('h4', 'drawer-card-title', 'Forensic Evidence & Artifacts'));

    if (f.path) {
      var pathField = el('div', 'drawer-field');
      var pathHdr = el('div', 'field-header');
      pathHdr.appendChild(el('span', 'drawer-field-label', 'Primary Path / Target'));
      var copyPathBtn = el('button', 'btn-copy-sm', 'Copy Path');
      copyPathBtn.addEventListener('click', function() { copyText(f.path, copyPathBtn); });
      pathHdr.appendChild(copyPathBtn);
      pathField.appendChild(pathHdr);
      pathField.appendChild(el('div', 'code-block', f.path));
      evidCard.appendChild(pathField);
    }

    if (f.paths && f.paths.length > 1) {
      var pathsField = el('div', 'drawer-field');
      var pathsHdr = el('div', 'field-header');
      pathsHdr.appendChild(el('span', 'drawer-field-label', 'All Matched Paths (' + f.paths.length + ')'));
      var copyAllBtn = el('button', 'btn-copy-sm', 'Copy All');
      copyAllBtn.addEventListener('click', function() { copyText(f.paths.join('\n'), copyAllBtn); });
      pathsHdr.appendChild(copyAllBtn);
      pathsField.appendChild(pathsHdr);
      pathsField.appendChild(renderCodeBlockWithLines(f.paths.join('\n')));
      evidCard.appendChild(pathsField);
    }

    if (f.reason) {
      var reasonField = el('div', 'drawer-field');
      reasonField.appendChild(el('span', 'drawer-field-label', 'Detection Details'));
      reasonField.appendChild(el('div', 'drawer-text-block', f.reason));
      evidCard.appendChild(reasonField);
    }

    if (f.evidence) {
      var evField = el('div', 'drawer-field');
      var evHdr = el('div', 'field-header');
      evHdr.appendChild(el('span', 'drawer-field-label', 'Raw Evidence / Matched String'));
      var copyEvBtn = el('button', 'btn-copy-sm', 'Copy Evidence');
      copyEvBtn.addEventListener('click', function() { copyText(f.evidence, copyEvBtn); });
      evHdr.appendChild(copyEvBtn);
      evField.appendChild(evHdr);
      evField.appendChild(renderCodeBlockWithLines(f.evidence));
      evidCard.appendChild(evField);
    }

    if (f.hashes && Object.keys(f.hashes).length > 0) {
      var hashField = el('div', 'drawer-field');
      var hashHdr = el('div', 'field-header');
      hashHdr.appendChild(el('span', 'drawer-field-label', 'Cryptographic Hashes'));
      var allHashStr = [];
      for (var hName in f.hashes) {
        allHashStr.push(hName + ': ' + f.hashes[hName]);
      }
      var copyHashBtn = el('button', 'btn-copy-sm', 'Copy Hashes');
      copyHashBtn.addEventListener('click', function() { copyText(allHashStr.join('\n'), copyHashBtn); });
      hashHdr.appendChild(copyHashBtn);
      hashField.appendChild(hashHdr);

      var hashList = el('div', 'hash-list');
      for (var hKey in f.hashes) {
        (function(key, val) {
          var hRow = el('div', 'hash-row');
          hRow.appendChild(el('code', 'hash-code', key + ': ' + val));
          var cBtn = el('button', 'btn-copy-xs', 'Copy');
          cBtn.addEventListener('click', function() { copyText(val, cBtn); });
          hRow.appendChild(cBtn);
          hashList.appendChild(hRow);
        })(hKey, f.hashes[hKey]);
      }
      hashField.appendChild(hashList);
      evidCard.appendChild(hashField);
    }

    if (f.metadata && Object.keys(f.metadata).length > 0) {
      var metaField = el('div', 'drawer-field');
      metaField.appendChild(el('span', 'drawer-field-label', 'Forensic Metadata'));
      metaField.appendChild(el('div', 'code-block', JSON.stringify(f.metadata, null, 2)));
      evidCard.appendChild(metaField);
    }

    drawerBody.appendChild(evidCard);

    // 3. MITRE ATT&CK Mapping Card
    if (f.mitre && f.mitre.length > 0) {
      var mitreCard = el('div', 'drawer-card');
      mitreCard.appendChild(el('h4', 'drawer-card-title', 'MITRE ATT&CK® Enterprise Alignment'));
      var mitreList = el('div', 'mitre-chips-grid');
      f.mitre.forEach(function(m) {
        var item = el('div', 'mitre-item-card');
        var topRow = el('div', 'mitre-top-row');
        topRow.appendChild(el('span', 'mitre-tech-id', m.technique || ''));
        topRow.appendChild(el('span', 'mitre-tactic-name', m.tactic || ''));
        item.appendChild(topRow);
        item.appendChild(el('div', 'mitre-tech-name', m.technique_name || ''));
        mitreList.appendChild(item);
      });
      mitreCard.appendChild(mitreList);
      drawerBody.appendChild(mitreCard);
    }

    // 4. Actionable Containment & Remediation Card
    if (f.remediation && f.remediation.length > 0) {
      var remCard = el('div', 'drawer-card');
      remCard.appendChild(el('h4', 'drawer-card-title', 'Actionable Containment & Remediation'));
      var remList = el('ol', 'remediation-steps');
      f.remediation.forEach(function(step) {
        var li = el('li', 'remediation-step');
        var trimmed = step.trim();
        var isCommand = trimmed.startsWith('kill ') ||
                        trimmed.startsWith('rm ') ||
                        trimmed.startsWith('systemctl ') ||
                        trimmed.startsWith('chmod ') ||
                        trimmed.startsWith('iptables ') ||
                        trimmed.startsWith('sed ') ||
                        trimmed.startsWith('pkill ') ||
                        trimmed.startsWith('chattr ');
        if (isCommand) {
          var cmdBox = el('div', 'cmd-box');
          cmdBox.appendChild(el('code', '', trimmed));
          var copyCmdBtn = el('button', 'btn-copy-sm', 'Copy Command');
          copyCmdBtn.addEventListener('click', function() { copyText(trimmed, copyCmdBtn); });
          cmdBox.appendChild(copyCmdBtn);
          li.appendChild(cmdBox);
        } else {
          li.appendChild(el('div', 'step-desc', step));
        }
        remList.appendChild(li);
      });
      remCard.appendChild(remList);
      drawerBody.appendChild(remCard);
    }
  }

  function openDrawer() {
    if (drawerOverlay) {
      drawerOverlay.style.display = 'flex';
      drawerOverlay.setAttribute('aria-hidden', 'false');
      drawerOverlay.setAttribute('aria-modal', 'true');
      drawerOverlay.setAttribute('role', 'dialog');
      if (drawerClose) drawerClose.focus();
    }
  }

  function closeDrawer() {
    if (drawerOverlay) {
      drawerOverlay.style.display = 'none';
      drawerOverlay.setAttribute('aria-hidden', 'true');
      if (activeRow) {
        activeRow.focus();
      }
    }
  }

  if (drawerClose) {
    drawerClose.addEventListener('click', closeDrawer);
  }
  if (drawerOverlay) {
    drawerOverlay.addEventListener('click', function(e) {
      if (e.target === drawerOverlay) {
        closeDrawer();
      }
    });
  }

  if (drawerPrev) {
    drawerPrev.addEventListener('click', function() {
      if (currentFilteredIndex > 0) {
        currentFilteredIndex--;
        renderDrawerFinding(currentFilteredFindings[currentFilteredIndex]);
      }
    });
  }

  if (drawerNext) {
    drawerNext.addEventListener('click', function() {
      if (currentFilteredIndex < currentFilteredFindings.length - 1) {
        currentFilteredIndex++;
        renderDrawerFinding(currentFilteredFindings[currentFilteredIndex]);
      }
    });
  }

  window.addEventListener('keydown', function(e) {
    if (drawerOverlay && drawerOverlay.style.display !== 'none') {
      if (e.key === 'Escape' || e.keyCode === 27) {
        closeDrawer();
      } else if (e.key === 'ArrowLeft' && currentFilteredIndex > 0) {
        currentFilteredIndex--;
        renderDrawerFinding(currentFilteredFindings[currentFilteredIndex]);
      } else if (e.key === 'ArrowRight' && currentFilteredIndex < currentFilteredFindings.length - 1) {
        currentFilteredIndex++;
        renderDrawerFinding(currentFilteredFindings[currentFilteredIndex]);
      } else if (e.key === 'Tab' || e.keyCode === 9) {
        var focusables = drawerOverlay.querySelectorAll('button:not([disabled]), [tabindex="0"]:not([disabled])');
        if (focusables.length > 0) {
          var first = focusables[0];
          var last = focusables[focusables.length - 1];
          if (e.shiftKey) {
            if (document.activeElement === first) {
              e.preventDefault();
              last.focus();
            }
          } else {
            if (document.activeElement === last) {
              e.preventDefault();
              first.focus();
            }
          }
        }
      }
      return;
    }

    // Global Command-K / '/' shortcut to focus search input
    var isSearchShortcut = ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) ||
      (e.key === '/' && document.activeElement !== searchInput && document.activeElement &&
       document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA');
    if (isSearchShortcut) {
      e.preventDefault();
      if (searchInput) {
        searchInput.focus();
        searchInput.select();
      }
    }
  });

  // 7. MITRE Technique Chip Click Handling
  var techChips = document.querySelectorAll('.btn-tech-chip');
  techChips.forEach(function(chip) {
    chip.addEventListener('click', function() {
      var techId = chip.getAttribute('data-tech-id') || '';
      if (searchInput) {
        searchInput.value = techId;
        currentSearch = techId;
        renderTable();
        var tableSection = document.getElementById('findings-table');
        if (tableSection) {
          tableSection.scrollIntoView({ behavior: 'smooth' });
        }
      }
    });
  });

  // 8. Search & Filters
  if (searchInput) {
    searchInput.addEventListener('input', function() {
      currentSearch = (searchInput.value || '').trim();
      renderTable();
    });
  }

  if (moduleFilter) {
    moduleFilter.addEventListener('change', function() {
      currentModule = moduleFilter.value || '';
      renderTable();
    });
  }

  pills.forEach(function(btn) {
    btn.addEventListener('click', function() {
      pills.forEach(function(b) {
        b.classList.remove('active');
        b.setAttribute('aria-pressed', 'false');
      });
      btn.classList.add('active');
      btn.setAttribute('aria-pressed', 'true');
      currentSeverity = btn.getAttribute('data-sev') || 'ALL';
      renderTable();
    });
  });

  // Initial table render
  renderTable();
})();
`
