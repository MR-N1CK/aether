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
	Version              string
	Commit               string
	BuildDate            string
	BinaryName           string
	Hostname             string
	ScanMode             string
	StartTime            time.Time
	Duration             time.Duration
	TargetPaths          []string
	Excludes             []string
	Threads              int
	MaxFileSize          int64
	Verdict              events.Verdict
	VerdictReason        string
	Partial              bool
	RedactHosts          bool
	MaxReportFindings    int

	TotalFindings        int
	Alerts               int
	Warnings             int
	Notices              int
	Infos                int
	FilesScanned         int64
	AffectedFiles        int

	Coverage             events.CoverageStats
	ModulesRun           []events.ModuleFinished
	ModulesNotRun        []string
	StartupNotices       []string
	ProcessCoverage      *events.ProcessCoverageStats
	PersistenceCoverage  *events.PersistenceCoverageStats
	UsersCoverage        *events.UsersCoverageStats
	NetworkCoverage      *events.NetworkCoverageStats
	KernelCoverage       *events.KernelCoverageStats
	YARACoverage         *events.YARACoverageStats

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
			Severity:            string(f.Severity),
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

	// 4. Metric / Counter Cards
	buf.WriteString("    <section class=\"counters-grid\" aria-label=\"Severity Breakdown\">\n")
	buf.WriteString(fmt.Sprintf("      <div class=\"card counter-card\"><span class=\"counter-num\">%d</span><span class=\"counter-lbl\">Total Findings</span></div>\n", data.TotalFindings))
	buf.WriteString(fmt.Sprintf("      <div class=\"card counter-card sev-alert\"><span class=\"counter-num\">%d</span><span class=\"counter-lbl\">Alerts</span></div>\n", data.Alerts))
	buf.WriteString(fmt.Sprintf("      <div class=\"card counter-card sev-warning\"><span class=\"counter-num\">%d</span><span class=\"counter-lbl\">Warnings</span></div>\n", data.Warnings))
	buf.WriteString(fmt.Sprintf("      <div class=\"card counter-card sev-notice\"><span class=\"counter-num\">%d</span><span class=\"counter-lbl\">Notices</span></div>\n", data.Notices))
	buf.WriteString(fmt.Sprintf("      <div class=\"card counter-card sev-info\"><span class=\"counter-num\">%d</span><span class=\"counter-lbl\">Infos</span></div>\n", data.Infos))
	buf.WriteString(fmt.Sprintf("      <div class=\"card counter-card\"><span class=\"counter-num\">%d</span><span class=\"counter-lbl\">Files Scanned</span></div>\n", data.FilesScanned))
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
			badgeClass := "sev-" + strings.ToLower(string(tr.Severity))
			ackStr := "No"
			if tr.Acknowledged {
				ackStr = "Yes"
			}
			buf.WriteString(fmt.Sprintf("            <tr><td><code>%s</code></td><td><span class=\"badge %s\">%s</span></td><td><strong>%d</strong></td><td>%s</td></tr>\n",
				html.EscapeString(tr.RuleName),
				badgeClass,
				html.EscapeString(string(tr.Severity)),
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
	buf.WriteString("          <input type=\"search\" id=\"search-input\" class=\"input-search\" placeholder=\"Search path, rule, reason, module, metadata...\" aria-label=\"Search findings\">\n")
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
	buf.WriteString("        <h3 id=\"drawer-title\">Finding Details</h3>\n")
	buf.WriteString("        <button id=\"drawer-close\" class=\"btn btn-close\" aria-label=\"Close details dialog\">&times;</button>\n")
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
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 20px 0 16px;
  border-bottom: 1px solid var(--border-color);
  margin-bottom: 20px;
  flex-wrap: wrap;
  gap: 12px;
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
  gap: 12px;
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

.counters-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
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
  margin-bottom: 12px;
  color: var(--accent);
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

/* Slide-over Drawer */
.drawer-overlay {
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  background-color: rgba(0, 0, 0, 0.6);
  z-index: 100;
  display: flex;
  justify-content: flex-end;
}
.drawer {
  background: var(--bg-card);
  width: 100%;
  max-width: 550px;
  height: 100%;
  border-left: 1px solid var(--border-color);
  display: flex;
  flex-direction: column;
  box-shadow: -4px 0 16px rgba(0, 0, 0, 0.3);
}
.drawer-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 20px;
  border-bottom: 1px solid var(--border-color);
}
.drawer-header h3 { font-size: 16px; color: var(--accent); }
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

.drawer-field { display: flex; flex-direction: column; gap: 4px; }
.drawer-field-label { font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700; letter-spacing: 0.5px; }
.drawer-field-val { word-break: break-all; }
.code-block {
  background: var(--bg-surface);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  padding: 10px 12px;
  font-family: var(--font-mono);
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
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
  .header-right, .filter-bar, .capping-banner, .btn, #theme-toggle { display: none !important; }
  .drawer-overlay { display: none !important; }
  .data-table th { background: #eeeeee !important; color: #000000 !important; }
  .data-table td, .data-table th { border-bottom: 1px solid #dddddd !important; }
  .badge { border: 1px solid #000000 !important; color: #000000 !important; background: transparent !important; }
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

  function createBadge(sev) {
    var span = document.createElement('span');
    span.classList.add('badge');
    var sLower = (sev || 'info').toLowerCase();
    span.classList.add('sev-' + sLower);
    span.textContent = sev || 'INFO';
    return span;
  }

  // 3. Render Findings Table
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
        if (!matchPath && !matchRule && !matchReason && !matchModule) {
          return false;
        }
      }
      return true;
    });

    if (countSummary) {
      countSummary.textContent = 'Showing ' + filtered.length + ' of ' + allFindings.length + ' items';
    }

    if (filtered.length === 0) {
      if (emptyState) emptyState.style.display = 'block';
      return;
    } else {
      if (emptyState) emptyState.style.display = 'none';
    }

    filtered.forEach(function(f) {
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
      codePath.textContent = f.path || '';
      tdPath.appendChild(codePath);
      tr.appendChild(tdPath);

      // Rule Name column
      var tdRule = document.createElement('td');
      var codeRule = document.createElement('code');
      codeRule.textContent = f.rule_name || '';
      tdRule.appendChild(codeRule);
      tr.appendChild(tdRule);

      // Reason column
      var tdReason = document.createElement('td');
      tdReason.textContent = f.reason || '';
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
        openDrawer(f);
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

  // 4. Detail Drawer
  function openDrawer(f) {
    clearChildren(drawerBody);

    // Helper to add field
    function addField(label, value, isCode) {
      if (value === undefined || value === null || value === '') return;
      var div = document.createElement('div');
      div.classList.add('drawer-field');

      var lbl = document.createElement('span');
      lbl.classList.add('drawer-field-label');
      lbl.textContent = label;
      div.appendChild(lbl);

      var valElem;
      if (isCode) {
        valElem = document.createElement('div');
        valElem.classList.add('code-block');
        valElem.textContent = (typeof value === 'object') ? JSON.stringify(value, null, 2) : String(value);
      } else {
        valElem = document.createElement('span');
        valElem.classList.add('drawer-field-val');
        valElem.textContent = String(value);
      }
      div.appendChild(valElem);
      drawerBody.appendChild(div);
    }

    // Severity
    var sevDiv = document.createElement('div');
    sevDiv.classList.add('drawer-field');
    var sevLbl = document.createElement('span');
    sevLbl.classList.add('drawer-field-label');
    sevLbl.textContent = 'Severity';
    sevDiv.appendChild(sevLbl);
    sevDiv.appendChild(createBadge(f.severity));
    drawerBody.appendChild(sevDiv);

    addField('Module', f.module);
    addField('Rule Name', f.rule_name);
    addField('Primary Path', f.path, true);
    if (f.paths && f.paths.length > 1) {
      addField('All Matched Paths (' + f.paths.length + ')', f.paths.join('\\n'), true);
    }
    addField('Reason & Details', f.reason);
    addField('Timestamp', f.timestamp);

    if (f.hashes && Object.keys(f.hashes).length > 0) {
      var hashLines = [];
      for (var hName in f.hashes) {
        hashLines.push(hName + ': ' + f.hashes[hName]);
      }
      addField('File Hashes', hashLines.join('\\n'), true);
    }

    if (f.metadata && Object.keys(f.metadata).length > 0) {
      addField('Metadata', f.metadata, true);
    }

    if (drawerOverlay) {
      drawerOverlay.style.display = 'flex';
      drawerOverlay.setAttribute('aria-hidden', 'false');
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

  window.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' || e.keyCode === 27) {
      if (drawerOverlay && drawerOverlay.style.display !== 'none') {
        closeDrawer();
      }
    }
  });

  // 5. Search & Filters
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
