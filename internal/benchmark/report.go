package benchmark

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ReportExporter handles formatting and persisting benchmark reports in JSON and Markdown formats.
type ReportExporter struct{}

// NewReportExporter creates a new report exporter instance.
func NewReportExporter() *ReportExporter {
	return &ReportExporter{}
}

// GenerateJSON marshals a benchmark report into indented JSON bytes.
func (e *ReportExporter) GenerateJSON(rep BenchmarkReport) ([]byte, error) {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal benchmark report to JSON: %w", err)
	}
	return data, nil
}

// ExportJSON writes a benchmark report to disk formatted as indented JSON.
func (e *ReportExporter) ExportJSON(rep BenchmarkReport, filePath string) error {
	data, err := e.GenerateJSON(rep)
	if err != nil {
		return err
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write benchmark JSON report to %s: %w", filePath, err)
	}

	return nil
}

// GenerateMarkdownSummary formats benchmark metrics and failures into an executive Markdown table.
func (e *ReportExporter) GenerateMarkdownSummary(rep BenchmarkReport) string {
	var sb strings.Builder
	m := rep.Metrics

	sb.WriteString("# Aether Detection Accuracy & Validation Benchmark Report\n\n")
	sb.WriteString(fmt.Sprintf("**Date**: %s | **Aether Engine Version**: %s | **Benchmark Duration**: %dms\n\n", rep.Timestamp, rep.Version, rep.DurationMs))

	sb.WriteString("## 1. Executive Validation Summary\n\n")
	sb.WriteString(fmt.Sprintf("> *Aether was evaluated against %d total validation scenarios, achieving a measured **Precision of %.2f%%**, **Recall of %.2f%%**, **False-Positive Rate of %.2f%%**, and **Detection Coverage Index of %.2f%%** across cataloged threat classes.*\n\n",
		m.TotalCases, m.Precision*100, m.Recall*100, m.FalsePositiveRate*100, m.DetectionCoverageIndex))

	sb.WriteString("### Metric Scorecard\n\n")
	sb.WriteString("| Metric | Value | Target / Quality Gate | Status |\n")
	sb.WriteString("| :--- | :---: | :---: | :---: |\n")
	sb.WriteString(fmt.Sprintf("| **Precision** | `%.2f%%` | $\\ge 90.0\\%%$ | %s |\n", m.Precision*100, statusBadge(m.Precision >= 0.90)))
	sb.WriteString(fmt.Sprintf("| **Recall (Threat Detection)** | `%.2f%%` | $\\ge 95.0\\%%$ (Category B) | %s |\n", m.Recall*100, statusBadge(m.Recall >= 0.95)))
	sb.WriteString(fmt.Sprintf("| **False-Positive Rate (FPR)** | `%.2f%%` | $0.0\\%%$ (Category A Zero-FP) | %s |\n", m.FalsePositiveRate*100, statusBadge(m.FalsePositiveRate == 0.0)))
	sb.WriteString(fmt.Sprintf("| **F1-Score** | `%.4f` | $\\ge 0.9200$ | %s |\n", m.F1Score, statusBadge(m.F1Score >= 0.92)))
	sb.WriteString(fmt.Sprintf("| **Detection Coverage Index (DCI)** | `%.2f%%` | $100.0\\%%$ catalog coverage | %s |\n", m.DetectionCoverageIndex, statusBadge(m.DetectionCoverageIndex >= 100.0)))
	sb.WriteString(fmt.Sprintf("| **Suspicious Triage Accuracy** | `%.2f%%` | $\\ge 90.0\\%%$ triage accuracy | %s |\n", m.SuspiciousTriageAccuracy, statusBadge(m.SuspiciousTriageAccuracy >= 90.0)))
	sb.WriteString(fmt.Sprintf("| **Abstention Accuracy** | `%.2f%%` | $100.0\\%%$ (`UNKNOWN != SAFE`) | %s |\n\n", m.AbstentionAccuracy, statusBadge(m.AbstentionAccuracy == 100.0)))

	sb.WriteString("### Confusion Matrix Tallies\n\n")
	sb.WriteString("| Classification | Count | Description |\n")
	sb.WriteString("| :--- | :---: | :--- |\n")
	sb.WriteString(fmt.Sprintf("| **True Positives ($TP$)** | `%d` | Confirmed malicious threats correctly identified as `MALICIOUS` |\n", m.TruePositives))
	sb.WriteString(fmt.Sprintf("| **True Negatives ($TN$)** | `%d` | Benign and triaged non-malicious scenarios correctly classified |\n", m.TrueNegatives))
	sb.WriteString(fmt.Sprintf("| **False Positives ($FP$)** | `%d` | Benign or uncorroborated scenarios incorrectly escalated to `MALICIOUS` |\n", m.FalsePositives))
	sb.WriteString(fmt.Sprintf("| **False Negatives ($FN$)** | `%d` | Malicious threats missed or incorrectly classified as safe/unknown |\n\n", m.FalseNegatives))

	// Failed Cases Breakdown
	var failures []BenchmarkResult
	for _, r := range rep.Results {
		if !r.Passed {
			failures = append(failures, r)
		}
	}

	sb.WriteString(fmt.Sprintf("## 2. Failed Cases & Gap Analysis (%d total)\n\n", len(failures)))
	if len(failures) == 0 {
		sb.WriteString("✅ **100% of benchmark evaluation assertions passed. Zero detection gaps or false alarms detected.**\n\n")
	} else {
		sb.WriteString("| Case ID | Failure Classification | Normalized Target Path | Actual Verdict | Failure Details |\n")
		sb.WriteString("| :--- | :--- | :--- | :---: | :--- |\n")
		for _, f := range failures {
			sb.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | `%s` | %s |\n",
				f.CaseID, f.FailureClassification, f.NormalizedPath, f.ActualVerdict, f.FailureReason))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func statusBadge(pass bool) string {
	if pass {
		return "✅ PASS"
	}
	return "❌ FAIL"
}
