package benchmark

import (
	"encoding/json"
	"strings"
	"time"

	"aether/internal/report"
)

// CorpusCategory represents the top-level classification of a test scenario.
type CorpusCategory string

const (
	CategoryBenign            CorpusCategory = "BENIGN"
	CategoryMalicious         CorpusCategory = "MALICIOUS"
	CategorySuspicious        CorpusCategory = "SUSPICIOUS"
	CategoryEdgeCase          CorpusCategory = "EDGE_CASE"
	CategoryPartialVisibility CorpusCategory = "PARTIAL_VISIBILITY"
)

// BenchmarkCorpusCase represents an individual test scenario in the validation corpus.
type BenchmarkCorpusCase struct {
	ID                string          `json:"id"`
	Name              string          `json:"name"`
	Category          CorpusCategory  `json:"category"`
	Subcategory       string          `json:"subcategory"`
	TargetPath        string          `json:"target_path"`
	FileMode          uint32          `json:"file_mode,omitempty"`
	OwnerUID          uint32          `json:"owner_uid,omitempty"`
	IsPackageOwned    bool            `json:"is_package_owned,omitempty"`
	PackageName       string          `json:"package_name,omitempty"`
	Expected          ExpectedOutcome `json:"expected"`
	FixtureContent    []byte          `json:"-"`
	CorpusRelativeDir string          `json:"-"`
	MockProcDir       string          `json:"mock_proc_dir,omitempty"`
}

// ExpectedOutcome defines the immutable analytical contract for a corpus case.
type ExpectedOutcome struct {
	ExpectedVerdict           report.Verdict          `json:"verdict"`
	AllowedSeverities         []report.Severity       `json:"allowed_severities"`
	ExpectedStrength          report.EvidenceStrength `json:"evidence_strength"`
	RequiredCorroboration     []string                `json:"required_corroboration,omitempty"`
	MinConfidence             report.Confidence       `json:"min_confidence"`
	ExpectedRules             []string                `json:"expected_rules,omitempty"`
	MITRETechnique            string                  `json:"mitre_technique,omitempty"`
	ExpectedRationaleContains string                  `json:"expected_rationale_contains,omitempty"`
}

// UnmarshalJSON implements custom deserialization for ExpectedOutcome to normalize EvidenceStrength.
func (e *ExpectedOutcome) UnmarshalJSON(data []byte) error {
	type Alias ExpectedOutcome
	aux := &struct {
		Strength string `json:"evidence_strength"`
		*Alias
	}{
		Alias: (*Alias)(e),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	// Normalize strength conventions
	switch strings.ToUpper(aux.Strength) {
	case "STRENGTHDIRECT", "DIRECT":
		e.ExpectedStrength = report.StrengthDirect
	case "STRENGTHCORROBORATED", "CORROBORATED":
		e.ExpectedStrength = report.StrengthCorroborated
	case "STRENGTHCONTEXTUAL", "CONTEXTUAL":
		e.ExpectedStrength = report.StrengthContextual
	case "STRENGTHINCOMPLETE", "INCOMPLETE":
		e.ExpectedStrength = report.StrengthIncomplete
	default:
		e.ExpectedStrength = report.EvidenceStrength(aux.Strength)
	}

	return nil
}

// BenchmarkResult records the analytical outcome of running Aether against a corpus case.
type BenchmarkResult struct {
	CaseID                string            `json:"case_id"`
	Passed                bool              `json:"passed"`
	NormalizedPath        string            `json:"normalized_path,omitempty"`
	ActualVerdict         report.Verdict    `json:"actual_verdict"`
	ActualSeverity        report.Severity   `json:"actual_severity"`
	ActualStrength        string            `json:"actual_strength,omitempty"`
	ActualConfidence      report.Confidence `json:"actual_confidence,omitempty"`
	ActualRules           []string          `json:"actual_rules,omitempty"`
	ActualCorroboration   []string          `json:"actual_corroboration,omitempty"`
	ActualRationale       string            `json:"actual_rationale,omitempty"`
	FailureReason         string            `json:"failure_reason,omitempty"`
	FailureClassification string            `json:"failure_classification,omitempty"`
	DurationMs            int64             `json:"duration_ms"`
}

// BenchmarkMetrics stores aggregated statistical measurements with zero-denominator safety.
type BenchmarkMetrics struct {
	TotalCases               int          `json:"total_cases"`
	TruePositives            int          `json:"true_positives"`
	TrueNegatives            int          `json:"true_negatives"`
	FalsePositives           int          `json:"false_positives"`
	FalseNegatives           int          `json:"false_negatives"`
	Precision                float64      `json:"precision"`
	Recall                   float64      `json:"recall"`
	F1Score                  float64      `json:"f1_score"`
	FalsePositiveRate        float64      `json:"false_positive_rate"`
	DetectionCoverageIndex   float64      `json:"detection_coverage_index"`
	SuspiciousTriageAccuracy float64      `json:"suspicious_triage_accuracy"`
	AbstentionAccuracy       float64      `json:"abstention_accuracy"`
	EvasionResilienceScore   float64      `json:"evasion_resilience_score"`
	RuleAccuracy             []RuleFPStat `json:"rule_accuracy,omitempty"`
}

// RuleFPStat tracks one detection rule's behavior across the corpus: how
// often it fired on benign vs malicious fixtures, and how often its fire was
// adjudicated a false positive or an over-escalation. This is the data
// behind data-driven rule tuning — a rule whose benign-hit count grows
// without recall credit is a tuning candidate, not a guessing candidate.
type RuleFPStat struct {
	RuleName        string  `json:"rule_name"`
	BenignHits      int     `json:"benign_hits"`
	MaliciousHits   int     `json:"malicious_hits"`
	FalsePositives  int     `json:"false_positives"`
	OverEscalations int     `json:"over_escalations"`
	FPRatePercent   float64 `json:"fp_rate_percent"`
}

// RuleFPStatStatus classifies a rule's measured behavior for the report card.
func (s RuleFPStat) Status() string {
	switch {
	case s.FalsePositives > 0 || s.OverEscalations > 0:
		return "REVIEW"
	case s.BenignHits > 0:
		return "WATCH"
	default:
		return "OK"
	}
}

// BenchmarkReport encapsulates the serialized benchmark suite execution output.
type BenchmarkReport struct {
	Timestamp  string            `json:"timestamp"`
	Version    string            `json:"version"`
	DurationMs int64             `json:"duration_ms,omitempty"`
	Metrics    BenchmarkMetrics  `json:"metrics"`
	Results    []BenchmarkResult `json:"results"`
}

// ExplainabilityAudit records the validation of the 8-question explainability standard.
type ExplainabilityAudit struct {
	CaseID           string   `json:"case_id"`
	HasWhat          bool     `json:"has_what"`
	HasWhere         bool     `json:"has_where"`
	HasWhy           bool     `json:"has_why"`
	HasEvidence      bool     `json:"has_evidence"`
	HasContext       bool     `json:"has_context"`
	HasCorroboration bool     `json:"has_corroboration"`
	HasConfidence    bool     `json:"has_confidence"`
	HasRemediation   bool     `json:"has_remediation"`
	IsCompliant      bool     `json:"is_compliant"`
	FailureDetails   []string `json:"failure_details,omitempty"`
}

// NewBenchmarkCorpusCase returns an initialized case with defaults.
func NewBenchmarkCorpusCase(id, name string, cat CorpusCategory, subcat, target string, expected ExpectedOutcome) BenchmarkCorpusCase {
	return BenchmarkCorpusCase{
		ID:          id,
		Name:        name,
		Category:    cat,
		Subcategory: subcat,
		TargetPath:  target,
		FileMode:    0644,
		Expected:    expected,
	}
}

// MockProcessFixture represents synthetic process metadata for runtime benchmark fixtures.
type MockProcessFixture struct {
	PID          int      `json:"pid"`
	PPID         int      `json:"ppid,omitempty"`
	Comm         string   `json:"comm"`
	Exe          string   `json:"exe"`
	Cmdline      []string `json:"cmdline,omitempty"`
	Cwd          string   `json:"cwd,omitempty"`
	EUID         int      `json:"euid"`
	IsDeleted    bool     `json:"is_deleted,omitempty"`
	IsMemfd      bool     `json:"is_memfd,omitempty"`
	HasELFHeader bool     `json:"has_elf_header,omitempty"`
	MntNs        string   `json:"mnt_ns,omitempty"`
}

// MockSocketFixture represents synthetic network socket metadata for runtime benchmark fixtures.
type MockSocketFixture struct {
	Protocol   string `json:"protocol"` // "TCP", "TCP6", "UDP", "UDP6", "RAW", "PACKET"
	LocalIP    string `json:"local_ip"`
	LocalPort  int    `json:"local_port"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	State      string `json:"state"`
	Inode      uint64 `json:"inode"`
	OwningPID  int    `json:"owning_pid,omitempty"`
}

// BenchmarkRuntimeFixture encapsulates mock procfs structure references or definitions for a case.
type BenchmarkRuntimeFixture struct {
	CaseID            string               `json:"case_id"`
	MockProcfsRelPath string               `json:"mock_procfs_rel_path,omitempty"`
	MockProcesses     []MockProcessFixture `json:"mock_processes,omitempty"`
	MockSockets       []MockSocketFixture  `json:"mock_sockets,omitempty"`
}

// Duration returns the execution duration as a time.Duration.
func (r *BenchmarkResult) Duration() time.Duration {
	return time.Duration(r.DurationMs) * time.Millisecond
}
