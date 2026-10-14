package benchmark

import (
	"fmt"
	"strings"

	"aether/internal/report"
)

// RegressionCase represents a historical false-positive scenario tracked permanently.
type RegressionCase struct {
	ID                string         `json:"id"`
	Description       string         `json:"description"`
	OriginalIssueDate string         `json:"original_issue_date"`
	TargetFile        string         `json:"target_file"`
	RootCause         string         `json:"root_cause"`
	CorpusCaseID      string         `json:"corpus_case_id"`
	ExpectedVerdict   report.Verdict `json:"expected_verdict"`
}

// RegressionResult records the evaluation outcome of a regression test case.
type RegressionResult struct {
	Case           RegressionCase  `json:"case"`
	Passed         bool            `json:"passed"`
	ActualVerdict  report.Verdict  `json:"actual_verdict"`
	ActualSeverity report.Severity `json:"actual_severity"`
	MatchedRules   []string        `json:"matched_rules"`
	FailureReason  string          `json:"failure_reason,omitempty"`
}

// RegressionManager manages historical false alarm tracking.
type RegressionManager struct {
	cases []RegressionCase
}

// NewRegressionManager initializes a manager preloaded with historical false-positive regression cases.
func NewRegressionManager() *RegressionManager {
	return &RegressionManager{
		cases: []RegressionCase{
			{
				ID:                "REG-PY-001",
				Description:       "Python .dist-info/METADATA with example curl | sh setup command in description",
				OriginalIssueDate: "2026-09-15",
				TargetFile:        "benign/03_python_packages/dist_info_metadata/METADATA",
				RootCause:         "Overbroad script heuristic matching inert documentation markdown",
				CorpusCaseID:      "BENIGN-PY-DOC-001",
				ExpectedVerdict:   report.VerdictSafe,
			},
			{
				ID:                "REG-PY-002",
				Description:       "Package unit test mock with test socket listener (test_mock.py)",
				OriginalIssueDate: "2026-09-20",
				TargetFile:        "benign/03_python_packages/unit_test_trees/test_mock.py",
				RootCause:         "Socket listener heuristic flagging mock server in package test directory",
				CorpusCaseID:      "BENIGN-PY-TEST-001",
				ExpectedVerdict:   report.VerdictSafe,
			},
			{
				ID:                "REG-PENTEST-001",
				Description:       "Authorized penetration testing tool in standard pentest package path",
				OriginalIssueDate: "2026-09-28",
				TargetFile:        "benign/05_pentest_tooling/mimikatz_test.txt",
				RootCause:         "Pentest framework signatures triggering ALERT without package whitelist check",
				CorpusCaseID:      "BENIGN-PENTEST-001",
				ExpectedVerdict:   report.VerdictSafe,
			},
			{
				ID:                "REG-DAEMON-001",
				Description:       "Standard systemd service unit for openssh-server",
				OriginalIssueDate: "2026-10-01",
				TargetFile:        "benign/01_system_daemons/sshd.service",
				RootCause:         "Systemd daemon listener misidentified as unauthorized backdoor listener",
				CorpusCaseID:      "BENIGN-DAEMON-001",
				ExpectedVerdict:   report.VerdictSafe,
			},
		},
	}
}

// GetAllCases returns all registered regression test cases.
func (m *RegressionManager) GetAllCases() []RegressionCase {
	return append([]RegressionCase(nil), m.cases...)
}

// RegisterCase adds an additional regression case to the manager.
func (m *RegressionManager) RegisterCase(c RegressionCase) {
	m.cases = append(m.cases, c)
}

// EvaluateRegressionRuns runs the regression cases against the corpus using the engine adapter.
func (m *RegressionManager) EvaluateRegressionRuns(adapter *EngineAdapter, loader *CorpusLoader) ([]RegressionResult, error) {
	corpusCases, err := loader.LoadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to load benchmark corpus for regression testing: %w", err)
	}

	caseMap := make(map[string]BenchmarkCorpusCase)
	for _, cc := range corpusCases {
		caseMap[cc.ID] = cc
	}

	var results []RegressionResult
	for _, rc := range m.cases {
		cc, exists := caseMap[rc.CorpusCaseID]
		if !exists {
			results = append(results, RegressionResult{
				Case:          rc,
				Passed:        false,
				FailureReason: fmt.Sprintf("referenced corpus case ID %s not found in corpus", rc.CorpusCaseID),
			})
			continue
		}

		mockDB := CreateMockPackageDBForCase(cc)
		findings, _ := adapter.ScanCase(cc, mockDB)

		var actualVerdict report.Verdict = report.VerdictSafe
		var actualSev report.Severity = report.SeverityInfo
		var ruleNames []string

		for _, f := range findings {
			ruleNames = append(ruleNames, f.RuleName)
			if f.Verdict == report.VerdictMalicious {
				actualVerdict = report.VerdictMalicious
				actualSev = f.Severity
			} else if f.Verdict == report.VerdictSuspicious && actualVerdict != report.VerdictMalicious {
				actualVerdict = report.VerdictSuspicious
				actualSev = f.Severity
			} else if f.Verdict == report.VerdictUnknown && actualVerdict == report.VerdictSafe {
				actualVerdict = report.VerdictUnknown
				actualSev = f.Severity
			}
		}

		// Regression Invariant: A false-positive regression case must NEVER produce VerdictMalicious
		passed := true
		var failureReason string

		if actualVerdict == report.VerdictMalicious {
			passed = false
			failureReason = fmt.Sprintf("CRITICAL REGRESSION: Historical false-positive case %s re-triggered MALICIOUS verdict with rules: %s", rc.ID, strings.Join(ruleNames, ", "))
		} else if rc.ExpectedVerdict != "" && actualVerdict != rc.ExpectedVerdict {
			passed = false
			failureReason = fmt.Sprintf("Verdict mismatch: expected %s, got %s", rc.ExpectedVerdict, actualVerdict)
		}

		results = append(results, RegressionResult{
			Case:           rc,
			Passed:         passed,
			ActualVerdict:  actualVerdict,
			ActualSeverity: actualSev,
			MatchedRules:   ruleNames,
			FailureReason:  failureReason,
		})
	}

	return results, nil
}
