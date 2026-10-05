package benchmark

import (
	"encoding/json"
	"testing"
	"time"

	"aether/internal/report"
)

func TestBenchmarkCorpusCaseSerialization(t *testing.T) {
	sample := BenchmarkCorpusCase{
		ID:          "CORPUS-MAL-001",
		Name:        "Bash Interactive Reverse Shell",
		Category:    CategoryMalicious,
		Subcategory: "reverse_shell_interactive",
		TargetPath:  "fixtures/malicious/revshell_bash.sh",
		FileMode:    0755,
		OwnerUID:    1000,
		Expected: ExpectedOutcome{
			ExpectedVerdict:           report.VerdictMalicious,
			AllowedSeverities:         []report.Severity{report.SeverityAlert},
			ExpectedStrength:          report.StrengthDirect,
			MinConfidence:             report.ConfidenceHigh,
			ExpectedRules:             []string{"Script_Reverse_Shell_Interactive"},
			MITRETechnique:            "T1059.004",
			ExpectedRationaleContains: "Interactive reverse shell",
		},
	}

	data, err := json.Marshal(sample)
	if err != nil {
		t.Fatalf("Failed to marshal BenchmarkCorpusCase: %v", err)
	}

	var parsed BenchmarkCorpusCase
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal BenchmarkCorpusCase: %v", err)
	}

	if parsed.ID != sample.ID {
		t.Errorf("Expected ID %s, got %s", sample.ID, parsed.ID)
	}
	if parsed.Expected.ExpectedVerdict != report.VerdictMalicious {
		t.Errorf("Expected Verdict %s, got %s", report.VerdictMalicious, parsed.Expected.ExpectedVerdict)
	}
	if parsed.Expected.ExpectedStrength != report.StrengthDirect {
		t.Errorf("Expected Strength %s, got %s", report.StrengthDirect, parsed.Expected.ExpectedStrength)
	}
}

func TestBenchmarkReportSerialization(t *testing.T) {
	reportObj := BenchmarkReport{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Version:    "1.0.0",
		DurationMs: 1250,
		Metrics: BenchmarkMetrics{
			TotalCases:               100,
			TruePositives:            30,
			TrueNegatives:            50,
			FalsePositives:           0,
			FalseNegatives:           0,
			Precision:                1.0,
			Recall:                   1.0,
			F1Score:                  1.0,
			FalsePositiveRate:        0.0,
			DetectionCoverageIndex:   100.0,
			SuspiciousTriageAccuracy: 100.0,
			AbstentionAccuracy:       100.0,
			EvasionResilienceScore:   92.5,
		},
		Results: []BenchmarkResult{
			{
				CaseID:         "BENIGN-001",
				Passed:         true,
				NormalizedPath: "benign/01_system_daemons/sshd.service",
				ActualVerdict:  report.VerdictSafe,
				ActualSeverity: report.SeverityNotice,
				DurationMs:     5,
			},
		},
	}

	data, err := json.Marshal(reportObj)
	if err != nil {
		t.Fatalf("Failed to marshal BenchmarkReport: %v", err)
	}

	var parsed BenchmarkReport
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal BenchmarkReport: %v", err)
	}

	if parsed.Metrics.TotalCases != 100 {
		t.Errorf("Expected TotalCases 100, got %d", parsed.Metrics.TotalCases)
	}
	if parsed.Metrics.Precision != 1.0 {
		t.Errorf("Expected Precision 1.0, got %f", parsed.Metrics.Precision)
	}
	if len(parsed.Results) != 1 || parsed.Results[0].CaseID != "BENIGN-001" {
		t.Errorf("Unexpected results in parsed report: %+v", parsed.Results)
	}
}
