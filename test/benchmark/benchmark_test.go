package benchmark_test

import (
	"os"
	"testing"
	"time"

	"aether/internal/benchmark"
	"aether/internal/config"
	"aether/internal/report"
)

func TestRunDetectionBenchmark(t *testing.T) {
	corpusRoot := benchmark.GetCorpusRoot()
	loader := benchmark.NewCorpusLoader(corpusRoot)
	cases, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("Failed to load benchmark corpus: %v", err)
	}

	if len(cases) == 0 {
		t.Fatalf("Corpus loader returned 0 cases from %s", corpusRoot)
	}

	cfg := config.NewDefaultConfig()
	adapter := benchmark.NewEngineAdapter(cfg)
	evaluator := benchmark.NewEvaluator()
	calc := benchmark.NewMetricsCalculator()
	exporter := benchmark.NewReportExporter()

	var results []benchmark.BenchmarkResult

	for _, c := range cases {
		mockDB := benchmark.CreateMockPackageDBForCase(c)
		findings, durMs := adapter.ScanCase(c, mockDB)
		res := evaluator.EvaluateCase(c, findings, durMs)
		results = append(results, res)
	}

	metrics := calc.CalculateMetrics(cases, results)

	rep := benchmark.BenchmarkReport{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Version:    "1.0.0",
		DurationMs: 0,
		Metrics:    metrics,
		Results:    results,
	}

	summary := exporter.GenerateMarkdownSummary(rep)
	t.Logf("\n%s\n", summary)

	// Save report if path provided in environment
	if outPath := os.Getenv("AETHER_BENCHMARK_REPORT"); outPath != "" {
		_ = exporter.ExportJSON(rep, outPath)
	}
}

func TestCategoryA_Benign(t *testing.T) {
	corpusRoot := benchmark.GetCorpusRoot()
	loader := benchmark.NewCorpusLoader(corpusRoot)
	cases, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("Failed to load corpus: %v", err)
	}

	cfg := config.NewDefaultConfig()
	adapter := benchmark.NewEngineAdapter(cfg)
	evaluator := benchmark.NewEvaluator()

	var benignCases []benchmark.BenchmarkCorpusCase
	for _, c := range cases {
		if c.Category == benchmark.CategoryBenign {
			benignCases = append(benignCases, c)
		}
	}

	if len(benignCases) == 0 {
		t.Fatalf("No Category A Benign cases found in corpus")
	}

	for _, c := range benignCases {
		t.Run(c.ID+"_"+c.Name, func(t *testing.T) {
			mockDB := benchmark.CreateMockPackageDBForCase(c)
			findings, durMs := adapter.ScanCase(c, mockDB)
			res := evaluator.EvaluateCase(c, findings, durMs)

			// Zero-Tolerance Invariant: Benign case must NEVER produce VerdictMalicious
			if res.ActualVerdict == report.VerdictMalicious {
				t.Fatalf("CRITICAL: Benign fixture %s produced MALICIOUS verdict (%s). FPR violation!", c.ID, res.ActualRules)
			}
			if !res.Passed {
				t.Errorf("Benign case %s failed evaluation: %s", c.ID, res.FailureReason)
			}
		})
	}
}

func TestCategoryB_Malicious(t *testing.T) {
	corpusRoot := benchmark.GetCorpusRoot()
	loader := benchmark.NewCorpusLoader(corpusRoot)
	cases, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("Failed to load corpus: %v", err)
	}

	cfg := config.NewDefaultConfig()
	adapter := benchmark.NewEngineAdapter(cfg)
	evaluator := benchmark.NewEvaluator()

	var malCases []benchmark.BenchmarkCorpusCase
	for _, c := range cases {
		if c.Category == benchmark.CategoryMalicious {
			malCases = append(malCases, c)
		}
	}

	if len(malCases) == 0 {
		t.Fatalf("No Category B Malicious cases found in corpus")
	}

	detected := 0
	for _, c := range malCases {
		t.Run(c.ID+"_"+c.Name, func(t *testing.T) {
			mockDB := benchmark.CreateMockPackageDBForCase(c)
			findings, durMs := adapter.ScanCase(c, mockDB)
			res := evaluator.EvaluateCase(c, findings, durMs)

			if res.Passed {
				detected++
			} else {
				t.Errorf("Malicious fixture %s failed contract evaluation: %s", c.ID, res.FailureReason)
			}
		})
	}

	recall := float64(detected) / float64(len(malCases))
	if recall < 0.95 {
		t.Errorf("Threat Recall below 95%% threshold: got %.2f%% (%d/%d)", recall*100, detected, len(malCases))
	}
}

func TestCategoryC_Suspicious(t *testing.T) {
	corpusRoot := benchmark.GetCorpusRoot()
	loader := benchmark.NewCorpusLoader(corpusRoot)
	cases, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("Failed to load corpus: %v", err)
	}

	cfg := config.NewDefaultConfig()
	adapter := benchmark.NewEngineAdapter(cfg)
	evaluator := benchmark.NewEvaluator()

	var suspCases []benchmark.BenchmarkCorpusCase
	for _, c := range cases {
		if c.Category == benchmark.CategorySuspicious {
			suspCases = append(suspCases, c)
		}
	}

	for _, c := range suspCases {
		t.Run(c.ID+"_"+c.Name, func(t *testing.T) {
			mockDB := benchmark.CreateMockPackageDBForCase(c)
			findings, durMs := adapter.ScanCase(c, mockDB)
			res := evaluator.EvaluateCase(c, findings, durMs)

			// Over-escalation check: uncorroborated suspicious should not become MALICIOUS
			if res.ActualVerdict == report.VerdictMalicious {
				t.Fatalf("Suspicious fixture %s over-escalated to MALICIOUS without corroboration!", c.ID)
			}
			if !res.Passed {
				t.Fatalf("Suspicious fixture %s failed contract evaluation: %s (actual verdict: %s, severity: %s, rules: %v)",
					c.ID, res.FailureReason, res.ActualVerdict, res.ActualSeverity, res.ActualRules)
			}
		})
	}
}

func TestCategoryE_PartialVisibility(t *testing.T) {
	corpusRoot := benchmark.GetCorpusRoot()
	loader := benchmark.NewCorpusLoader(corpusRoot)
	cases, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("Failed to load corpus: %v", err)
	}

	cfg := config.NewDefaultConfig()
	adapter := benchmark.NewEngineAdapter(cfg)
	evaluator := benchmark.NewEvaluator()

	var partialCases []benchmark.BenchmarkCorpusCase
	for _, c := range cases {
		if c.Category == benchmark.CategoryPartialVisibility {
			partialCases = append(partialCases, c)
		}
	}

	for _, c := range partialCases {
		t.Run(c.ID+"_"+c.Name, func(t *testing.T) {
			mockDB := benchmark.CreateMockPackageDBForCase(c)
			findings, durMs := adapter.ScanCase(c, mockDB)
			res := evaluator.EvaluateCase(c, findings, durMs)

			// Invariant: UNKNOWN != SAFE
			if res.ActualVerdict == report.VerdictSafe {
				t.Fatalf("Partial visibility fixture %s produced SAFE verdict (false clean pass)!", c.ID)
			}
			if res.ActualVerdict != report.VerdictUnknown {
				t.Fatalf("Expected UNKNOWN verdict for %s, got %s", c.ID, res.ActualVerdict)
			}
		})
	}
}

func TestCategoryD_EdgeCases(t *testing.T) {
	corpusRoot := benchmark.GetCorpusRoot()
	loader := benchmark.NewCorpusLoader(corpusRoot)
	cases, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("Failed to load corpus: %v", err)
	}

	cfg := config.NewDefaultConfig()
	adapter := benchmark.NewEngineAdapter(cfg)
	evaluator := benchmark.NewEvaluator()

	var edgeCases []benchmark.BenchmarkCorpusCase
	for _, c := range cases {
		if c.Category == benchmark.CategoryEdgeCase {
			edgeCases = append(edgeCases, c)
		}
	}

	if len(edgeCases) == 0 {
		t.Fatalf("No Category D Edge cases found in corpus")
	}

	for _, c := range edgeCases {
		t.Run(c.ID+"_"+c.Name, func(t *testing.T) {
			mockDB := benchmark.CreateMockPackageDBForCase(c)
			findings, durMs := adapter.ScanCase(c, mockDB)
			res := evaluator.EvaluateCase(c, findings, durMs)

			if !res.Passed {
				t.Fatalf("Edge case fixture %s failed contract evaluation: %s (actual verdict: %s)", c.ID, res.FailureReason, res.ActualVerdict)
			}
			if c.ID == "EDGE-TROJAN-001" {
				if res.ActualVerdict != report.VerdictMalicious {
					t.Fatalf("CRITICAL: Trojanized package file %s produced non-malicious verdict %s!", c.ID, res.ActualVerdict)
				}
			}
		})
	}
}
