package benchmark_test

import (
	"testing"

	"aether/internal/benchmark"
	"aether/internal/config"
	"aether/internal/report"
)

func TestRegressionSuite(t *testing.T) {
	corpusRoot := benchmark.GetCorpusRoot()
	loader := benchmark.NewCorpusLoader(corpusRoot)
	cfg := config.NewDefaultConfig()
	adapter := benchmark.NewEngineAdapter(cfg)
	regMgr := benchmark.NewRegressionManager()

	results, err := regMgr.EvaluateRegressionRuns(adapter, loader)
	if err != nil {
		t.Fatalf("Failed to execute regression test suite: %v", err)
	}

	if len(results) == 0 {
		t.Fatalf("Regression manager returned 0 cases")
	}

	for _, res := range results {
		t.Run(res.Case.ID+"_"+res.Case.Description, func(t *testing.T) {
			if res.ActualVerdict == report.VerdictMalicious {
				t.Fatalf("CRITICAL REGRESSION: %s re-escalated to MALICIOUS! Rules: %v", res.Case.ID, res.MatchedRules)
			}
			if !res.Passed {
				t.Errorf("Regression case %s failed: %s", res.Case.ID, res.FailureReason)
			}
		})
	}
}
