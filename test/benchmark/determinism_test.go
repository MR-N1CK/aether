package benchmark_test

import (
	"bytes"
	"sync"
	"testing"

	"aether/internal/benchmark"
	"aether/internal/config"
)

func TestDeterminism_10ConcurrentRuns(t *testing.T) {
	corpusRoot := benchmark.GetCorpusRoot()
	loader := benchmark.NewCorpusLoader(corpusRoot)
	cases, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("Failed to load corpus for determinism test: %v", err)
	}

	const iterations = 10
	resultsJSON := make([][]byte, iterations)
	var wg sync.WaitGroup

	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func(runIdx int) {
			defer wg.Done()

			cfg := config.NewDefaultConfig()
			adapter := benchmark.NewEngineAdapter(cfg)
			evaluator := benchmark.NewEvaluator()
			calc := benchmark.NewMetricsCalculator()
			exporter := benchmark.NewReportExporter()

			var runResults []benchmark.BenchmarkResult
			for _, c := range cases {
				mockDB := benchmark.CreateMockPackageDBForCase(c)
				findings, _ := adapter.ScanCase(c, mockDB)
				// Use fixed 0ms duration for determinism comparison
				res := evaluator.EvaluateCase(c, findings, 0)
				runResults = append(runResults, res)
			}

			metrics := calc.CalculateMetrics(cases, runResults)
			rep := benchmark.BenchmarkReport{
				Timestamp:  "2026-10-01T00:00:00Z", // Fixed timestamp for determinism comparison
				Version:    "1.0.0",
				DurationMs: 0,
				Metrics:    metrics,
				Results:    runResults,
			}

			jsonBytes, err := exporter.GenerateJSON(rep)
			if err != nil {
				t.Errorf("Run %d failed to generate JSON: %v", runIdx, err)
				return
			}
			resultsJSON[runIdx] = jsonBytes
		}(i)
	}

	wg.Wait()

	baseline := resultsJSON[0]
	if len(baseline) == 0 {
		t.Fatalf("Baseline run 0 generated empty JSON")
	}

	for i := 1; i < iterations; i++ {
		if !bytes.Equal(baseline, resultsJSON[i]) {
			t.Fatalf("Determinism violation: Run %d produced different JSON output from Run 0 (byte lengths %d vs %d)",
				i, len(resultsJSON[i]), len(baseline))
		}
	}

	t.Logf("Determinism Verified: %d concurrent runs produced 100%% byte-for-byte identical JSON (%d bytes)",
		iterations, len(baseline))
}
