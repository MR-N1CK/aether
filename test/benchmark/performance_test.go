package benchmark_test

import (
	"runtime"
	"testing"
	"time"

	"aether/internal/benchmark"
	"aether/internal/config"
)

func TestBenchmarkPerformanceAndMemory(t *testing.T) {
	corpusRoot := benchmark.GetCorpusRoot()
	loader := benchmark.NewCorpusLoader(corpusRoot)
	cases, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("Failed to load corpus for performance test: %v", err)
	}

	cfg := config.NewDefaultConfig()
	adapter := benchmark.NewEngineAdapter(cfg)
	evaluator := benchmark.NewEvaluator()

	runtime.GC()
	var mBefore runtime.MemStats
	runtime.ReadMemStats(&mBefore)

	start := time.Now()
	for _, c := range cases {
		mockDB := benchmark.CreateMockPackageDBForCase(c)
		findings, durMs := adapter.ScanCase(c, mockDB)
		_ = evaluator.EvaluateCase(c, findings, durMs)
	}
	totalElapsed := time.Since(start)

	var mAfter runtime.MemStats
	runtime.ReadMemStats(&mAfter)

	allocMB := float64(mAfter.TotalAlloc-mBefore.TotalAlloc) / (1024 * 1024)
	avgMsPerCase := float64(totalElapsed.Milliseconds()) / float64(len(cases))

	t.Logf("Performance Scorecard: %d cases scanned in %v (avg %.2f ms/case). Total memory allocated: %.2f MB",
		len(cases), totalElapsed, avgMsPerCase, allocMB)

	// Invariant: Average inspection latency per small case must be strictly bounded (< 50ms)
	if avgMsPerCase > 50.0 {
		t.Errorf("Performance degradation: average latency per case %.2f ms exceeds 50ms threshold", avgMsPerCase)
	}

	// Invariant: Total memory allocation for benchmark run should be strictly bounded (< 100MB)
	if allocMB > 100.0 {
		t.Errorf("Memory budget exceeded: allocated %.2f MB exceeds 100MB bound", allocMB)
	}
}
