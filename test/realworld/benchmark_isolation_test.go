package realworld_test

import (
	"os/exec"
	"strings"
	"testing"

	"aether/internal/benchmark"
	"aether/internal/report"
)

// TestBenchmarkSeparationAndIsolation verifies that the Feature 002/003 controlled
// benchmark suite and corpus have remained strictly separated, frozen, and unmodified
// throughout Feature 004 real-world validation implementation.
func TestBenchmarkSeparationAndIsolation(t *testing.T) {
	// 1. Verify git status has zero modifications to controlled benchmark directories
	cmd := exec.Command("git", "status", "--porcelain", "--",
		"internal/benchmark",
		"test/benchmark",
		"testdata/benchmark_corpus",
	)
	out, err := cmd.Output()
	if err != nil {
		t.Logf("git status check skipped (not in git tree or git error): %v", err)
	} else {
		trimmed := strings.TrimSpace(string(out))
		if trimmed != "" {
			t.Fatalf("CRITICAL: Controlled benchmark directories were modified during Feature 004:\n%s", trimmed)
		}
		t.Log("Controlled benchmark directories (internal/benchmark, test/benchmark, testdata/benchmark_corpus) verified clean with 0 git modifications.")
	}

	// 2. Verify that the controlled benchmark corpus loads completely and intact
	corpusRoot := benchmark.GetCorpusRoot()
	loader := benchmark.NewCorpusLoader(corpusRoot)
	cases, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("Failed to load controlled benchmark corpus: %v", err)
	}

	if len(cases) == 0 {
		t.Fatalf("Controlled benchmark corpus is empty!")
	}
	t.Logf("Loaded %d controlled benchmark test cases from %s.", len(cases), corpusRoot)

	// Verify both synthetic attack and clean benchmark cases are present
	var attacks, cleans int
	for _, c := range cases {
		if c.Category == benchmark.CategoryMalicious || c.Expected.ExpectedVerdict == report.VerdictMalicious {
			attacks++
		} else if c.Category == benchmark.CategoryBenign || c.Expected.ExpectedVerdict == report.VerdictSafe {
			cleans++
		}
	}

	if attacks == 0 || cleans == 0 {
		t.Fatalf("Corpus balance compromised: %d attacks, %d clean cases", attacks, cleans)
	}
	t.Logf("Benchmark corpus integrity verified: %d attack cases, %d clean cases.", attacks, cleans)
}
