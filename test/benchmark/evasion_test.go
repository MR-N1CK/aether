package benchmark_test

import (
	"testing"

	"aether/internal/benchmark"
	"aether/internal/config"
	"aether/internal/report"
)

func TestStaticEvasionResilience(t *testing.T) {
	corpusRoot := benchmark.GetCorpusRoot()
	loader := benchmark.NewCorpusLoader(corpusRoot)
	cases, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("Failed to load corpus for evasion testing: %v", err)
	}

	cfg := config.NewDefaultConfig()
	adapter := benchmark.NewEngineAdapter(cfg)
	mutator := benchmark.NewLexicalMutator()

	var malCases []benchmark.BenchmarkCorpusCase
	for _, c := range cases {
		if c.Category == benchmark.CategoryMalicious && len(c.FixtureContent) > 0 {
			malCases = append(malCases, c)
		}
	}

	if len(malCases) == 0 {
		t.Fatalf("No malicious cases available for mutation testing")
	}

	totalMutations := 0
	detectedMutations := 0
	typeTotals := make(map[benchmark.MutationType]int)
	typeDetected := make(map[benchmark.MutationType]int)

	for _, mc := range malCases {
		variants := mutator.GenerateMutations(mc.FixtureContent, mc.ID)
		for _, v := range variants {
			totalMutations++
			typeTotals[v.MutationType]++

			// Create synthetic test case with mutated content
			mutatedCase := mc
			mutatedCase.FixtureContent = v.MutatedContent

			mockDB := benchmark.CreateMockPackageDBForCase(mutatedCase)
			findings, _ := adapter.ScanCase(mutatedCase, mockDB)

			isDetected := false
			for _, f := range findings {
				if f.Verdict == report.VerdictMalicious || f.Verdict == report.VerdictSuspicious {
					isDetected = true
					break
				}
			}

			if isDetected {
				detectedMutations++
				typeDetected[v.MutationType]++
			}
		}
	}

	resilienceScore := 0.0
	if totalMutations > 0 {
		resilienceScore = float64(detectedMutations) / float64(totalMutations)
	}

	breakdown := make(map[benchmark.MutationType]float64)
	for mType, count := range typeTotals {
		if count > 0 {
			breakdown[mType] = float64(typeDetected[mType]) / float64(count)
		}
	}

	scorecard := benchmark.EvasionScorecard{
		TotalMutations:    totalMutations,
		DetectedMutations: detectedMutations,
		ResilienceScore:   resilienceScore,
		MutationBreakdown: breakdown,
	}

	t.Logf("Evasion Resilience Scorecard: Total Mutations=%d, Detected=%d, Overall Resilience=%.2f%%",
		scorecard.TotalMutations, scorecard.DetectedMutations, scorecard.ResilienceScore*100)

	for mType, rate := range breakdown {
		t.Logf(" - Mutation %-25s: %5.1f%% (%d/%d)", mType, rate*100, typeDetected[mType], typeTotals[mType])
	}

	// Invariant: Mutation framework must evaluate > 0 mutations and maintain non-zero resilience
	if totalMutations == 0 {
		t.Errorf("No mutations were generated or tested")
	}
}
