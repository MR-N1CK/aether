package benchmark_test

import (
	"testing"

	"aether/internal/benchmark"
	"aether/internal/config"
	"aether/internal/report"
)

func TestExplainabilityCompliance(t *testing.T) {
	corpusRoot := benchmark.GetCorpusRoot()
	loader := benchmark.NewCorpusLoader(corpusRoot)
	cases, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("Failed to load corpus for explainability testing: %v", err)
	}

	cfg := config.NewDefaultConfig()
	adapter := benchmark.NewEngineAdapter(cfg)
	auditor := benchmark.NewExplainabilityAuditor()

	var allFindings []*report.Finding
	for _, c := range cases {
		mockDB := benchmark.CreateMockPackageDBForCase(c)
		findings, _ := adapter.ScanCase(c, mockDB)
		allFindings = append(allFindings, findings...)
	}

	if len(allFindings) == 0 {
		t.Fatalf("Benchmark scan produced 0 findings across corpus")
	}

	summary := auditor.AuditFindings(allFindings)

	t.Logf("Explainability Audit Results: %d/%d findings compliant (%.2f%%)",
		summary.CompliantFindings, summary.TotalFindings, summary.ComplianceRate*100)

	for question, passRate := range summary.QuestionBreakdown {
		t.Logf(" - Question %-15s: %5.1f%% pass rate", question, passRate*100)
	}

	if summary.ComplianceRate < 1.0 {
		for _, failed := range summary.FailedAudits {
			t.Errorf("Finding %s (%s, %s) failed explainability standard: %v",
				failed.FindingID, failed.RuleName, failed.TargetPath, failed.MissingElements)
		}
		t.Fatalf("Explainability compliance below mandatory 100%% standard: got %.2f%%", summary.ComplianceRate*100)
	}
}

func TestMultiEnvironmentConsistency(t *testing.T) {
	corpusRoot := benchmark.GetCorpusRoot()
	loader := benchmark.NewCorpusLoader(corpusRoot)
	cases, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("Failed to load corpus: %v", err)
	}

	cfg := config.NewDefaultConfig()
	adapter := benchmark.NewEngineAdapter(cfg)
	evaluator := benchmark.NewEvaluator()

	distros := []benchmark.DistroProfile{
		benchmark.DistroDebian,
		benchmark.DistroArch,
		benchmark.DistroRPM,
	}

	for _, c := range cases {
		var baselineResult benchmark.BenchmarkResult
		for i, distro := range distros {
			mockDB := benchmark.CreateMockPackageDBForEnvironment(c, distro)
			findings, durMs := adapter.ScanCase(c, mockDB)
			res := evaluator.EvaluateCase(c, findings, durMs)

			if i == 0 {
				baselineResult = res
			} else {
				// Assert cross-environment consistency for managed packages
				if res.ActualVerdict != baselineResult.ActualVerdict {
					t.Errorf("Inconsistent verdict for case %s across distros: %s got %s, but Debian got %s",
						c.ID, distro, res.ActualVerdict, baselineResult.ActualVerdict)
				}
			}
		}
	}
}
