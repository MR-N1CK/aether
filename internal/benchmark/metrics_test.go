package benchmark

import (
	"encoding/json"
	"math"
	"testing"

	"aether/internal/report"
)

func TestMetricsCalculator_PerfectScores(t *testing.T) {
	calc := NewMetricsCalculator()

	cases := []BenchmarkCorpusCase{
		{ID: "MAL-001", Category: CategoryMalicious, Subcategory: "reverse_shells", Expected: ExpectedOutcome{ExpectedVerdict: report.VerdictMalicious}},
		{ID: "BEN-001", Category: CategoryBenign, Subcategory: "system_daemons", Expected: ExpectedOutcome{ExpectedVerdict: report.VerdictSafe}},
		{ID: "SUSP-001", Category: CategorySuspicious, Subcategory: "dual_use", Expected: ExpectedOutcome{ExpectedVerdict: report.VerdictSuspicious}},
		{ID: "PART-001", Category: CategoryPartialVisibility, Subcategory: "unreadable_shadow", Expected: ExpectedOutcome{ExpectedVerdict: report.VerdictUnknown}},
	}

	results := []BenchmarkResult{
		{CaseID: "MAL-001", ActualVerdict: report.VerdictMalicious, Passed: true},
		{CaseID: "BEN-001", ActualVerdict: report.VerdictSafe, Passed: true},
		{CaseID: "SUSP-001", ActualVerdict: report.VerdictSuspicious, Passed: true},
		{CaseID: "PART-001", ActualVerdict: report.VerdictUnknown, Passed: true},
	}

	m := calc.CalculateMetrics(cases, results)

	if m.TruePositives != 1 {
		t.Errorf("Expected TP 1, got %d", m.TruePositives)
	}
	if m.TrueNegatives != 3 {
		t.Errorf("Expected TN 3, got %d", m.TrueNegatives)
	}
	if m.FalsePositives != 0 {
		t.Errorf("Expected FP 0, got %d", m.FalsePositives)
	}
	if m.FalseNegatives != 0 {
		t.Errorf("Expected FN 0, got %d", m.FalseNegatives)
	}
	if m.Precision != 1.0 {
		t.Errorf("Expected Precision 1.0, got %f", m.Precision)
	}
	if m.Recall != 1.0 {
		t.Errorf("Expected Recall 1.0, got %f", m.Recall)
	}
	if m.F1Score != 1.0 {
		t.Errorf("Expected F1 1.0, got %f", m.F1Score)
	}
	if m.FalsePositiveRate != 0.0 {
		t.Errorf("Expected FPR 0.0, got %f", m.FalsePositiveRate)
	}
	if m.SuspiciousTriageAccuracy != 100.0 {
		t.Errorf("Expected SuspiciousTriageAccuracy 100.0, got %f", m.SuspiciousTriageAccuracy)
	}
	if m.AbstentionAccuracy != 100.0 {
		t.Errorf("Expected AbstentionAccuracy 100.0, got %f", m.AbstentionAccuracy)
	}
}

func TestMetricsCalculator_ZeroDenominators(t *testing.T) {
	calc := NewMetricsCalculator()

	// Empty results
	m := calc.CalculateMetrics(nil, nil)

	if math.IsNaN(m.Precision) || math.IsInf(m.Precision, 0) {
		t.Errorf("Precision produced NaN or Inf: %f", m.Precision)
	}
	if math.IsNaN(m.Recall) || math.IsInf(m.Recall, 0) {
		t.Errorf("Recall produced NaN or Inf: %f", m.Recall)
	}
	if math.IsNaN(m.F1Score) || math.IsInf(m.F1Score, 0) {
		t.Errorf("F1Score produced NaN or Inf: %f", m.F1Score)
	}
	if math.IsNaN(m.FalsePositiveRate) || math.IsInf(m.FalsePositiveRate, 0) {
		t.Errorf("FalsePositiveRate produced NaN or Inf: %f", m.FalsePositiveRate)
	}

	// Verify valid JSON marshalling without error
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("JSON marshal failed on zero-denominator metrics: %v", err)
	}
	if string(data) == "" {
		t.Errorf("Empty JSON serialized")
	}
}

func TestMetricsCalculator_OverEscalationAndUnderClassification(t *testing.T) {
	calc := NewMetricsCalculator()

	cases := []BenchmarkCorpusCase{
		{ID: "SUSP-001", Category: CategorySuspicious, Subcategory: "dual_use", Expected: ExpectedOutcome{ExpectedVerdict: report.VerdictSuspicious}},
		{ID: "SUSP-002", Category: CategorySuspicious, Subcategory: "dual_use", Expected: ExpectedOutcome{ExpectedVerdict: report.VerdictSuspicious}},
	}

	results := []BenchmarkResult{
		{CaseID: "SUSP-001", ActualVerdict: report.VerdictMalicious}, // Over-escalation -> FP
		{CaseID: "SUSP-002", ActualVerdict: report.VerdictSafe},      // Under-classification -> TN for binary malware, but reduces SuspiciousTriageAccuracy
	}

	m := calc.CalculateMetrics(cases, results)

	if m.FalsePositives != 1 {
		t.Errorf("Expected FP 1 from over-escalation, got %d", m.FalsePositives)
	}
	if m.TrueNegatives != 1 {
		t.Errorf("Expected TN 1 from non-malicious classification, got %d", m.TrueNegatives)
	}
	if m.SuspiciousTriageAccuracy != 0.0 {
		t.Errorf("Expected SuspiciousTriageAccuracy 0.0, got %f", m.SuspiciousTriageAccuracy)
	}
}

func TestMetricsCalculator_HarmonicMeanIntegrity(t *testing.T) {
	calc := NewMetricsCalculator()

	cases := []BenchmarkCorpusCase{
		{ID: "MAL-1", Category: CategoryMalicious, Subcategory: "c1", Expected: ExpectedOutcome{ExpectedVerdict: report.VerdictMalicious}},
		{ID: "MAL-2", Category: CategoryMalicious, Subcategory: "c2", Expected: ExpectedOutcome{ExpectedVerdict: report.VerdictMalicious}},
		{ID: "MAL-3", Category: CategoryMalicious, Subcategory: "c3", Expected: ExpectedOutcome{ExpectedVerdict: report.VerdictMalicious}},
		{ID: "BEN-1", Category: CategoryBenign, Subcategory: "b1", Expected: ExpectedOutcome{ExpectedVerdict: report.VerdictSafe}},
		{ID: "BEN-2", Category: CategoryBenign, Subcategory: "b2", Expected: ExpectedOutcome{ExpectedVerdict: report.VerdictSafe}},
	}

	// TP = 2, FN = 1, FP = 1, TN = 1
	results := []BenchmarkResult{
		{CaseID: "MAL-1", ActualVerdict: report.VerdictMalicious},
		{CaseID: "MAL-2", ActualVerdict: report.VerdictMalicious},
		{CaseID: "MAL-3", ActualVerdict: report.VerdictSafe},
		{CaseID: "BEN-1", ActualVerdict: report.VerdictMalicious}, // FP
		{CaseID: "BEN-2", ActualVerdict: report.VerdictSafe},      // TN
	}

	m := calc.CalculateMetrics(cases, results)

	expectedP := 2.0 / 3.0 // 0.6667
	expectedR := 2.0 / 3.0 // 0.6667
	expectedF1 := 2.0 * (expectedP * expectedR) / (expectedP + expectedR)

	if math.Abs(m.Precision-math.Round(expectedP*10000)/10000) > 0.0001 {
		t.Errorf("Precision mismatch: expected %f, got %f", expectedP, m.Precision)
	}
	if math.Abs(m.Recall-math.Round(expectedR*10000)/10000) > 0.0001 {
		t.Errorf("Recall mismatch: expected %f, got %f", expectedR, m.Recall)
	}
	if math.Abs(m.F1Score-math.Round(expectedF1*10000)/10000) > 0.0001 {
		t.Errorf("F1Score mismatch: expected %f, got %f", expectedF1, m.F1Score)
	}
}
