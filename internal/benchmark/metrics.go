package benchmark

import (
	"math"
	"sort"

	"aether/internal/report"
)

const TotalCatalogedMaliciousSubclasses = 12

// MetricsCalculator aggregates benchmark execution results into mathematical metrics.
type MetricsCalculator struct{}

// NewMetricsCalculator creates a new metric calculator instance.
func NewMetricsCalculator() *MetricsCalculator {
	return &MetricsCalculator{}
}

// CalculateMetrics aggregates results into verifiable statistical metrics with zero-denominator safety.
func (m *MetricsCalculator) CalculateMetrics(cases []BenchmarkCorpusCase, results []BenchmarkResult) BenchmarkMetrics {
	caseMap := make(map[string]BenchmarkCorpusCase, len(cases))
	for _, c := range cases {
		caseMap[c.ID] = c
	}

	var tp, tn, fp, fn int
	var catCTotal, catCCorrect int
	var catETotal, catECorrect int
	detectedMalSubclasses := make(map[string]bool)
	ruleStats := make(map[string]*RuleFPStat)

	ruleStatFor := func(name string) *RuleFPStat {
		st, ok := ruleStats[name]
		if !ok {
			st = &RuleFPStat{RuleName: name}
			ruleStats[name] = st
		}
		return st
	}

	for _, r := range results {
		c, ok := caseMap[r.CaseID]
		if !ok {
			continue
		}

		// 0. Per-rule behavior tracking: every rule that fired gets credit or
		// scrutiny depending on the ground truth and the case's adjudication.
		isMaliciousGroundTruth := c.Expected.ExpectedVerdict == report.VerdictMalicious
		for _, name := range r.ActualRules {
			st := ruleStatFor(name)
			if isMaliciousGroundTruth {
				st.MaliciousHits++
			} else {
				st.BenignHits++
			}
			switch r.FailureClassification {
			case "FALSE_POSITIVE":
				st.FalsePositives++
			case "OVER_ESCALATION":
				st.OverEscalations++
			}
		}
		// 1. Binary Threat Classification (Ground Truth MALICIOUS vs Non-MALICIOUS)
		if c.Expected.ExpectedVerdict == report.VerdictMalicious {
			if r.ActualVerdict == report.VerdictMalicious {
				tp++
			} else {
				fn++
			}
		} else {
			if r.ActualVerdict == report.VerdictMalicious {
				fp++ // Over-escalation to MALICIOUS
			} else {
				tn++ // Correctly classified as non-MALICIOUS (SAFE / SUSPICIOUS / UNKNOWN)
			}
		}

		// 2. Threat Subcategory Coverage Tracking
		if (c.Category == CategoryMalicious || c.Expected.ExpectedVerdict == report.VerdictMalicious) &&
			(r.ActualVerdict == report.VerdictMalicious || (c.Expected.ExpectedVerdict == report.VerdictSuspicious && r.ActualVerdict == report.VerdictSuspicious)) {
			if c.Subcategory != "" {
				detectedMalSubclasses[c.Subcategory] = true
			}
		}

		// 3. Category C: Suspicious Triage Tracking
		if c.Category == CategorySuspicious {
			catCTotal++
			if r.ActualVerdict == report.VerdictSuspicious {
				catCCorrect++
			}
		}

		// 4. Category E: Partial Visibility / Abstention Tracking
		if c.Category == CategoryPartialVisibility {
			catETotal++
			if r.ActualVerdict == report.VerdictUnknown {
				catECorrect++
			}
		}
	}

	metrics := BenchmarkMetrics{
		TotalCases:     len(results),
		TruePositives:  tp,
		TrueNegatives:  tn,
		FalsePositives: fp,
		FalseNegatives: fn,
	}

	// 1. Precision calculation with zero-denominator safety
	if tp+fp == 0 {
		if fp == 0 {
			metrics.Precision = 1.0 // Zero false alarms raised
		} else {
			metrics.Precision = 0.0
		}
	} else {
		metrics.Precision = float64(tp) / float64(tp+fp)
	}

	// 2. Recall calculation with zero-denominator safety
	if tp+fn == 0 {
		if fn == 0 {
			metrics.Recall = 1.0 // Zero positive targets missed
		} else {
			metrics.Recall = 0.0
		}
	} else {
		metrics.Recall = float64(tp) / float64(tp+fn)
	}

	// 3. F1-Score calculation
	if metrics.Precision+metrics.Recall == 0 {
		metrics.F1Score = 0.0
	} else {
		metrics.F1Score = 2 * (metrics.Precision * metrics.Recall) / (metrics.Precision + metrics.Recall)
	}

	// 4. False Positive Rate calculation
	if fp+tn == 0 {
		metrics.FalsePositiveRate = 0.0
	} else {
		metrics.FalsePositiveRate = float64(fp) / float64(fp+tn)
	}

	// 5. Detection Coverage Index
	metrics.DetectionCoverageIndex = (float64(len(detectedMalSubclasses)) / float64(TotalCatalogedMaliciousSubclasses)) * 100.0
	if metrics.DetectionCoverageIndex > 100.0 {
		metrics.DetectionCoverageIndex = 100.0
	}

	// 6. Suspicious Triage Accuracy
	if catCTotal == 0 {
		metrics.SuspiciousTriageAccuracy = 100.0
	} else {
		metrics.SuspiciousTriageAccuracy = (float64(catCCorrect) / float64(catCTotal)) * 100.0
	}

	// 7. Abstention Accuracy
	if catETotal == 0 {
		metrics.AbstentionAccuracy = 100.0
	} else {
		metrics.AbstentionAccuracy = (float64(catECorrect) / float64(catETotal)) * 100.0
	}

	// 8. Per-rule accuracy report card: FP-rate per rule, sorted worst-first
	// so tuning candidates surface at the top. Deterministic total order
	// (FP count → benign hits → name) — the determinism gate byte-compares
	// benchmark reports across runs.
	ruleAccuracy := make([]RuleFPStat, 0, len(ruleStats))
	for _, st := range ruleStats {
		if st.BenignHits > 0 {
			st.FPRatePercent = sanitizeFloat((float64(st.FalsePositives+st.OverEscalations) / float64(st.BenignHits)) * 100.0)
		}
		ruleAccuracy = append(ruleAccuracy, *st)
	}
	sort.SliceStable(ruleAccuracy, func(i, j int) bool {
		fi := ruleAccuracy[i].FalsePositives + ruleAccuracy[i].OverEscalations
		fj := ruleAccuracy[j].FalsePositives + ruleAccuracy[j].OverEscalations
		if fi != fj {
			return fi > fj
		}
		if ruleAccuracy[i].BenignHits != ruleAccuracy[j].BenignHits {
			return ruleAccuracy[i].BenignHits > ruleAccuracy[j].BenignHits
		}
		return ruleAccuracy[i].RuleName < ruleAccuracy[j].RuleName
	})
	metrics.RuleAccuracy = ruleAccuracy

	// Ensure all floats are sanitized
	metrics.Precision = sanitizeFloat(metrics.Precision)
	metrics.Recall = sanitizeFloat(metrics.Recall)
	metrics.F1Score = sanitizeFloat(metrics.F1Score)
	metrics.FalsePositiveRate = sanitizeFloat(metrics.FalsePositiveRate)
	metrics.DetectionCoverageIndex = sanitizeFloat(metrics.DetectionCoverageIndex)
	metrics.SuspiciousTriageAccuracy = sanitizeFloat(metrics.SuspiciousTriageAccuracy)
	metrics.AbstentionAccuracy = sanitizeFloat(metrics.AbstentionAccuracy)

	return metrics
}

func sanitizeFloat(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0.0
	}
	return math.Round(v*10000) / 10000 // 4 decimal places
}
