//go:build yara

package yara

import (
	"sort"
	"testing"

	"aether/internal/config"
)

// TestFallback_ParityWithYaraX is the permanent drift guard between the two
// signature engines: both compile the identical EmbeddedCoreLinuxRules source
// and must produce the same matching rule-name set for every fixture. If this
// test fails after a rule edit, the rule has drifted outside the pure-Go
// subset semantics and must be rewritten (or the fallback engine extended).
func TestFallback_ParityWithYaraX(t *testing.T) {
	cfg := config.NewDefaultConfig()

	yx := NewYaraXEngine(cfg, nil, false)
	defer yx.Close()
	if err := yx.LoadRules(nil); err != nil {
		t.Fatalf("YARA-X LoadRules failed: %v", err)
	}
	yxScanner := yx.NewScanner()
	defer yxScanner.Destroy()

	fb := NewFallbackEngine(cfg, nil)
	if !fb.Enabled() {
		t.Fatalf("fallback engine failed to compile embedded rules: %v", fb.Coverage().FailedFiles)
	}
	fbScanner := fb.NewScanner()
	defer fbScanner.Destroy()

	corpus := append(append([]ruleFixture{}, embeddedRuleFixtures...), benignContentFixtures...)
	for _, fx := range corpus {
		t.Run(fx.ruleName, func(t *testing.T) {
			target := ScanTarget{Path: fx.path, Filename: fx.filename, Data: fx.payload}

			want, err := yxScanner.Scan(target)
			if err != nil {
				t.Fatalf("YARA-X scan error: %v", err)
			}
			got, err := fbScanner.Scan(target)
			if err != nil {
				t.Fatalf("fallback scan error: %v", err)
			}

			wantNames := sortedRuleNames(want)
			gotNames := sortedRuleNames(got)
			if !equalStrings(wantNames, gotNames) {
				t.Errorf("engine drift on %s:\n  yara-x:   %v\n  fallback: %v",
					fx.path, wantNames, gotNames)
			}

			// Scores and severities must also agree for shared matches.
			wantScores := scoreByRule(want)
			for _, m := range got {
				if w, ok := wantScores[m.RuleName]; ok {
					if w.Score != m.Score || w.Severity != m.Severity || w.IsStrong != m.IsStrong {
						t.Errorf("rule %s diverged: yara-x (score=%d sev=%v strong=%v) vs fallback (score=%d sev=%v strong=%v)",
							m.RuleName, w.Score, w.Severity, w.IsStrong, m.Score, m.Severity, m.IsStrong)
					}
				}
			}
		})
	}
}

func sortedRuleNames(matches []RuleMatch) []string {
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m.RuleName)
	}
	sort.Strings(out)
	return out
}

func scoreByRule(matches []RuleMatch) map[string]RuleMatch {
	out := make(map[string]RuleMatch, len(matches))
	for _, m := range matches {
		out[m.RuleName] = m
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
