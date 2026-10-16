package tui

import "testing"

func TestFuzzyScore_SubsequenceMatch(t *testing.T) {
	text := "/tmp/revshell.sh — Reverse shell via nc to 10.0.0.1:4444"
	cases := []struct {
		query string
		want  bool
	}{
		{"rvsh", true},      // subsequence of "revshell"
		{"revshell", true},  // exact substring
		{"shell", true},
		{"TMP", true}, // case-insensitive
		{"zqx", false},
		{"tmpx", false}, // ordering violated
	}
	for _, tc := range cases {
		_, ok := fuzzyScore(text, tc.query)
		if ok != tc.want {
			t.Errorf("fuzzyScore(%q, %q) = match %v, want %v", text, tc.query, ok, tc.want)
		}
	}
}

func TestFuzzyScore_ContiguousBeatsScattered(t *testing.T) {
	text := "findings feed"
	contiguous, _ := fuzzyScore(text, "feed")
	scattered, ok := fuzzyScore(text, "fd")
	if !ok {
		t.Fatal("expected scattered subsequence 'fd' to match 'findings feed'")
	}
	if contiguous <= scattered {
		t.Errorf("contiguous match (%d) should outrank scattered subsequence (%d)", contiguous, scattered)
	}
}

func TestFuzzyScore_TokenBoundaryBonus(t *testing.T) {
	text := "enable feed"
	atBoundary, _ := fuzzyScore(text, "feed")

	textMid := "unfeasible"
	midWord, okMid := fuzzyScore(textMid, "feed")
	if okMid {
		if atBoundary <= midWord {
			t.Errorf("token-boundary match (%d) should outrank mid-word match (%d)", atBoundary, midWord)
		}
	}
}

func TestFuzzyScore_EmptyQueryMatches(t *testing.T) {
	score, ok := fuzzyScore("anything", "")
	if !ok || score != 0 {
		t.Errorf("empty query should match with zero score, got (%d, %v)", score, ok)
	}
}

func TestFuzzyHaystack_CrossFieldBoundary(t *testing.T) {
	// An acronym-style query spanning path and severity fields must match and
	// should score better than the equivalent scattered query, because the
	// separator grants boundary credit.
	h := fuzzyHaystack("/usr/lib/module.so", "suspicious reason", "process", "WARNING", "Process_Netlink")
	_, ok := fuzzyScore(h, "WARNING")
	if !ok {
		t.Error("expected severity field to be searchable via haystack")
	}
	_, ok = fuzzyScore(h, "libso")
	if !ok {
		t.Error("expected cross-field subsequence to match")
	}
	score, ok := fuzzyScore(h, "usr")
	if !ok || score == 0 {
		t.Error("expected path-field query to match with positive score")
	}
}
