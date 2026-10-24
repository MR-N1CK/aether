package scanner

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"aether/internal/report"
)

func baselineTestFinding(path, rule, sha string, sev report.Severity) report.Finding {
	f := report.NewFinding("filesystem", sev, path, "test", rule)
	if sha != "" {
		f.Hashes["SHA256"] = sha
	}
	return f
}

func TestBaselineSaveLoadRoundtrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "baseline.json")
	findings := []report.Finding{
		baselineTestFinding("/tmp/a", "Rule_A", "aa11", report.SeverityWarning),
		baselineTestFinding("/tmp/b", "Rule_B", "", report.SeverityNotice),
	}
	if err := SaveBaseline(p, findings, "host-a", "quick", []string{"/tmp"}); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	bf, err := LoadBaseline(p)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if bf.Hostname != "host-a" || bf.Mode != "quick" || len(bf.Entries) != 2 {
		t.Fatalf("roundtrip mismatch: %+v", bf)
	}
	if bf.Entries[0].SHA256 != "aa11" {
		t.Errorf("hash not persisted: %+v", bf.Entries[0])
	}
	// 0600 permissions: baselines list host state.
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("baseline must be 0600, got %v", fi.Mode().Perm())
	}
}

func TestBaselineClassifyStates(t *testing.T) {
	bf := &BaselineFile{Version: 1}
	bf.Entries = []BaselineEntry{
		{Path: "/tmp/a", Rule: "Rule_A", SHA256: "aa11"},
		{Path: "/tmp/b", Rule: "Rule_B"}, // no hash pinned
	}
	bf.index = map[baselineKey]int{
		{"/tmp/a", "Rule_A"}: 0,
		{"/tmp/b", "Rule_B"}: 1,
	}

	cases := []struct {
		name     string
		finding  report.Finding
		expected string
	}{
		{"same rule same hash", baselineTestFinding("/tmp/a", "Rule_A", "aa11", report.SeverityWarning), BaselineStateUnchanged},
		{"same rule changed hash", baselineTestFinding("/tmp/a", "Rule_A", "ff99", report.SeverityWarning), BaselineStateNew},
		{"same rule missing current hash", baselineTestFinding("/tmp/a", "Rule_A", "", report.SeverityWarning), BaselineStateUnchanged},
		{"unpinned entry always unchanged", baselineTestFinding("/tmp/b", "Rule_B", "anything", report.SeverityNotice), BaselineStateUnchanged},
		{"unknown path", baselineTestFinding("/tmp/c", "Rule_A", "aa11", report.SeverityWarning), BaselineStateNew},
		{"same path different rule", baselineTestFinding("/tmp/a", "Rule_Z", "aa11", report.SeverityWarning), BaselineStateNew},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bf.Classify(&tc.finding); got != tc.expected {
				t.Errorf("Classify = %q, want %q", got, tc.expected)
			}
		})
	}

	// Nil baseline always reports NEW (delta mode off behaves like no baseline).
	var nilBf *BaselineFile
	if got := nilBf.Classify(&cases[0].finding); got != BaselineStateNew {
		t.Errorf("nil baseline must classify NEW, got %q", got)
	}
}

func TestBaselineResolvedDiff(t *testing.T) {
	bf := &BaselineFile{
		Version: 1,
		Entries: []BaselineEntry{
			{Path: "/tmp/a", Rule: "Rule_A"},
			{Path: "/tmp/b", Rule: "Rule_B"},
			{Path: "/tmp/c", Rule: "Rule_C"},
		},
	}
	current := []report.Finding{
		baselineTestFinding("/tmp/a", "Rule_A", "", report.SeverityWarning),
		baselineTestFinding("/tmp/c", "Rule_Other", "", report.SeverityNotice), // different rule: /tmp/c Rule_C resolved
	}
	resolved := bf.ResolvedDiff(current)
	if len(resolved) != 2 {
		t.Fatalf("expected 2 resolved entries, got %d: %+v", len(resolved), resolved)
	}
	seen := map[string]bool{}
	for _, r := range resolved {
		seen[r.Path+"/"+r.Rule] = true
	}
	if !seen["/tmp/b/Rule_B"] || !seen["/tmp/c/Rule_C"] {
		t.Errorf("resolved set mismatch: %+v", resolved)
	}
}

func TestBaselineRejectsEmptyAndBroken(t *testing.T) {
	dir := t.TempDir()

	empty := filepath.Join(dir, "empty.json")
	_ = os.WriteFile(empty, []byte(`{"version":1,"entries":[]}`), 0o600)
	if _, err := LoadBaseline(empty); err == nil {
		t.Error("empty baseline must be rejected")
	}

	broken := filepath.Join(dir, "broken.json")
	_ = os.WriteFile(broken, []byte(`{"version":`), 0o600)
	if _, err := LoadBaseline(broken); err == nil {
		t.Error("malformed baseline must be rejected")
	}

	future := filepath.Join(dir, "future.json")
	_ = os.WriteFile(future, []byte(`{"version":99,"entries":[{"path":"/x","rule":"R"}]}`), 0o600)
	if _, err := LoadBaseline(future); err == nil {
		t.Error("unsupported baseline version must be rejected")
	}

	// Symlink refusal: baseline files carry host state.
	link := filepath.Join(dir, "link.json")
	real := filepath.Join(dir, "real.json")
	_ = os.WriteFile(real, []byte("{}"), 0o600)
	_ = os.Symlink(real, link)
	if err := SaveBaseline(link, nil, "h", "quick", nil); err == nil {
		t.Error("SaveBaseline must refuse symlinks")
	}
}

// Guard against timestamp zero-values poisoning FirstSeen in snapshots.
func TestBaselineFirstSeenRecording(t *testing.T) {
	p := filepath.Join(t.TempDir(), "b.json")
	f := baselineTestFinding("/tmp/x", "R", "", report.SeverityNotice)
	f.Timestamp = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	if err := SaveBaseline(p, []report.Finding{f}, "h", "full", nil); err != nil {
		t.Fatalf("save: %v", err)
	}
	bf, err := LoadBaseline(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if bf.Entries[0].FirstSeen != "2026-10-24T12:00:00Z" {
		t.Errorf("FirstSeen not recorded verbatim: %q", bf.Entries[0].FirstSeen)
	}
}
