package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFPFilterFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fp-filters.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write filter file: %v", err)
	}
	return p
}

func TestFPFilterLoadAndMatch(t *testing.T) {
	p := writeFPFilterFile(t, `
version: 1
filters:
  - rule: "Linux_Backdoor_Reverse_Shell_OneLiner"
    path: "/usr/lib/python3/dist-packages/netexec"
    note: "NetExec ships reverse shell one-liners as attack modules"
  - rule: "ELF_Behavioral_ReverseShell_Combo"
    path: "/home/dev/tools/**"
    note: "Self-built network testing tools"
  - rule: "Linux_Webshell_PHP_Generic_Backdoor"
    path: "/var/www/**"
    description_contains: "router"
    note: "Framework router false positive"
`)

	set, err := LoadFPFilters([]string{p})
	if err != nil {
		t.Fatalf("LoadFPFilters: %v", err)
	}
	if set.Count() != 3 {
		t.Fatalf("expected 3 filters, got %d", set.Count())
	}

	cases := []struct {
		name  string
		rule  string
		path  string
		desc  string
		match bool
	}{
		{"exact dir prefix", "Linux_Backdoor_Reverse_Shell_OneLiner", "/usr/lib/python3/dist-packages/netexec/protocols/ssh.py", "", true},
		{"rule mismatch", "Some_Other_Rule", "/usr/lib/python3/dist-packages/netexec/x.py", "", false},
		{"path mismatch", "Linux_Backdoor_Reverse_Shell_OneLiner", "/tmp/evil.py", "", false},
		{"subtree glob", "ELF_Behavioral_ReverseShell_Combo", "/home/dev/tools/bin/nc-clone", "", true},
		{"subtree glob excludes root file", "ELF_Behavioral_ReverseShell_Combo", "/home/dev/tools", "", false},
		{"desc substring required", "Linux_Webshell_PHP_Generic_Backdoor", "/var/www/html/index.php", "custom router dispatch", true},
		{"desc substring absent", "Linux_Webshell_PHP_Generic_Backdoor", "/var/www/html/index.php", "eval base64", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := set.Match(tc.rule, tc.path, tc.desc)
			if tc.match && got == nil {
				t.Errorf("expected suppression for %s %s", tc.rule, tc.path)
			}
			if !tc.match && got != nil {
				t.Errorf("unexpected suppression via %v", got)
			}
		})
	}
}

func TestFPFilterMalformedFileFailsClosed(t *testing.T) {
	// Filters without notes are rejected: every suppression must be auditable.
	p := writeFPFilterFile(t, `
version: 1
filters:
  - rule: "Some_Rule"
    path: "/opt"
`)
	if _, err := LoadFPFilters([]string{p}); err == nil {
		t.Fatal("expected error for filter missing note")
	}

	// Malformed YAML is a hard error.
	p2 := writeFPFilterFile(t, "\tversion: [broken\n  - {")
	if _, err := LoadFPFilters([]string{p2}); err == nil {
		t.Fatal("expected error for malformed YAML")
	}

	// Missing files are silently skipped (filters are optional).
	set, err := LoadFPFilters([]string{filepath.Join(t.TempDir(), "absent.yaml")})
	if err != nil || set.Count() != 0 {
		t.Fatalf("missing file must be skipped silently, got err=%v count=%d", err, set.Count())
	}
}

func TestFPFilterSetNilSafe(t *testing.T) {
	var set *FPFilterSet
	if set.Match("Any_Rule", "/any/path", "") != nil {
		t.Error("nil filter set must never suppress")
	}
	if set.Count() != 0 {
		t.Error("nil filter set count must be 0")
	}
}
