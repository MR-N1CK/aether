package ioc_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aether/internal/config"
	"aether/internal/ioc"
	"aether/internal/report"
)

func TestParseHashFile(t *testing.T) {
	data := `
# Comment line
  # Indented comment

5d41402abc4b2a76b9719d911017c592 # Test MD5 Hash
aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d # Test SHA1 Hash
b6d7732601e6575123995043f0f223b1855c42528f6652431fa6977483e65f42 # Test SHA256 Hash
invalid_length_hash # should be skipped
`
	rules, err := ioc.ParseHashFile(strings.NewReader(data), "test_hashes.txt")
	if err != nil {
		t.Fatalf("unexpected error parsing hashes: %v", err)
	}

	if len(rules) != 3 {
		t.Fatalf("expected 3 valid rules, got %d", len(rules))
	}

	if rules[0].Type != ioc.TypeMD5 || rules[0].Hash != "5d41402abc4b2a76b9719d911017c592" {
		t.Errorf("unexpected MD5 rule: %+v", rules[0])
	}
	if rules[1].Type != ioc.TypeSHA1 || rules[1].Hash != "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d" {
		t.Errorf("unexpected SHA1 rule: %+v", rules[1])
	}
	if rules[2].Type != ioc.TypeSHA256 || rules[2].Hash != "b6d7732601e6575123995043f0f223b1855c42528f6652431fa6977483e65f42" {
		t.Errorf("unexpected SHA256 rule: %+v", rules[2])
	}
}

func TestParsePatternFile(t *testing.T) {
	yamlData := `
- pattern: '.*\.suspect_payload$'
  score: 85
  reason: 'Suspect payload file extension'
  os_hint: 'linux'

- pattern: '[invalid(regex'
  score: 50
  reason: 'Should be safely skipped without crashing'
`
	rules, err := ioc.ParsePatternFile([]byte(yamlData), "patterns.yaml", nil)
	if err != nil {
		t.Fatalf("unexpected error parsing pattern yaml: %v", err)
	}

	// Only the valid regex should be loaded; invalid is safely skipped
	if len(rules) != 1 {
		t.Fatalf("expected 1 valid rule, got %d", len(rules))
	}

	if rules[0].Severity != report.SeverityAlert {
		t.Errorf("expected score 85 to produce SeverityAlert, got %s", rules[0].Severity)
	}
	if !rules[0].Regex.MatchString("/tmp/test.suspect_payload") {
		t.Errorf("expected pattern to match /tmp/test.suspect_payload")
	}
}

func TestAllowlist(t *testing.T) {
	al := ioc.NewAllowlist()
	content := `
# Trusted vendor hashes
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 # Empty file hash
`
	if err := al.LoadReader(strings.NewReader(content)); err != nil {
		t.Fatalf("failed to load allowlist: %v", err)
	}

	if al.Count() != 1 {
		t.Errorf("expected 1 allowlisted hash, got %d", al.Count())
	}

	ok, _ := al.Contains("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	if !ok {
		t.Errorf("expected empty file hash to be allowlisted")
	}

	ok, _ = al.Contains("0000000000000000000000000000000000000000000000000000000000000000")
	if ok {
		t.Errorf("unexpected allowlist match for dummy hash")
	}
}

func TestRealEngine_Integration(t *testing.T) {
	tmpDir := t.TempDir()
	iocDir := filepath.Join(tmpDir, "iocs")
	if err := os.MkdirAll(iocDir, 0700); err != nil {
		t.Fatal(err)
	}

	hashFile := filepath.Join(iocDir, "threats.txt")
	testHash := "b6d7732601e6575123995043f0f223b1855c42528f6652431fa6977483e65f42"
	if err := os.WriteFile(hashFile, []byte(testHash+" # TestThreat"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := config.NewDefaultConfig()
	cfg.Scan.IOCDir = iocDir

	eng, err := ioc.NewEngine(cfg, nil)
	if err != nil {
		t.Fatalf("failed to initialize IOC engine: %v", err)
	}

	// 1. Test hash check
	res := eng.CheckHash(testHash)
	if res == nil {
		t.Fatal("expected match for test hash, got nil")
	}
	if !res.IsHashMatch {
		t.Errorf("expected IsHashMatch to be true")
	}
	if res.Severity != report.SeverityAlert {
		t.Errorf("expected SeverityAlert, got %s", res.Severity)
	}

	// 2. Test built-in demo pattern match
	pathRes := eng.CheckPath("/var/tmp/sample.aether-test-malware")
	if pathRes == nil {
		t.Fatal("expected match for built-in test pattern, got nil")
	}
	if pathRes.Severity != report.SeverityAlert {
		t.Errorf("expected SeverityAlert, got %s", pathRes.Severity)
	}
}

func TestKnownBenignSuppression(t *testing.T) {
	yamlData := `
- path_regex: '^/tmp/\.bun-[0-9]+-.*'
  reason: 'Bun runtime cache'
- path_regex: '^/tmp/go-build.*'
  reason: 'Go build cache'
`
	rules, err := ioc.ParseBenignFile([]byte(yamlData), "known_benign.yaml", nil)
	if err != nil {
		t.Fatalf("unexpected error parsing benign yaml: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	eng, err := ioc.NewEngine(nil, nil)
	if err != nil {
		t.Fatalf("failed to initialize engine: %v", err)
	}

	// Test built-in benign match with matching UID (1000)
	ok, reason := eng.IsKnownBenign("/tmp/.bun-1000-abcdef/bun", 1000)
	if !ok {
		t.Errorf("expected /tmp/.bun-1000-abcdef/bun with uid 1000 to match known benign")
	}
	if reason == "" {
		t.Errorf("expected non-empty reason for benign match")
	}

	// Test mismatched UID: name has 1000, file owner is 1001 -> should NOT suppress!
	ok, _ = eng.IsKnownBenign("/tmp/.bun-1000-abcdef/bun", 1001)
	if ok {
		t.Errorf("expected /tmp/.bun-1000-abcdef/bun with mismatched uid 1001 NOT to match known benign")
	}

	ok, _ = eng.IsKnownBenign("/tmp/evil_miner", 1000)
	if ok {
		t.Errorf("expected /tmp/evil_miner NOT to match known benign")
	}
}

