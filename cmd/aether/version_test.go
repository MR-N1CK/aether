package main

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	appversion "aether/internal/version"
	"aether/internal/yara"
)

func TestVersionOutputContract(t *testing.T) {
	testVer := "1.0.0"
	testCommit := "abc1234"
	testDate := "2026-10-04T12:00:00Z"

	info := appversion.New(testVer, testCommit, testDate, yara.VersionInfo())
	output := info.String()

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 6 {
		t.Fatalf("expected 6 lines of version output, got %d:\n%s", len(lines), output)
	}

	// Line 1: Title & Version
	line1Regex := regexp.MustCompile(`^Aether Threat Hunter v[0-9]+\.[0-9]+\.[0-9]+.*$`)
	if !line1Regex.MatchString(lines[0]) {
		t.Errorf("line 1 failed regex match: %q", lines[0])
	}

	// Line 2: Commit
	line2Regex := regexp.MustCompile(`^\s*Commit:\s+[a-f0-9]+.*$`)
	if !line2Regex.MatchString(lines[1]) {
		t.Errorf("line 2 failed regex match: %q", lines[1])
	}

	// Line 3: Build Date
	line3Regex := regexp.MustCompile(`^\s*Build Date:\s+[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	if !line3Regex.MatchString(lines[2]) {
		t.Errorf("line 3 failed regex match: %q", lines[2])
	}

	// Line 4: Go Version
	line4Regex := regexp.MustCompile(`^\s*Go Version:\s+go[0-9.]+$`)
	if !line4Regex.MatchString(lines[3]) {
		t.Errorf("line 4 failed regex match: %q", lines[3])
	}

	// Line 5: OS/Arch
	line5Regex := regexp.MustCompile(`^\s*OS/Arch:\s+[a-z0-9]+/[a-z0-9]+$`)
	if !line5Regex.MatchString(lines[4]) {
		t.Errorf("line 5 failed regex match: %q", lines[4])
	}

	// Line 6: YARA status
	yaraStatus := lines[5]
	expectedPure := "  YARA:       disabled (native heuristics only)"
	expectedYara := "  YARA:       YARA-X v1.21.0 (static)"
	if yaraStatus != expectedPure && yaraStatus != expectedYara {
		t.Errorf("line 6 unexpected YARA status: %q (expected %q or %q)", yaraStatus, expectedPure, expectedYara)
	}
}

func TestVersionJSONOutputContract(t *testing.T) {
	testVer := "1.0.0"
	testCommit := "abc1234"
	testDate := "2026-10-04T12:00:00Z"

	info := appversion.New(testVer, testCommit, testDate, yara.VersionInfo())
	jsonStr, err := info.JSON()
	if err != nil {
		t.Fatalf("failed to format JSON version info: %v", err)
	}

	var parsed map[string]string
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	requiredKeys := []string{"version", "commit", "build_date", "go_version", "os", "arch", "yara"}
	for _, key := range requiredKeys {
		if val, ok := parsed[key]; !ok || val == "" {
			t.Errorf("missing or empty required key in version JSON: %s", key)
		}
	}
}
