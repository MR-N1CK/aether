package yara

import (
	"os"
	"path/filepath"
	"testing"

	"aether/internal/report"
)

func TestScoreFromMeta(t *testing.T) {
	tests := []struct {
		name             string
		meta             map[string]interface{}
		defScore         int
		warningThreshold int
		strongThreshold  int
		alertThreshold   int
		wantScore        int
		wantSev          report.Severity
		wantStrong       bool
		wantConf         string
	}{
		{
			name:             "boundary score 39 (NOTICE)",
			meta:             map[string]interface{}{"score": 39},
			defScore:         50,
			warningThreshold: 40,
			strongThreshold:  75,
			alertThreshold:   90,
			wantScore:        39,
			wantSev:          report.SeverityNotice,
			wantStrong:       false,
			wantConf:         "",
		},
		{
			name:             "boundary score 40 (WARNING weak)",
			meta:             map[string]interface{}{"score": 40},
			defScore:         50,
			warningThreshold: 40,
			strongThreshold:  75,
			alertThreshold:   90,
			wantScore:        40,
			wantSev:          report.SeverityWarning,
			wantStrong:       false,
			wantConf:         "",
		},
		{
			name:             "boundary score 74 (WARNING weak)",
			meta:             map[string]interface{}{"score": 74},
			defScore:         50,
			warningThreshold: 40,
			strongThreshold:  75,
			alertThreshold:   90,
			wantScore:        74,
			wantSev:          report.SeverityWarning,
			wantStrong:       false,
			wantConf:         "",
		},
		{
			name:             "boundary score 75 (WARNING strong)",
			meta:             map[string]interface{}{"score": 75},
			defScore:         50,
			warningThreshold: 40,
			strongThreshold:  75,
			alertThreshold:   90,
			wantScore:        75,
			wantSev:          report.SeverityWarning,
			wantStrong:       true,
			wantConf:         "",
		},
		{
			name:             "boundary score 89 (WARNING strong)",
			meta:             map[string]interface{}{"score": 89},
			defScore:         50,
			warningThreshold: 40,
			strongThreshold:  75,
			alertThreshold:   90,
			wantScore:        89,
			wantSev:          report.SeverityWarning,
			wantStrong:       true,
			wantConf:         "",
		},
		{
			name:             "boundary score 90 (ALERT)",
			meta:             map[string]interface{}{"score": 90, "confidence": "high"},
			defScore:         50,
			warningThreshold: 40,
			strongThreshold:  75,
			alertThreshold:   90,
			wantScore:        90,
			wantSev:          report.SeverityAlert,
			wantStrong:       true,
			wantConf:         "high",
		},
		{
			name:             "score 500 clamped to 100 (ALERT)",
			meta:             map[string]interface{}{"score": 500},
			defScore:         50,
			warningThreshold: 40,
			strongThreshold:  75,
			alertThreshold:   90,
			wantScore:        100,
			wantSev:          report.SeverityAlert,
			wantStrong:       true,
			wantConf:         "",
		},
		{
			name:             "negative score clamped to 0 (NOTICE)",
			meta:             map[string]interface{}{"score": -15},
			defScore:         50,
			warningThreshold: 40,
			strongThreshold:  75,
			alertThreshold:   90,
			wantScore:        0,
			wantSev:          report.SeverityNotice,
			wantStrong:       false,
			wantConf:         "",
		},
		{
			name:             "non-numeric string score falls back to defaultScore",
			meta:             map[string]interface{}{"score": "invalid_number"},
			defScore:         50,
			warningThreshold: 40,
			strongThreshold:  75,
			alertThreshold:   90,
			wantScore:        50,
			wantSev:          report.SeverityWarning,
			wantStrong:       false,
			wantConf:         "",
		},
		{
			name:             "severity LOW mapped to 25 (NOTICE)",
			meta:             map[string]interface{}{"severity": "LOW"},
			defScore:         50,
			warningThreshold: 40,
			strongThreshold:  75,
			alertThreshold:   90,
			wantScore:        25,
			wantSev:          report.SeverityNotice,
			wantStrong:       false,
			wantConf:         "",
		},
		{
			name:             "severity CRITICAL mapped to 90 (ALERT)",
			meta:             map[string]interface{}{"severity": "CRITICAL"},
			defScore:         50,
			warningThreshold: 40,
			strongThreshold:  75,
			alertThreshold:   90,
			wantScore:        90,
			wantSev:          report.SeverityAlert,
			wantStrong:       true,
			wantConf:         "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, sev, strong, conf := ScoreFromMeta(tt.meta, tt.defScore, tt.warningThreshold, tt.strongThreshold, tt.alertThreshold)
			if score != tt.wantScore {
				t.Errorf("Score: got %d, want %d", score, tt.wantScore)
			}
			if sev != tt.wantSev {
				t.Errorf("Severity: got %s, want %s", sev, tt.wantSev)
			}
			if strong != tt.wantStrong {
				t.Errorf("IsStrong: got %v, want %v", strong, tt.wantStrong)
			}
			if conf != tt.wantConf {
				t.Errorf("Confidence: got %q, want %q", conf, tt.wantConf)
			}
		})
	}
}

func TestValidateRulesDirTrust(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Root user check: /home/ user dir rejected
	homeUserDir := "/home/testuser/.config/aether/rules"
	trusted, reason := ValidateRulesDirTrust(homeUserDir, true, 0, false)
	if trusted {
		t.Errorf("expected root to reject /home directory, but got trusted=true")
	}
	if reason == "" {
		t.Errorf("expected rejection reason, got empty")
	}

	// 2. Normal directory owned by current user
	_ = os.Chmod(tempDir, 0755)
	uid := uint32(os.Getuid())
	trusted, reason = ValidateRulesDirTrust(tempDir, false, uid, false)
	if !trusted {
		t.Errorf("expected tempDir to be trusted for current UID, got false: %s", reason)
	}

	// 3. Writable permissions check (group or world writable)
	insecureDir := filepath.Join(tempDir, "insecure")
	if err := os.Mkdir(insecureDir, 0777); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}
	_ = os.Chmod(insecureDir, 0777)
	trusted, reason = ValidateRulesDirTrust(insecureDir, false, uid, false)
	if trusted {
		t.Errorf("expected 0777 directory to be rejected as insecure, got true")
	}

	// 4. trustRulesDir bypass check
	trustedBypass, _ := ValidateRulesDirTrust(insecureDir, false, uid, true)
	if !trustedBypass {
		t.Errorf("expected trustRulesDir=true to bypass validation, got false")
	}
}

func TestDiscoverRuleFiles(t *testing.T) {
	tempDir := t.TempDir()
	_ = os.Chmod(tempDir, 0755)

	rule1 := filepath.Join(tempDir, "rule1.yar")
	rule2 := filepath.Join(tempDir, "rule2.yara")
	txtFile := filepath.Join(tempDir, "ignored.txt")

	if err := os.WriteFile(rule1, []byte(DemoRuleEICAR), 0644); err != nil {
		t.Fatalf("failed to write rule1: %v", err)
	}
	if err := os.WriteFile(rule2, []byte(DemoRuleMarker), 0644); err != nil {
		t.Fatalf("failed to write rule2: %v", err)
	}
	if err := os.WriteFile(txtFile, []byte("ignored"), 0644); err != nil {
		t.Fatalf("failed to write txtFile: %v", err)
	}

	// Nested subdirectory with rule
	subDir := filepath.Join(tempDir, "subdir")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}
	rule3 := filepath.Join(subDir, "rule3.yar")
	if err := os.WriteFile(rule3, []byte("rule Sub_Rule { condition: true }"), 0644); err != nil {
		t.Fatalf("failed to write rule3: %v", err)
	}

	uid := uint32(os.Getuid())
	files, warnings := DiscoverRuleFiles([]string{tempDir}, false, uid, false, nil)
	if len(warnings) > 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if len(files) != 3 {
		t.Fatalf("expected 3 rule files, got %d: %v", len(files), files)
	}
	if files[0] != rule1 || files[1] != rule2 || files[2] != rule3 {
		t.Errorf("unexpected discovered files: %v", files)
	}

	// Test 1: Empty directory
	emptyDir := filepath.Join(tempDir, "empty_rules")
	_ = os.Mkdir(emptyDir, 0755)
	emptyFiles, emptyWarnings := DiscoverRuleFiles([]string{emptyDir}, false, uid, false, nil)
	if len(emptyWarnings) > 0 {
		t.Errorf("unexpected warnings for empty dir: %v", emptyWarnings)
	}
	if len(emptyFiles) != 0 {
		t.Errorf("expected 0 files from empty dir, got %d", len(emptyFiles))
	}

	// Test 2: Non-existent directory
	nonExistentDir := filepath.Join(tempDir, "does_not_exist")
	nonExistentFiles, nonExistentWarnings := DiscoverRuleFiles([]string{nonExistentDir}, false, uid, false, nil)
	if len(nonExistentWarnings) > 0 {
		t.Errorf("unexpected warnings for non-existent dir: %v", nonExistentWarnings)
	}
	if len(nonExistentFiles) != 0 {
		t.Errorf("expected 0 files from non-existent dir, got %d", len(nonExistentFiles))
	}

	// Test 3: File passed instead of directory
	fileAsDirFiles, fileAsDirWarnings := DiscoverRuleFiles([]string{rule1}, false, uid, false, nil)
	if len(fileAsDirWarnings) == 0 {
		t.Errorf("expected warning when file is passed as directory")
	}
	if len(fileAsDirFiles) != 0 {
		t.Errorf("expected 0 files when passing file path as rules dir, got %d", len(fileAsDirFiles))
	}
}

func TestGetRuleNamespace(t *testing.T) {
	cases := map[string]string{
		"/path/to/my_rule.yar":       "my_rule",
		"/etc/rules/123_custom.yara": "ns_123_custom",
		"special-chars.name.yar":     "special_chars_name",
	}

	for input, want := range cases {
		got := GetRuleNamespace(input)
		if got != want {
			t.Errorf("GetRuleNamespace(%q) = %q, want %q", input, got, want)
		}
	}
}
