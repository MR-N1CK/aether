package realworld_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aether/internal/realworld"
	"aether/internal/report"
)

func findSpecsContractsDir(t *testing.T) string {
	t.Helper()
	// Navigate up to find specs/004-real-world-validation/contracts
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd failed: %v", err)
	}

	for i := 0; i < 5; i++ {
		candidate := filepath.Join(dir, "specs", "004-real-world-validation", "contracts")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("Could not locate specs/004-real-world-validation/contracts from working dir")
	return ""
}

func TestProfileManifestSchemaCompliance(t *testing.T) {
	contractsDir := findSpecsContractsDir(t)
	schemaPath := filepath.Join(contractsDir, "profile-manifest-schema.json")
	schemaBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("Failed to read profile-manifest-schema.json: %v", err)
	}

	var schema map[string]interface{}
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		t.Fatalf("Schema JSON is invalid: %v", err)
	}

	// Verify required fields in schema
	requiredList, ok := schema["required"].([]interface{})
	if !ok {
		t.Fatalf("schema.required is not a list")
	}
	expectedRequired := map[string]bool{
		"profile_id":              false,
		"version":                 false,
		"expected_status":         false,
		"max_acceptable_alerts":   false,
		"max_acceptable_warnings": false,
	}
	for _, req := range requiredList {
		if reqStr, ok := req.(string); ok {
			expectedRequired[reqStr] = true
		}
	}
	for k, found := range expectedRequired {
		if !found {
			t.Errorf("profile-manifest-schema.json missing required property %q", k)
		}
	}

	// Create and marshal a valid ProfileManifest Go struct
	manifest := realworld.ProfileManifest{
		ProfileID:             realworld.ProfileDesktopStandard,
		Version:               "1.0.0",
		ExpectedStatus:        realworld.PostureSafe,
		MaxAcceptableAlerts:   0,
		MaxAcceptableWarnings: 2,
		AcceptableFindings: []realworld.AcceptableFindingRule{
			{
				RuleName:         "Network_Loopback_Listener",
				PathPattern:      "/proc/*/fd/*",
				ExpectedSeverity: "INFO",
				ExpectedVerdict:  "SAFE",
				Reason:           "Standard desktop pipewire/pulseaudio loopback socket",
			},
		},
		ForbiddenFindings: []realworld.ForbiddenFindingRule{
			{
				RulePattern: "Ransomware_*",
				Severity:    "ALERT",
				Reason:      "Benign desktop must never contain ransomware signatures",
			},
		},
		ExpectedCoverageLimits: []string{"/proc/1/exe", "/etc/shadow"},
		DualUseSoftware: []realworld.DualUseSoftwareCatalogEntry{
			{
				ToolName:                "wireshark",
				PrimaryBinary:           "wireshark",
				StandardPaths:           []string{"/usr/bin/wireshark"},
				ExpectedPassiveSeverity: "INFO",
				ExpectedPassiveVerdict:  "SAFE",
			},
		},
	}

	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Failed to marshal ProfileManifest: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(manifestBytes, &raw); err != nil {
		t.Fatalf("Failed to unmarshal manifest JSON: %v", err)
	}

	// Verify all schema required fields exist in marshaled JSON
	for k := range expectedRequired {
		if _, exists := raw[k]; !exists {
			t.Errorf("Marshaled manifest missing required property %q", k)
		}
	}

	// Verify enum value matches schema
	if raw["profile_id"] != realworld.ProfileDesktopStandard {
		t.Errorf("Expected profile_id %s, got %v", realworld.ProfileDesktopStandard, raw["profile_id"])
	}
	if raw["expected_status"] != "SAFE" {
		t.Errorf("Expected expected_status SAFE, got %v", raw["expected_status"])
	}
}

func TestSystemAssessmentSchemaCompliance(t *testing.T) {
	contractsDir := findSpecsContractsDir(t)
	schemaPath := filepath.Join(contractsDir, "system-assessment-schema.json")
	schemaBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("Failed to read system-assessment-schema.json: %v", err)
	}

	var schema map[string]interface{}
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		t.Fatalf("Schema JSON is invalid: %v", err)
	}

	requiredList, ok := schema["required"].([]interface{})
	if !ok {
		t.Fatalf("schema.required is not a list")
	}
	expectedRequired := map[string]bool{
		"posture":           false,
		"summary_rationale": false,
		"total_findings":    false,
		"alerts_count":      false,
		"warnings_count":    false,
		"notices_count":     false,
		"infos_count":       false,
		"unknowns_count":    false,
		"next_actions":      false,
	}
	for _, req := range requiredList {
		if reqStr, ok := req.(string); ok {
			expectedRequired[reqStr] = true
		}
	}
	for k, found := range expectedRequired {
		if !found {
			t.Errorf("system-assessment-schema.json missing required property %q", k)
		}
	}

	// Create and marshal ComprehensiveSystemAssessment
	assessment := realworld.ComprehensiveSystemAssessment{
		Posture:          realworld.PostureSafe,
		SummaryRationale: "All 15 inspected subsystems verified benign. Zero malware or unauthorized listeners.",
		TotalFindings:    1,
		AlertsCount:      0,
		WarningsCount:    0,
		NoticesCount:     0,
		InfosCount:       1,
		UnknownsCount:    0,
		CriticalFindings: []report.Finding{},
		VisibilityGaps: []realworld.CoverageGap{
			{
				Subsystem:   "process",
				TargetPath:  "/proc/1/exe",
				Reason:      "EACCES: permission denied",
				Remediation: "Re-run with sudo or grant CAP_DAC_OVERRIDE",
			},
		},
		NextActions: []realworld.PrioritizedAction{
			{
				Priority:    1,
				Title:       "Elevate Privileges for Full Audit",
				Description: "Run Aether with root privileges to audit root-owned processes in /proc",
				Command:     "sudo aether scan --full",
			},
		},
	}

	assessmentBytes, err := json.Marshal(assessment)
	if err != nil {
		t.Fatalf("Failed to marshal ComprehensiveSystemAssessment: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(assessmentBytes, &raw); err != nil {
		t.Fatalf("Failed to unmarshal assessment JSON: %v", err)
	}

	for k := range expectedRequired {
		if _, exists := raw[k]; !exists {
			t.Errorf("Marshaled assessment missing required property %q", k)
		}
	}

	if raw["posture"] != "SAFE" {
		t.Errorf("Expected posture SAFE, got %v", raw["posture"])
	}
}

func TestValidationRunSchemaCompliance(t *testing.T) {
	contractsDir := findSpecsContractsDir(t)
	schemaPath := filepath.Join(contractsDir, "validation-run-schema.json")
	schemaBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("Failed to read validation-run-schema.json: %v", err)
	}

	var schema map[string]interface{}
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		t.Fatalf("Schema JSON is invalid: %v", err)
	}

	requiredList, ok := schema["required"].([]interface{})
	if !ok {
		t.Fatalf("schema.required is not a list")
	}
	expectedRequired := map[string]bool{
		"run_id":                   false,
		"timestamp":                false,
		"profile_id":               false,
		"is_elevated":              false,
		"files_inspected":          false,
		"processes_inspected":      false,
		"sockets_inspected":        false,
		"peak_memory_mb":           false,
		"throughput_files_per_sec": false,
		"duration":                 false,
		"assessment":               false,
		"manifest_compliance":      false,
	}
	for _, req := range requiredList {
		if reqStr, ok := req.(string); ok {
			expectedRequired[reqStr] = true
		}
	}
	for k, found := range expectedRequired {
		if !found {
			t.Errorf("validation-run-schema.json missing required property %q", k)
		}
	}

	// Create and marshal RealWorldValidationRun
	run := realworld.RealWorldValidationRun{
		RunID:                 "run-validation-001",
		Timestamp:             time.Now().UTC(),
		ProfileID:             realworld.ProfileServerWeb,
		IsElevated:            true,
		FilesInspected:        15420,
		ProcessesInspected:    184,
		SocketsInspected:      42,
		PeakMemoryMB:          64.5,
		ThroughputFilesPerSec: 3200.0,
		Duration: realworld.DurationBreakdown{
			FilesystemWalk: 1200 * time.Millisecond,
			Hashing:        800 * time.Millisecond,
			Heuristics:     400 * time.Millisecond,
			YARA:           500 * time.Millisecond,
			Process:        150 * time.Millisecond,
			Network:        50 * time.Millisecond,
			Persistence:    30 * time.Millisecond,
			Users:          20 * time.Millisecond,
			Kernel:         10 * time.Millisecond,
			Correlation:    40 * time.Millisecond,
			Reporting:      15 * time.Millisecond,
			Total:          3215 * time.Millisecond,
		},
		Assessment: realworld.ComprehensiveSystemAssessment{
			Posture:          realworld.PostureSafe,
			SummaryRationale: "Clean web server profile.",
			TotalFindings:    0,
			NextActions:      []realworld.PrioritizedAction{},
		},
		ManifestCompliance:   true,
		ComplianceViolations: []string{},
	}

	runBytes, err := json.Marshal(run)
	if err != nil {
		t.Fatalf("Failed to marshal RealWorldValidationRun: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(runBytes, &raw); err != nil {
		t.Fatalf("Failed to unmarshal run JSON: %v", err)
	}

	for k := range expectedRequired {
		if _, exists := raw[k]; !exists {
			t.Errorf("Marshaled run missing required property %q", k)
		}
	}

	durMap, ok := raw["duration"].(map[string]interface{})
	if !ok {
		t.Fatalf("duration field in run JSON is not an object")
	}
	if _, ok := durMap["total"].(string); !ok {
		t.Errorf("duration.total must serialize as string, got %T", durMap["total"])
	}
}
