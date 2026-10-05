package realworld

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCategorizeAnomaly(t *testing.T) {
	tests := []struct {
		name            string
		ruleName        string
		targetPath      string
		reason          string
		observedVerdict string
		expectedVerdict string
		expectedCat     AnomalyTaxonomyCategory
	}{
		{
			name:        "Permission Limitation",
			ruleName:    "Users_Shadow",
			targetPath:  "/etc/shadow",
			reason:      "EACCES: permission denied",
			expectedCat: TaxonomyPermissionBoundary,
		},
		{
			name:        "Runtime Race",
			ruleName:    "Process_Hidden",
			targetPath:  "/proc/9999",
			reason:      "Process vanished between opendir and stat",
			expectedCat: TaxonomyRuntimeRace,
		},
		{
			name:        "Dual Use Tool",
			ruleName:    "Tool_Detected",
			targetPath:  "/usr/bin/nmap",
			reason:      "Network scanner",
			expectedCat: TaxonomyDualUseTool,
		},
		{
			name:        "Namespace Isolation",
			ruleName:    "Container_Mount",
			targetPath:  "/var/lib/docker/overlay2",
			reason:      "container namespace discrepancy",
			expectedCat: TaxonomyNamespaceIsolation,
		},
		{
			name:        "Package Mismatch",
			ruleName:    "Binary_Replaced",
			targetPath:  "/usr/sbin/nginx",
			reason:      "package replaced on disk",
			expectedCat: TaxonomyPackageMismatch,
		},
		{
			name:        "Missing Context",
			ruleName:    "Build_Artifact",
			targetPath:  "/home/user/project/node_modules/lib.js",
			reason:      "untrusted script",
			expectedCat: TaxonomyMissingContext,
		},
		{
			name:            "Weak Heuristic",
			ruleName:        "Generic_Script_Exec",
			targetPath:      "/tmp/run.sh",
			reason:          "contains eval",
			observedVerdict: "MALICIOUS",
			expectedVerdict: "SAFE",
			expectedCat:     TaxonomyWeakHeuristic,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cat := CategorizeAnomaly(tt.ruleName, tt.targetPath, tt.reason, tt.observedVerdict, tt.expectedVerdict)
			if cat != tt.expectedCat {
				t.Errorf("expected category %s, got %s", tt.expectedCat, cat)
			}
		})
	}
}

func TestRegressionWriter_Roundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	writer := NewRegressionWriter(tmpDir)

	fixture := RegressionFixture{
		AnomalyID:        "REG-TEST-001",
		RuleName:         "Suspicious_Script",
		Category:         TaxonomyMissingContext,
		TargetPath:       "opt/app/start.sh",
		ExpectedVerdict:  "SAFE",
		ExpectedSeverity: "INFO",
		Description:      "App startup helper script",
		FileContents: map[string]string{
			"opt/app/start.sh": "#!/bin/bash\necho start\n",
		},
	}

	fixDir, err := writer.WriteFixture(fixture)
	if err != nil {
		t.Fatalf("WriteFixture failed: %v", err)
	}

	loaded, err := writer.LoadFixture(fixDir)
	if err != nil {
		t.Fatalf("LoadFixture failed: %v", err)
	}

	if loaded.AnomalyID != fixture.AnomalyID {
		t.Errorf("expected AnomalyID %s, got %s", fixture.AnomalyID, loaded.AnomalyID)
	}
	if loaded.Category != fixture.Category {
		t.Errorf("expected Category %s, got %s", fixture.Category, loaded.Category)
	}

	content, err := os.ReadFile(filepath.Join(fixDir, "rootfs", "opt/app/start.sh"))
	if err != nil {
		t.Fatalf("failed to read payload: %v", err)
	}
	if string(content) != fixture.FileContents["opt/app/start.sh"] {
		t.Errorf("content mismatch")
	}
}
