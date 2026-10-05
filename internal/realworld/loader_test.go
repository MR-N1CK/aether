package realworld_test

import (
	"os"
	"path/filepath"
	"testing"

	"aether/internal/realworld"
)

func TestProfileLoader_ValidManifest(t *testing.T) {
	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "profile_manifest.json")

	validJSON := `{
		"profile_id": "desktop-standard",
		"version": "1.0.0",
		"expected_status": "SAFE",
		"max_acceptable_alerts": 0,
		"max_acceptable_warnings": 1,
		"acceptable_findings": [
			{
				"rule_name": "Network_Loopback_Listener",
				"path_pattern": "/proc/*/fd/*",
				"expected_severity": "INFO",
				"expected_verdict": "SAFE",
				"reason": "Desktop loopback listener"
			}
		],
		"forbidden_findings": [
			{
				"rule_pattern": "Ransomware_*",
				"reason": "No ransomware on clean desktop"
			}
		],
		"dual_use_software": [
			{
				"tool_name": "wireshark",
				"primary_binary": "wireshark",
				"expected_passive_verdict": "SAFE"
			}
		]
	}`

	if err := os.WriteFile(manifestPath, []byte(validJSON), 0644); err != nil {
		t.Fatalf("Failed to write manifest: %v", err)
	}

	loader := realworld.NewProfileLoader()
	manifest, err := loader.LoadManifest(manifestPath)
	if err != nil {
		t.Fatalf("LoadManifest failed: %v", err)
	}

	if manifest.ProfileID != realworld.ProfileDesktopStandard {
		t.Errorf("Expected profile_id %s, got %s", realworld.ProfileDesktopStandard, manifest.ProfileID)
	}
	if manifest.ExpectedStatus != realworld.PostureSafe {
		t.Errorf("Expected status SAFE, got %s", manifest.ExpectedStatus)
	}
	if len(manifest.AcceptableFindings) != 1 {
		t.Errorf("Expected 1 acceptable finding, got %d", len(manifest.AcceptableFindings))
	}
}

func TestProfileLoader_InvalidManifests(t *testing.T) {
	loader := realworld.NewProfileLoader()

	cases := []struct {
		name     string
		manifest realworld.ProfileManifest
		wantErr  string
	}{
		{
			name: "missing profile_id",
			manifest: realworld.ProfileManifest{
				ProfileID:      "",
				Version:        "1.0.0",
				ExpectedStatus: realworld.PostureSafe,
			},
			wantErr: "missing profile_id",
		},
		{
			name: "unknown profile_id",
			manifest: realworld.ProfileManifest{
				ProfileID:      "quantum-mainframe",
				Version:        "1.0.0",
				ExpectedStatus: realworld.PostureSafe,
			},
			wantErr: "unknown profile_id",
		},
		{
			name: "invalid expected_status",
			manifest: realworld.ProfileManifest{
				ProfileID:      realworld.ProfileServerWeb,
				Version:        "1.0.0",
				ExpectedStatus: "TOTALLY_FINE",
			},
			wantErr: "invalid expected_status",
		},
		{
			name: "negative max alerts",
			manifest: realworld.ProfileManifest{
				ProfileID:           realworld.ProfileServerWeb,
				Version:             "1.0.0",
				ExpectedStatus:      realworld.PostureSafe,
				MaxAcceptableAlerts: -1,
			},
			wantErr: "max_acceptable_alerts cannot be negative",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := loader.ValidateManifest(&tc.manifest)
			if err == nil {
				t.Fatalf("Expected validation error containing %q, got nil", tc.wantErr)
			}
		})
	}
}

func TestProfileLoader_SnapshotPathNormalization(t *testing.T) {
	tempDir := t.TempDir()
	rootFS := filepath.Join(tempDir, "rootfs")
	procDir := filepath.Join(tempDir, "proc")
	if err := os.MkdirAll(rootFS, 0755); err != nil {
		t.Fatalf("MkdirAll rootfs failed: %v", err)
	}
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("MkdirAll proc failed: %v", err)
	}

	manifestPath := filepath.Join(tempDir, "profile_manifest.json")
	validJSON := `{
		"profile_id": "server-minimal",
		"version": "1.0.0",
		"expected_status": "SAFE",
		"max_acceptable_alerts": 0,
		"max_acceptable_warnings": 0
	}`
	if err := os.WriteFile(manifestPath, []byte(validJSON), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	loader := realworld.NewProfileLoader()
	snapshot, err := loader.LoadSnapshot(tempDir)
	if err != nil {
		t.Fatalf("LoadSnapshot failed: %v", err)
	}

	if snapshot.RootFS != rootFS {
		t.Errorf("Expected RootFS %s, got %s", rootFS, snapshot.RootFS)
	}
	if snapshot.ProcRoot != procDir {
		t.Errorf("Expected ProcRoot %s, got %s", procDir, snapshot.ProcRoot)
	}

	// Test path normalization
	physPath := filepath.Join(rootFS, "etc", "passwd")
	norm := snapshot.NormalizeRelativePath(physPath)
	if norm != "/etc/passwd" {
		t.Errorf("Expected /etc/passwd, got %s", norm)
	}
}
