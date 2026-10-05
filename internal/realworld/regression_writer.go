package realworld

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// RegressionFixture specifies an ingested field anomaly turned into an automated regression test.
type RegressionFixture struct {
	AnomalyID        string                  `json:"anomaly_id"`
	RuleName         string                  `json:"rule_name"`
	Category         AnomalyTaxonomyCategory `json:"category"`
	TargetPath       string                  `json:"target_path"`
	ExpectedVerdict  string                  `json:"expected_verdict"`
	ExpectedSeverity string                  `json:"expected_severity"`
	Description      string                  `json:"description"`
	FileContents     map[string]string       `json:"file_contents,omitempty"` // rel path -> content
}

// RegressionWriter creates reproducible regression test fixtures from field findings.
type RegressionWriter struct {
	baseDir string
}

// NewRegressionWriter creates a RegressionWriter targeting baseDir.
func NewRegressionWriter(baseDir string) *RegressionWriter {
	return &RegressionWriter{
		baseDir: baseDir,
	}
}

// WriteFixture persists a minimal reproducible regression fixture to disk.
func (w *RegressionWriter) WriteFixture(fix RegressionFixture) (string, error) {
	if fix.AnomalyID == "" {
		return "", fmt.Errorf("missing anomaly_id")
	}

	fixtureDir := filepath.Join(w.baseDir, fix.AnomalyID)
	if err := os.MkdirAll(fixtureDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create fixture dir %s: %w", fixtureDir, err)
	}

	// 1. Write regression metadata
	metaPath := filepath.Join(fixtureDir, "regression.json")
	data, err := json.MarshalIndent(fix, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal regression metadata: %w", err)
	}
	if err := os.WriteFile(metaPath, append(data, '\n'), 0644); err != nil {
		return "", fmt.Errorf("failed to write regression.json: %w", err)
	}

	// 2. Write file payloads under rootfs
	rootFS := filepath.Join(fixtureDir, "rootfs")
	for relPath, content := range fix.FileContents {
		targetFile := filepath.Join(rootFS, relPath)
		if err := os.MkdirAll(filepath.Dir(targetFile), 0755); err != nil {
			return "", fmt.Errorf("failed to create dir for %s: %w", targetFile, err)
		}
		if err := os.WriteFile(targetFile, []byte(content), 0644); err != nil {
			return "", fmt.Errorf("failed to write payload %s: %w", targetFile, err)
		}
	}

	return fixtureDir, nil
}

// LoadFixture reads and parses a RegressionFixture from a directory containing regression.json.
func (w *RegressionWriter) LoadFixture(fixtureDir string) (*RegressionFixture, error) {
	metaPath := filepath.Join(fixtureDir, "regression.json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", metaPath, err)
	}

	var fix RegressionFixture
	if err := json.Unmarshal(data, &fix); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", metaPath, err)
	}

	return &fix, nil
}
