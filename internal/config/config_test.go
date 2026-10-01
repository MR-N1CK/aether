package config_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"aether/internal/config"
)

func TestNewDefaultConfig(t *testing.T) {
	cfg := config.NewDefaultConfig()

	if cfg == nil {
		t.Fatal("expected non-nil default config")
	}

	// Verify paths have sane defaults
	if len(cfg.Scan.Paths) == 0 {
		t.Errorf("expected default scan paths to be non-empty")
	}

	// Verify Linux forensic excludes: must include /proc, /sys, /dev/pts, /run/user
	requiredExcludes := []string{"/proc", "/sys", "/dev/pts", "/run/user"}
	for _, req := range requiredExcludes {
		if !slices.Contains(cfg.Scan.Excludes, req) {
			t.Errorf("expected default excludes to contain %q", req)
		}
	}

	// Verify /dev is NOT excluded wholesale
	if slices.Contains(cfg.Scan.Excludes, "/dev") {
		t.Errorf("critical failure: /dev must not be excluded wholesale, regular files in /dev must be scannable")
	}

	// Verify resource governance defaults
	if cfg.Scan.MaxFileSize <= 0 {
		t.Errorf("expected MaxFileSize > 0, got %d", cfg.Scan.MaxFileSize)
	}

	if cfg.Scan.Threads < 1 {
		t.Errorf("expected Threads >= 1, got %d", cfg.Scan.Threads)
	}

	if cfg.Logging.Level != "info" {
		t.Errorf("expected default log level 'info', got %q", cfg.Logging.Level)
	}
}

func TestParseYAML(t *testing.T) {
	yamlContent := `
scan:
  paths:
    - /opt/malware_test
  excludes:
    - /proc
    - /sys
    - /dev/pts
    - /run/user
    - /opt/malware_test/safe
  quick: true
  max_filesize: 10485760
  threads: 8
  nice: 15
  json_out: /tmp/aether-test.json
logging:
  level: debug
  format: json
`
	cfg, err := config.ParseYAML([]byte(yamlContent))
	if err != nil {
		t.Fatalf("unexpected error parsing yaml: %v", err)
	}

	if len(cfg.Scan.Paths) != 1 || cfg.Scan.Paths[0] != "/opt/malware_test" {
		t.Errorf("unexpected scan paths: %v", cfg.Scan.Paths)
	}

	if !cfg.Scan.Quick {
		t.Errorf("expected Quick to be true")
	}

	if cfg.Scan.MaxFileSize != 10485760 {
		t.Errorf("expected MaxFileSize 10485760, got %d", cfg.Scan.MaxFileSize)
	}

	if cfg.Scan.Threads != 8 {
		t.Errorf("expected Threads 8, got %d", cfg.Scan.Threads)
	}

	if cfg.Scan.Nice != 15 {
		t.Errorf("expected Nice 15, got %d", cfg.Scan.Nice)
	}

	if cfg.Scan.JSONOut != "/tmp/aether-test.json" {
		t.Errorf("expected JSONOut /tmp/aether-test.json, got %q", cfg.Scan.JSONOut)
	}

	if cfg.Logging.Level != "debug" {
		t.Errorf("expected Logging Level debug, got %q", cfg.Logging.Level)
	}

	if cfg.Logging.Format != "json" {
		t.Errorf("expected Logging Format json, got %q", cfg.Logging.Format)
	}
}

func TestParseYAML_Invalid(t *testing.T) {
	invalidYAML := `
scan:
  paths: [unterminated list
`
	_, err := config.ParseYAML([]byte(invalidYAML))
	if err == nil {
		t.Fatal("expected error parsing invalid YAML, got nil")
	}
}

func TestLoadConfig_CustomFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yamlData := `
scan:
  paths:
    - /srv
  nice: 5
logging:
  level: warn
`
	if err := os.WriteFile(configPath, []byte(yamlData), 0600); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, loadedPath, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("unexpected error loading config: %v", err)
	}

	if loadedPath != configPath {
		t.Errorf("expected loadedPath %q, got %q", configPath, loadedPath)
	}

	if len(cfg.Scan.Paths) != 1 || cfg.Scan.Paths[0] != "/srv" {
		t.Errorf("expected Paths [/srv], got %v", cfg.Scan.Paths)
	}

	if cfg.Scan.Nice != 5 {
		t.Errorf("expected Nice 5, got %d", cfg.Scan.Nice)
	}

	if cfg.Logging.Level != "warn" {
		t.Errorf("expected Level warn, got %q", cfg.Logging.Level)
	}
}

func TestLoadConfig_NonExistentCustomFile(t *testing.T) {
	_, _, err := config.LoadConfig("/nonexistent/path/to/aether.yaml")
	if err == nil {
		t.Fatal("expected error when loading nonexistent file, got nil")
	}
}

func TestLoadConfig_FallbackToDefaults(t *testing.T) {
	// Calling with empty path when neither ~/.config nor /etc has config
	// should succeed and return default configuration.
	cfg, _, err := config.LoadConfig("")
	if err != nil {
		t.Fatalf("expected fallback to default config without error, got: %v", err)
	}

	if cfg == nil {
		t.Fatal("expected non-nil default config")
	}

	if len(cfg.Scan.Paths) == 0 {
		t.Errorf("expected default paths to be set")
	}
}
