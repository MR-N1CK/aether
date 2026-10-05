package setup_test

import (
	"os"
	"path/filepath"
	"testing"

	"aether/internal/setup"
)

func TestValidateSetupPath_RootRejectsOutsideEtcAether(t *testing.T) {
	invalidPaths := []string{
		"/tmp/aether_rules",
		"/var/aether",
		"/usr/local/share/rules",
		"/home/user/rules",
		"/etc/cron.d",
	}

	for _, p := range invalidPaths {
		_, err := setup.ValidateSetupPath(p, true)
		if err == nil {
			t.Errorf("expected error for root path outside /etc/aether: %s", p)
		}
	}

	validPaths := []string{
		"/etc/aether",
		"/etc/aether/rules",
		"/etc/aether/custom_rules",
	}

	for _, p := range validPaths {
		cleaned, err := setup.ValidateSetupPath(p, true)
		if err != nil {
			t.Errorf("expected valid path for root %s, got error: %v", p, err)
		}
		if cleaned != filepath.Clean(p) {
			t.Errorf("expected %s, got %s", filepath.Clean(p), cleaned)
		}
	}
}

func TestValidateSetupPath_RejectsSymlinks(t *testing.T) {
	tempDir := t.TempDir()

	realDir := filepath.Join(tempDir, "real_target")
	if err := os.MkdirAll(realDir, 0755); err != nil {
		t.Fatalf("failed to create real dir: %v", err)
	}

	symlinkDir := filepath.Join(tempDir, "symlink_target")
	if err := os.Symlink(realDir, symlinkDir); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	// 1. Direct symlink
	_, err := setup.ValidateSetupPath(symlinkDir, false)
	if err == nil {
		t.Errorf("expected error for symlinked setup directory %s", symlinkDir)
	}

	// 2. Symlink in ancestor path
	subDir := filepath.Join(symlinkDir, "sub_rules")
	_, err = setup.ValidateSetupPath(subDir, false)
	if err == nil {
		t.Errorf("expected error for path with symlink ancestor %s", subDir)
	}
}

func TestRunSetup_NeverChmodsExistingDirectory(t *testing.T) {
	tempDir := t.TempDir()
	customRules := filepath.Join(tempDir, "rules")

	// Create with specific mode 0750
	if err := os.MkdirAll(customRules, 0750); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}

	opts := setup.SetupOptions{
		DownloadRules: false,
		CustomDir:     customRules,
	}

	res, err := setup.RunSetup(opts, nil)
	if err != nil {
		t.Fatalf("RunSetup failed: %v", err)
	}
	if res.RulesDir != customRules {
		t.Errorf("expected %s, got %s", customRules, res.RulesDir)
	}

	// Verify mode was NOT changed
	fi, err := os.Stat(customRules)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}

	if perm := fi.Mode().Perm(); perm != 0750 {
		t.Errorf("expected existing permissions 0750 to be preserved, got 0%o", perm)
	}
}
