package setup_test

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
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

func TestExtractRulesFromZip_ArchiveSecurity(t *testing.T) {
	// 1. Valid extraction with restrictive permissions (0600)
	t.Run("ValidExtractionWith0600Permissions", func(t *testing.T) {
		destDir := t.TempDir()
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)

		w, err := zw.Create("test_rule.yar")
		if err != nil {
			t.Fatalf("failed creating zip entry: %v", err)
		}
		_, _ = w.Write([]byte("rule test { condition: true }"))
		_ = zw.Close()

		zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
		if err != nil {
			t.Fatalf("zip reader failed: %v", err)
		}

		count, err := setup.ExtractRulesFromZip(zr, destDir)
		if err != nil {
			t.Fatalf("unexpected extract error: %v", err)
		}
		if count != 1 {
			t.Errorf("expected 1 extracted rule, got %d", count)
		}

		outPath := filepath.Join(destDir, "test_rule.yar")
		fi, err := os.Stat(outPath)
		if err != nil {
			t.Fatalf("extracted rule file missing: %v", err)
		}
		if perm := fi.Mode().Perm(); perm != 0600 {
			t.Errorf("expected extracted file permissions 0600, got 0%o", perm)
		}
	})

	// 2. ZipSlip traversal rejection
	t.Run("ZipSlipTraversalRejection", func(t *testing.T) {
		destDir := t.TempDir()
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)

		w, err := zw.Create("../../etc/evil.yar")
		if err != nil {
			t.Fatalf("failed creating zip entry: %v", err)
		}
		_, _ = w.Write([]byte("rule evil { condition: true }"))
		_ = zw.Close()

		zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
		if err != nil {
			t.Fatalf("zip reader failed: %v", err)
		}

		_, err = setup.ExtractRulesFromZip(zr, destDir)
		// Should either fail with traversal error or safely strip to base name inside destDir without escaping
		if err != nil && !strings.Contains(err.Error(), "traversal") && !strings.Contains(err.Error(), "escapes") {
			t.Errorf("expected traversal rejection error, got: %v", err)
		}
		// Confirm nothing was written outside destDir
		parentDir := filepath.Dir(destDir)
		if _, statErr := os.Stat(filepath.Join(parentDir, "etc", "evil.yar")); statErr == nil {
			t.Errorf("ZipSlip escape succeeded — file was written outside destDir!")
		}
	})

	// 3. Decompression bomb rejection (> 20MB single entry)
	t.Run("DecompressionBombRejection", func(t *testing.T) {
		destDir := t.TempDir()
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)

		// Create entry header
		w, err := zw.Create("large_rule.yar")
		if err != nil {
			t.Fatalf("failed creating zip entry: %v", err)
		}
		// Write 21MB of data (chunked to conserve memory)
		chunk := bytes.Repeat([]byte("0"), 1024*1024) // 1MB
		for i := 0; i < 21; i++ {
			if _, err := w.Write(chunk); err != nil {
				t.Fatalf("failed writing chunk: %v", err)
			}
		}
		_ = zw.Close()

		zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
		if err != nil {
			t.Fatalf("zip reader failed: %v", err)
		}

		_, err = setup.ExtractRulesFromZip(zr, destDir)
		if err == nil {
			t.Fatalf("expected decompression bomb to be rejected, got nil error")
		}
		if !strings.Contains(err.Error(), "decompression bomb") && !strings.Contains(err.Error(), "20MB") {
			t.Errorf("expected error to mention decompression bomb or 20MB limit, got: %v", err)
		}

		// Ensure truncated/oversized file was removed
		if _, statErr := os.Stat(filepath.Join(destDir, "large_rule.yar")); statErr == nil {
			t.Errorf("expected oversized extracted file to be cleaned up on failure")
		}
	})
}
