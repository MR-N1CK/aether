package setup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureRulesDir(t *testing.T) {
	t.Run("existing directory passes untouched", func(t *testing.T) {
		dir := t.TempDir()
		// Mode must not be modified (mirrors RunSetup's chmod discipline).
		if err := os.Chmod(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := ensureRulesDir(dir); err != nil {
			t.Errorf("existing dir must pass: %v", err)
		}
		fi, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o750 {
			t.Errorf("existing permissions must be preserved, got %04o", perm)
		}
	})

	t.Run("nested missing directory is created", func(t *testing.T) {
		base := t.TempDir()
		nested := filepath.Join(base, "aether", "rules")
		if err := ensureRulesDir(nested); err != nil {
			t.Fatalf("expected creation: %v", err)
		}
		fi, err := os.Stat(nested)
		if err != nil || !fi.IsDir() {
			t.Fatalf("expected directory at %s, got %v", nested, err)
		}
		if os.Geteuid() != 0 && fi.Mode().Perm() != 0o700 {
			t.Errorf("non-root creation must use mode 0700, got %04o", fi.Mode().Perm())
		}
	})

	t.Run("file as directory rejected", func(t *testing.T) {
		base := t.TempDir()
		filePath := filepath.Join(base, "rules")
		if err := os.WriteFile(filePath, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := ensureRulesDir(filePath); err == nil {
			t.Error("a plain file must be rejected as a rules dir")
		}
	})
}
