package scanner

import (
	"log/slog"
	"testing"

	"aether/internal/config"
	"aether/internal/events"
)

// moduleProfileOf runs buildDefaultModules and returns the selected live
// module count plus whether the filesystem-only (empty live set) profile
// was chosen. The filesystem module is the scanner core itself, so a
// filesystem-only scan yields an empty live-module slice.
func moduleProfileOf(t *testing.T, cfg *config.Config) (count int) {
	t.Helper()
	mods := buildDefaultModules(cfg, "", nil, events.NewEventBus(), slog.New(slog.NewTextHandler(testDiscard{}, nil)))
	return len(mods)
}

type testDiscard struct{}

func (testDiscard) Write(p []byte) (int, error) { return len(p), nil }

func TestBuildDefaultModules_Profiles(t *testing.T) {
	base := func() *config.Config { return config.NewDefaultConfig() }

	t.Run("QuickWithoutPath_RunsFullSet", func(t *testing.T) {
		cfg := base()
		cfg.Scan.Quick = true
		if got := moduleProfileOf(t, cfg); got != 6 {
			t.Errorf("quick without explicit path: live modules = %d, want 6", got)
		}
	})

	t.Run("FullAlwaysRunsFullSet", func(t *testing.T) {
		cfg := base()
		cfg.Scan.Full = true
		cfg.Scan.ExplicitPaths = true
		cfg.Scan.Paths = []string{"/tmp/demo"}
		if got := moduleProfileOf(t, cfg); got != 6 {
			t.Errorf("full scan: live modules = %d, want 6 (full overrides explicit paths)", got)
		}
	})

	t.Run("ExplicitPathWithQuick_IsFilesystemOnly", func(t *testing.T) {
		cfg := base()
		cfg.Scan.Quick = true
		cfg.Scan.ExplicitPaths = true
		cfg.Scan.Paths = []string{"/tmp/demo"}
		if got := moduleProfileOf(t, cfg); got != 0 {
			t.Errorf("quick + explicit path: live modules = %d, want 0 (filesystem-only) — explicit user path must win", got)
		}
	})

	t.Run("PlainScanWithPath_IsFilesystemOnly", func(t *testing.T) {
		cfg := base()
		cfg.Scan.ExplicitPaths = true
		cfg.Scan.Paths = []string{"/tmp/demo"}
		if got := moduleProfileOf(t, cfg); got != 0 {
			t.Errorf("plain scan with path: live modules = %d, want 0", got)
		}
	})

	t.Run("PlainScanWithoutPath_RunsFullSet", func(t *testing.T) {
		if got := moduleProfileOf(t, base()); got != 6 {
			t.Errorf("plain scan without path: live modules = %d, want 6", got)
		}
	})

	t.Run("ExplicitModulesFlag_AlwaysWins", func(t *testing.T) {
		cfg := base()
		cfg.Scan.Quick = true
		cfg.Scan.ExplicitPaths = true
		cfg.Scan.Paths = []string{"/tmp/demo"}
		cfg.Scan.Modules = []string{"process", "filesystem"}
		if got := moduleProfileOf(t, cfg); got != 1 {
			t.Errorf("explicit --modules: live modules = %d, want 1 (only process is a live module)", got)
		}
	})

	t.Run("DefaultPathsCountAsNonCustom", func(t *testing.T) {
		cfg := base()
		cfg.Scan.Paths = config.DefaultScanPaths()
		if got := moduleProfileOf(t, cfg); got != 6 {
			t.Errorf("default quick paths: live modules = %d, want 6", got)
		}
	})
}
