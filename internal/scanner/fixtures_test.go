package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/report"
	htmlreport "aether/internal/report/html"
	"aether/internal/ui/plain"
)

type fixtureTestCase struct {
	name            string
	fixtureDir      string
	expectedVerdict events.Verdict
	expectedRules   []string
	minSeverity     report.Severity
	mustBeClean     bool
	setup           func(t *testing.T, dir string)
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)

		if d.IsDir() {
			return os.MkdirAll(target, 0755)
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		if d.Type()&os.ModeSymlink != 0 {
			linkTarget, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(linkTarget, target)
		}

		srcF, err := os.Open(path)
		if err != nil {
			return err
		}
		defer srcF.Close()

		dstF, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
		if err != nil {
			return err
		}
		defer dstF.Close()

		if _, err := io.Copy(dstF, srcF); err != nil {
			return err
		}
		return os.Chtimes(target, info.ModTime(), info.ModTime())
	})
}

func TestFixtures_Golden(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working dir: %v", err)
	}

	fixturesRoot := filepath.Join(wd, "../../testdata/fixtures")
	if _, err := os.Stat(fixturesRoot); err != nil {
		fixturesRoot = filepath.Join(wd, "testdata/fixtures")
	}
	if _, err := os.Stat(fixturesRoot); err != nil {
		t.Fatalf("fixtures root directory not found: %s", fixturesRoot)
	}

	tests := []fixtureTestCase{
		{
			name:            "clean_debian",
			fixtureDir:      filepath.Join(fixturesRoot, "clean_debian"),
			expectedVerdict: events.VerdictClean,
			mustBeClean:     true,
		},
		{
			name:            "compromised_cron",
			fixtureDir:      filepath.Join(fixturesRoot, "compromised_cron"),
			expectedVerdict: events.VerdictSuspicious,
			expectedRules:   []string{"Persistence_Download_And_Execute"},
			minSeverity:     report.SeverityWarning,
			mustBeClean:     false,
		},
		{
			name:            "extra_uid0",
			fixtureDir:      filepath.Join(fixturesRoot, "extra_uid0"),
			expectedVerdict: events.VerdictCompromised,
			expectedRules:   []string{"Users_Extra_UID0_Account"},
			minSeverity:     report.SeverityAlert,
			mustBeClean:     false,
		},
		{
			name:            "preload_rootkit",
			fixtureDir:      filepath.Join(fixturesRoot, "preload_rootkit"),
			expectedVerdict: events.VerdictSuspicious,
			expectedRules:   []string{"Persistence_Loader_Preload"},
			minSeverity:     report.SeverityWarning,
			mustBeClean:     false,
		},
		{
			name:            "system_account_shell",
			fixtureDir:      filepath.Join(fixturesRoot, "system_account_shell"),
			expectedVerdict: events.VerdictClean,
			expectedRules:   []string{"Users_System_Account_Interactive_Shell"},
			mustBeClean:     true,
		},
		{
			name:            "ssh_backdoor",
			fixtureDir:      filepath.Join(fixturesRoot, "ssh_backdoor"),
			expectedVerdict: events.VerdictSuspicious,
			expectedRules:   []string{"Persistence_SSH_Forced_Command"},
			minSeverity:     report.SeverityWarning,
			mustBeClean:     false,
			setup: func(t *testing.T, dir string) {
				sshDir := filepath.Join(dir, "root/.ssh")
				_ = os.Chmod(sshDir, 0777)
			},
		},
		{
			name:            "systemd_tmp_exec",
			fixtureDir:      filepath.Join(fixturesRoot, "systemd_tmp_exec"),
			expectedVerdict: events.VerdictSuspicious,
			expectedRules:   []string{"Persistence_Exec_From_Temp"},
			minSeverity:     report.SeverityWarning,
			mustBeClean:     false,
		},
		{
			name:            "benign_edge_cases",
			fixtureDir:      filepath.Join(fixturesRoot, "benign_edge_cases"),
			expectedVerdict: events.VerdictClean,
			mustBeClean:     true,
			setup: func(t *testing.T, dir string) {
				tmpDir := filepath.Join(dir, "tmp")
				_ = os.Chmod(tmpDir, 01777)
			},
		},
		{
			name:            "compromised_rc_d",
			fixtureDir:      filepath.Join(fixturesRoot, "compromised_rc_d"),
			expectedVerdict: events.VerdictSuspicious,
			expectedRules:   []string{"Persistence_Download_And_Execute"},
			minSeverity:     report.SeverityWarning,
			mustBeClean:     false,
		},
		{
			name:            "clean_rc_d",
			fixtureDir:      filepath.Join(fixturesRoot, "clean_rc_d"),
			expectedVerdict: events.VerdictClean,
			mustBeClean:     true,
		},
		{
			name:            "multi_persistence",
			fixtureDir:      filepath.Join(fixturesRoot, "multi_persistence"),
			expectedVerdict: events.VerdictCompromised,
			expectedRules:   []string{"Persistence_Multi_Vector_Persistence"},
			minSeverity:     report.SeverityAlert,
			mustBeClean:     false,
		},
		{
			name:            "kali_clean_dotfiles",
			fixtureDir:      filepath.Join(fixturesRoot, "kali_clean_dotfiles"),
			expectedVerdict: events.VerdictClean,
			mustBeClean:     true,
			setup: func(t *testing.T, dir string) {
				_ = os.Chmod(filepath.Join(dir, "etc/shadow"), 0600)
			},
		},
		{
			name:            "ssh_keydrop_hidden",
			fixtureDir:      filepath.Join(fixturesRoot, "ssh_keydrop_hidden"),
			expectedVerdict: events.VerdictCompromised,
			expectedRules:   []string{"Persistence_Multi_Vector_Persistence"},
			minSeverity:     report.SeverityAlert,
			mustBeClean:     false,
			setup: func(t *testing.T, dir string) {
				_ = os.Chmod(filepath.Join(dir, "etc/shadow"), 0600)
				_ = os.Chmod(filepath.Join(dir, "root/.ssh/authorized_keys"), 0600)
				_ = os.Chmod(filepath.Join(dir, "usr/lib/.system-cache/id_ed25519"), 0600)
			},
		},
		{
			name:            "ssh_keydrop_unused",
			fixtureDir:      filepath.Join(fixturesRoot, "ssh_keydrop_unused"),
			expectedVerdict: events.VerdictSuspicious,
			expectedRules:   []string{"File_Suspicious_Private_Key_Location"},
			minSeverity:     report.SeverityWarning,
			mustBeClean:     false,
			setup: func(t *testing.T, dir string) {
				_ = os.Chmod(filepath.Join(dir, "etc/shadow"), 0600)
				_ = os.Chmod(filepath.Join(dir, "usr/lib/.system-cache/id_ed25519"), 0600)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := os.Stat(tc.fixtureDir); err != nil {
				t.Fatalf("fixture directory not found: %s (%v)", tc.fixtureDir, err)
			}

			tempRoot := t.TempDir()
			if err := copyDir(tc.fixtureDir, tempRoot); err != nil {
				t.Fatalf("failed to copy fixture to tempDir: %v", err)
			}

			if tc.setup != nil {
				tc.setup(t, tempRoot)
			}

			cfg := config.NewDefaultConfig()
			cfg.Scan.Root = tempRoot
			cfg.Scan.Full = true

			bus := events.NewEventBus()
			defer bus.Close()

			sub := bus.Subscribe()
			defer sub.Close()

			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			s := NewScanner(cfg, bus, nil, logger)

			var findings []report.Finding
			var scanFinished *events.ScanFinished

			done := make(chan struct{})
			go func() {
				defer close(done)
				for ev := range sub.Events() {
					switch e := ev.(type) {
					case events.FindingRaised:
						findings = append(findings, e.Finding)
					case events.ScanFinished:
						sf := e
						scanFinished = &sf
						return
					}
				}
			}()

			err := s.Run(context.Background())
			if err != nil {
				t.Fatalf("Scanner.Run failed: %v", err)
			}
			<-done

			if scanFinished == nil {
				t.Fatalf("expected ScanFinished event, got nil")
			}

			// Check verdict
			if scanFinished.Verdict != tc.expectedVerdict {
				t.Errorf("fixture %s: expected verdict %s, got %s (reason: %s)",
					tc.name, tc.expectedVerdict, scanFinished.Verdict, scanFinished.VerdictReason)
			}

			// Clean fixtures must have 0 Alerts and 0 Warnings
			if tc.mustBeClean {
				if scanFinished.Alerts > 0 || scanFinished.Warnings > 0 {
					var findingSummary []string
					for _, f := range findings {
						if f.Severity == report.SeverityAlert || f.Severity == report.SeverityWarning {
							findingSummary = append(findingSummary, f.RuleName+": "+f.Reason+" ("+f.Path+")")
						}
					}
					t.Errorf("fixture %s MUST be clean, but got %d alerts and %d warnings: %v",
						tc.name, scanFinished.Alerts, scanFinished.Warnings, strings.Join(findingSummary, "; "))
				}
			}

			// Assert expected rule names
			for _, expRule := range tc.expectedRules {
				found := false
				for _, f := range findings {
					if f.RuleName == expRule || strings.Contains(f.RuleName, expRule) {
						found = true
						if tc.minSeverity != "" && rankSeverity(f.Severity) < rankSeverity(tc.minSeverity) {
							t.Errorf("rule %s has severity %s, expected at least %s", expRule, f.Severity, tc.minSeverity)
						}
						break
					}
				}
				if !found {
					var ruleNames []string
					for _, f := range findings {
						ruleNames = append(ruleNames, f.RuleName)
					}
					t.Errorf("fixture %s: expected rule %s to trigger, found rules: %v", tc.name, expRule, ruleNames)
				}
			}
		})
	}
}

type fileSnapshot struct {
	mode    os.FileMode
	modTime time.Time
	size    int64
	hash    string
}

func takeTreeSnapshot(root string) (map[string]fileSnapshot, error) {
	snapshot := make(map[string]fileSnapshot)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}

		snap := fileSnapshot{
			mode:    info.Mode(),
			modTime: info.ModTime(),
			size:    info.Size(),
		}

		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			h := sha256.Sum256(data)
			snap.hash = hex.EncodeToString(h[:])
		}

		snapshot[rel] = snap
		return nil
	})
	return snapshot, err
}

func TestScanner_ReadOnlyGuarantee(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working dir: %v", err)
	}

	fixturesRoot := filepath.Join(wd, "../../testdata/fixtures")
	if _, err := os.Stat(fixturesRoot); err != nil {
		fixturesRoot = filepath.Join(wd, "testdata/fixtures")
	}

	targetFixture := filepath.Join(fixturesRoot, "clean_debian")
	tempRoot := t.TempDir()
	if err := copyDir(targetFixture, tempRoot); err != nil {
		t.Fatalf("failed to copy fixture: %v", err)
	}

	// Snapshot before scan
	beforeSnap, err := takeTreeSnapshot(tempRoot)
	if err != nil {
		t.Fatalf("failed to take snapshot before scan: %v", err)
	}

	cfg := config.NewDefaultConfig()
	cfg.Scan.Root = tempRoot
	cfg.Scan.Full = true

	bus := events.NewEventBus()
	defer bus.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewScanner(cfg, bus, nil, logger)

	err = s.Run(context.Background())
	if err != nil {
		t.Fatalf("Scanner.Run failed: %v", err)
	}

	// Snapshot after scan
	afterSnap, err := takeTreeSnapshot(tempRoot)
	if err != nil {
		t.Fatalf("failed to take snapshot after scan: %v", err)
	}

	if len(beforeSnap) != len(afterSnap) {
		t.Fatalf("tree size changed: before %d entries, after %d entries", len(beforeSnap), len(afterSnap))
	}

	for rel, before := range beforeSnap {
		after, exists := afterSnap[rel]
		if !exists {
			t.Errorf("file %s vanished after scan", rel)
			continue
		}
		if before.mode != after.mode {
			t.Errorf("file %s mode changed: was %v, now %v", rel, before.mode, after.mode)
		}
		if !before.modTime.Equal(after.modTime) {
			t.Errorf("file %s mtime changed: was %v, now %v", rel, before.modTime, after.modTime)
		}
		if before.size != after.size {
			t.Errorf("file %s size changed: was %d, now %d", rel, before.size, after.size)
		}
		if before.hash != after.hash {
			t.Errorf("file %s content changed: hash was %s, now %s", rel, before.hash, after.hash)
		}
	}
}

func TestScanner_HostConfinementIsolation(t *testing.T) {
	tempHostDir := t.TempDir()

	// Create host sentinel file outside the root
	sentinelPath := filepath.Join(tempHostDir, "host_sentinel.secret")
	sentinelContent := "TOP_SECRET_HOST_SENTINEL_STRING_12345"
	if err := os.WriteFile(sentinelPath, []byte(sentinelContent), 0600); err != nil {
		t.Fatalf("failed to write host sentinel: %v", err)
	}

	// Create synthetic root tree
	rootTree := filepath.Join(tempHostDir, "target_root")
	if err := os.MkdirAll(filepath.Join(rootTree, "etc"), 0755); err != nil {
		t.Fatalf("failed to create root etc: %v", err)
	}

	passwdContent := "root:x:0:0:root:/root:/bin/bash\n"
	if err := os.WriteFile(filepath.Join(rootTree, "etc/passwd"), []byte(passwdContent), 0644); err != nil {
		t.Fatalf("failed to write passwd: %v", err)
	}

	// 1. Absolute symlink to /etc/shadow
	_ = os.Symlink("/etc/shadow", filepath.Join(rootTree, "etc/shadow"))

	// 2. Relative escaping symlink ../../../host_sentinel.secret
	_ = os.Symlink("../../../host_sentinel.secret", filepath.Join(rootTree, "etc/escape_link"))

	// 3. Mutual symlink cycle loop_a <-> loop_b
	_ = os.Symlink("loop_b", filepath.Join(rootTree, "etc/loop_a"))
	_ = os.Symlink("loop_a", filepath.Join(rootTree, "etc/loop_b"))

	cfg := config.NewDefaultConfig()
	cfg.Scan.Root = rootTree
	cfg.Scan.Full = true

	bus := events.NewEventBus()
	defer bus.Close()

	sub := bus.Subscribe()
	defer sub.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewScanner(cfg, bus, nil, logger)

	var findings []report.Finding
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ev := range sub.Events() {
			switch e := ev.(type) {
			case events.FindingRaised:
				findings = append(findings, e.Finding)
			case events.ScanFinished:
				return
			}
		}
	}()

	err := s.Run(context.Background())
	if err != nil {
		t.Fatalf("Scanner.Run failed with confinement fixtures: %v", err)
	}
	<-done

	// Verify that the sentinel content was NEVER read or exposed in any finding
	for _, f := range findings {
		if strings.Contains(f.Reason, sentinelContent) || strings.Contains(f.Path, sentinelContent) {
			t.Fatalf("CRITICAL: scanner breached root confinement and exposed host sentinel: %+v", f)
		}
	}
}

func TestScanner_OfflineVerdictLine_NamesUnrunModules(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working dir: %v", err)
	}

	fixturesRoot := filepath.Join(wd, "../../testdata/fixtures")
	if _, err := os.Stat(fixturesRoot); err != nil {
		fixturesRoot = filepath.Join(wd, "testdata/fixtures")
	}

	targetFixture := filepath.Join(fixturesRoot, "clean_debian")

	cfg := config.NewDefaultConfig()
	cfg.Scan.Root = targetFixture
	cfg.Scan.Full = true

	bus := events.NewEventBus()
	defer bus.Close()

	subPlain := bus.Subscribe()
	defer subPlain.Close()

	subData := bus.Subscribe()
	defer subData.Close()

	var plainBuf bytes.Buffer
	plainConsumer := plain.NewConsumer(&plainBuf, nil, false)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewScanner(cfg, bus, nil, logger)

	var scanFinished *events.ScanFinished
	doneData := make(chan struct{})
	go func() {
		defer close(doneData)
		for ev := range subData.Events() {
			if sf, ok := ev.(events.ScanFinished); ok {
				scanFinished = &sf
				return
			}
		}
	}()

	donePlain := make(chan struct{})
	go func() {
		defer close(donePlain)
		_ = plainConsumer.Consume(context.Background(), subPlain)
	}()

	err = s.Run(context.Background())
	if err != nil {
		t.Fatalf("Scanner.Run failed: %v", err)
	}
	<-doneData
	<-donePlain

	if scanFinished == nil {
		t.Fatalf("expected ScanFinished event, got nil")
	}

	// Check ModulesNotRun on ScanFinished event
	var foundProcess, foundNetwork bool
	for _, m := range scanFinished.ModulesNotRun {
		if strings.Contains(m, "process") && strings.Contains(m, "offline") {
			foundProcess = true
		}
		if strings.Contains(m, "network") && strings.Contains(m, "offline") {
			foundNetwork = true
		}
	}
	if !foundProcess {
		t.Errorf("expected process module in ModulesNotRun (offline mode), got: %v", scanFinished.ModulesNotRun)
	}
	if !foundNetwork {
		t.Errorf("expected network module in ModulesNotRun (offline mode), got: %v", scanFinished.ModulesNotRun)
	}

	// Check plain output
	plainOut := plainBuf.String()
	if !strings.Contains(plainOut, "Modules Not Run:") {
		t.Errorf("plain output missing 'Modules Not Run:' header: %s", plainOut)
	}
	if !strings.Contains(plainOut, "process (not applicable in offline mode)") {
		t.Errorf("plain output missing process offline notice: %s", plainOut)
	}
	if !strings.Contains(plainOut, "network (not applicable in offline mode)") {
		t.Errorf("plain output missing network offline notice: %s", plainOut)
	}

	// Check HTML report output
	htmlData := htmlreport.HTMLReportData{
		Version:       "test-version",
		BuildDate:     "2026-10-01",
		ScanMode:      "full",
		Verdict:       scanFinished.Verdict,
		VerdictReason: scanFinished.VerdictReason,
		Partial:       scanFinished.Partial,
		ModulesNotRun: scanFinished.ModulesNotRun,
		Coverage:      scanFinished.Coverage,
	}
	htmlBytes, err := htmlreport.GenerateHTMLReport(htmlData)
	if err != nil {
		t.Fatalf("GenerateHTMLReport failed: %v", err)
	}

	htmlOut := string(htmlBytes)
	if !strings.Contains(htmlOut, "process") || !strings.Contains(htmlOut, "network") {
		t.Errorf("HTML report missing unrun offline modules in coverage: %s", htmlOut)
	}
}

func TestWorkerPoolTracker_TimeoutsAndReplacement(t *testing.T) {
	tracker := newWorkerPoolTracker()

	slot0 := tracker.registerSlot(0)
	slot1 := tracker.registerSlot(1)

	if slot0.id != 0 || slot1.id != 1 {
		t.Fatalf("unexpected slot IDs: slot0=%d, slot1=%d", slot0.id, slot1.id)
	}

	tracker.setActive(0, "/var/log/slow.log")
	tracker.setActive(1, "/etc/fast.conf")

	active := tracker.getActivePaths()
	if len(active) != 2 || active[0] != "/etc/fast.conf" || active[1] != "/var/log/slow.log" {
		t.Errorf("expected active paths [/etc/fast.conf, /var/log/slow.log], got: %v", active)
	}

	// Immediate timeout check with 1 hour -> should return nothing
	stuck := tracker.checkTimeouts(1 * time.Hour)
	if len(stuck) != 0 {
		t.Errorf("expected 0 stuck slots with 1h timeout, got %d", len(stuck))
	}

	// Timeout check with 0 duration -> returns both active slots
	stuck = tracker.checkTimeouts(0)
	if len(stuck) != 2 {
		t.Errorf("expected 2 stuck slots with 0 duration, got %d", len(stuck))
	}

	// Abandon slot 0
	if slot0.abandoned.Swap(true) {
		t.Errorf("expected slot0 abandoned to transition from false to true")
	}
	if !slot0.doneCalled.CompareAndSwap(false, true) {
		t.Errorf("expected doneCalled to transition from false to true")
	}
	// Second attempt must fail (WaitGroup safety)
	if slot0.doneCalled.CompareAndSwap(false, true) {
		t.Errorf("expected second doneCalled CompareAndSwap to return false")
	}

	tracker.mu.Lock()
	tracker.abandoned++
	tracker.mu.Unlock()

	// getActivePaths now only returns slot 1
	active = tracker.getActivePaths()
	if len(active) != 1 || active[0] != "/etc/fast.conf" {
		t.Errorf("expected active paths [/etc/fast.conf], got: %v", active)
	}

	// Clear slot 1
	tracker.clearActive(1)
	active = tracker.getActivePaths()
	if len(active) != 0 {
		t.Errorf("expected 0 active paths, got: %v", active)
	}
}

