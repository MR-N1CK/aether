package scanner_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/modules"
	"aether/internal/report"
	"aether/internal/scanner"
	"aether/internal/ui/plain"
	"aether/internal/yara"
)

func TestOpenRegularReadOnly_FIFO(t *testing.T) {
	tmpDir := t.TempDir()
	fifoPath := filepath.Join(tmpDir, "test.fifo")

	// Create a named pipe (FIFO)
	err := unix.Mkfifo(fifoPath, 0600)
	if err != nil {
		t.Skipf("mkfifo not supported in environment: %v", err)
	}

	// Attempting to open FIFO with OpenRegularReadOnly must NOT block
	// and must return ErrNotRegularFile immediately thanks to O_NONBLOCK + fstat.
	done := make(chan error, 1)
	go func() {
		_, err := scanner.OpenRegularReadOnly(fifoPath, 1024*1024)
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, scanner.ErrNotRegularFile) {
			t.Errorf("expected ErrNotRegularFile, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OpenRegularReadOnly blocked on FIFO pipe! O_NONBLOCK or fstat failed")
	}
}

func TestOpenRegularReadOnly_Oversize(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "large.bin")
	data := make([]byte, 1024)
	if err := os.WriteFile(testFile, data, 0600); err != nil {
		t.Fatal(err)
	}

	// Limit is 512 bytes, file is 1024 bytes -> must return ErrFileTooLarge before reading
	_, err := scanner.OpenRegularReadOnly(testFile, 512)
	if !errors.Is(err, scanner.ErrFileTooLarge) {
		t.Errorf("expected ErrFileTooLarge, got: %v", err)
	}
}

func TestScanner_SymlinkSkipping(t *testing.T) {
	tmpDir := t.TempDir()
	realDir := filepath.Join(tmpDir, "real")
	if err := os.MkdirAll(realDir, 0700); err != nil {
		t.Fatal(err)
	}

	realFile := filepath.Join(realDir, "file.txt")
	if err := os.WriteFile(realFile, []byte("normal content"), 0600); err != nil {
		t.Fatal(err)
	}

	// Create a symlink pointing to parent creating a loop
	symlinkLoop := filepath.Join(realDir, "loop_link")
	if err := os.Symlink(realDir, symlinkLoop); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{realDir}
	cfg.Scan.Threads = 2

	bus := events.NewEventBus()
	defer bus.Close()

	sub := bus.Subscribe()
	defer sub.Close()

	s := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules(nil))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := s.Run(ctx)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
}

func TestScanner_HardlinkDeduplication(t *testing.T) {
	tmpDir := t.TempDir()
	file1 := filepath.Join(tmpDir, "original.txt")
	content := []byte("shared content for hardlink test")
	if err := os.WriteFile(file1, content, 0600); err != nil {
		t.Fatal(err)
	}

	// Create hardlink
	file2 := filepath.Join(tmpDir, "hardlink.txt")
	if err := os.Link(file1, file2); err != nil {
		t.Skipf("hardlinks not supported: %v", err)
	}

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{tmpDir}
	cfg.Scan.Threads = 1

	bus := events.NewEventBus()
	defer bus.Close()

	var scannedFiles []string
	var filesScannedCount int64
	sub := bus.Subscribe()
	defer sub.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range sub.Events() {
			if fsEv, ok := e.(events.FileScanned); ok {
				scannedFiles = append(scannedFiles, fsEv.Path)
			}
			if sf, ok := e.(events.ScanFinished); ok {
				filesScannedCount = sf.FilesScanned
				return
			}
		}
	}()

	s := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules(nil))
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	<-done
	bus.Close()

	if filesScannedCount != 2 {
		t.Errorf("expected 2 files scanned in ScanFinished, got: %d (ephemeral received: %d)", filesScannedCount, len(scannedFiles))
	}
}

func TestScanner_EICARHarmlessTestStringAndAllowlist(t *testing.T) {
	tmpDir := t.TempDir()

	harmlessTestString := []byte("AETHER_TEST_HARLESS_STRING_FOR_VERIFICATION")
	h := sha256.Sum256(harmlessTestString)
	testSha256 := hex.EncodeToString(h[:])

	iocDir := filepath.Join(tmpDir, "iocs")
	_ = os.MkdirAll(iocDir, 0700)
	iocFile := filepath.Join(iocDir, "hashes.txt")
	_ = os.WriteFile(iocFile, []byte(testSha256+" # Synthetic_Test_IOC\n"), 0600)

	testFile := filepath.Join(tmpDir, "sample_threat.bin")
	_ = os.WriteFile(testFile, harmlessTestString, 0600)

	allowlistFile := filepath.Join(tmpDir, "allowlist.txt")
	_ = os.WriteFile(allowlistFile, []byte(testSha256+" # Trusted_Testing_Hash\n"), 0600)

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{tmpDir}
	cfg.Scan.IOCDir = iocDir
	cfg.Scan.AllowlistPath = allowlistFile
	cfg.Scan.Threads = 1

	bus := events.NewEventBus()
	defer bus.Close()

	var findings []report.Finding
	sub := bus.Subscribe()
	defer sub.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range sub.Events() {
			if fr, ok := e.(events.FindingRaised); ok {
				if fr.Finding.Module == "filesystem" {
					findings = append(findings, fr.Finding)
				}
			}
			if _, ok := e.(events.ScanFinished); ok {
				return
			}
		}
	}()

	s := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules(nil))
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	<-done
	bus.Close()

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (hash IOC match must survive allowlist), got: %d", len(findings))
	}

	if findings[0].Severity != report.SeverityAlert {
		t.Errorf("expected SeverityAlert for hash IOC, got: %s", findings[0].Severity)
	}
}

func TestScanner_PermissionDeniedHandling(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping permission denied test as root user")
	}

	tmpDir := t.TempDir()
	unreadableFile := filepath.Join(tmpDir, "no_access.txt")
	if err := os.WriteFile(unreadableFile, []byte("secret"), 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(unreadableFile, 0600)

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{tmpDir}
	cfg.Scan.Threads = 1

	bus := events.NewEventBus()
	defer bus.Close()

	var errorEvents []events.Error
	sub := bus.Subscribe()
	defer sub.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range sub.Events() {
			if errEv, ok := e.(events.Error); ok {
				errorEvents = append(errorEvents, errEv)
			}
			if _, ok := e.(events.ScanFinished); ok {
				return
			}
		}
	}()

	s := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules(nil))
	err := s.Run(context.Background())
	if err != nil {
		t.Fatalf("scan should not fail fatally on permission denied: %v", err)
	}

	<-done
	bus.Close()

	if len(errorEvents) == 0 {
		t.Errorf("expected Error event for unreadable file, got none")
	} else if errorEvents[0].Module != "filesystem" {
		t.Errorf("expected Error event Module to be 'filesystem', got %q", errorEvents[0].Module)
	}
}

func TestScanner_ExplicitPathRestrictsQuickScan(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{tmpDir}
	cfg.Scan.ExplicitPaths = true
	cfg.Scan.Quick = true

	s := scanner.NewScanner(cfg, nil, nil, nil, scanner.WithModules(nil))
	targets := s.ResolveTargets()

	if len(targets) != 1 || targets[0] != tmpDir {
		t.Fatalf("expected explicit --path to restrict targets to [%s], got %v", tmpDir, targets)
	}

	cfgDefault := config.NewDefaultConfig()
	cfgDefault.Scan.Quick = true
	sDefault := scanner.NewScanner(cfgDefault, nil, nil, nil, scanner.WithModules(nil))
	targetsDefault := sDefault.ResolveTargets()

	if len(targetsDefault) <= 1 {
		t.Fatalf("expected quick scan without --path to resolve multiple built-in targets, got: %v", targetsDefault)
	}
}

func TestScanner_BenignPatternSuppression(t *testing.T) {
	tmpDir := t.TempDir()

	benignDir := filepath.Join(tmpDir, "benign_cache")
	if err := os.MkdirAll(benignDir, 0700); err != nil {
		t.Fatal(err)
	}

	iocDir := filepath.Join(tmpDir, "iocs")
	_ = os.MkdirAll(iocDir, 0700)
	benignConfig := filepath.Join(iocDir, "known_benign.yaml")
	benignYAML := `
- path_regex: '.*benign_cache/.*'
  reason: 'Test benign cache pattern'
`
	if err := os.WriteFile(benignConfig, []byte(benignYAML), 0600); err != nil {
		t.Fatal(err)
	}

	elfHeader := []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00, 0x00}
	benignFile := filepath.Join(benignDir, "benign_tool")
	if err := os.WriteFile(benignFile, elfHeader, 0755); err != nil {
		t.Fatal(err)
	}

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{benignDir}
	cfg.Scan.ExplicitPaths = true
	cfg.Scan.IOCDir = iocDir
	cfg.Scan.Threads = 1

	bus := events.NewEventBus()
	defer bus.Close()

	var findings []report.Finding
	sub := bus.Subscribe()
	defer sub.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range sub.Events() {
			if fr, ok := e.(events.FindingRaised); ok {
				findings = append(findings, fr.Finding)
			}
			if _, ok := e.(events.ScanFinished); ok {
				return
			}
		}
	}()

	s := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules(nil))
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	<-done
	bus.Close()

	for _, f := range findings {
		if f.RuleName == "Heuristic_ELF_In_Temp" || f.RuleName == "Heuristic_ELF_In_Temp_Escalated" {
			t.Fatalf("expected ELF-in-temp heuristic to be suppressed for known benign path, got finding: %+v", f)
		}
	}
}

func TestScanner_FindingGrouping(t *testing.T) {
	baseDir := filepath.Join(os.TempDir(), fmt.Sprintf("aether_group_test_%d", time.Now().UnixNano()))
	_ = os.RemoveAll(baseDir)
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(baseDir)

	elfData := []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00, 0x00}
	file1 := filepath.Join(baseDir, "tool1")
	file2 := filepath.Join(baseDir, "tool2")
	file3 := filepath.Join(baseDir, "tool3")

	for _, p := range []string{file1, file2, file3} {
		if err := os.WriteFile(p, elfData, 0755); err != nil {
			t.Fatal(err)
		}
	}

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{baseDir}
	cfg.Scan.ExplicitPaths = true
	cfg.Scan.Threads = 1

	bus := events.NewEventBus()
	defer bus.Close()

	var findings []report.Finding
	sub := bus.Subscribe()
	defer sub.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range sub.Events() {
			if fr, ok := e.(events.FindingRaised); ok {
				if fr.Finding.Module == "filesystem" {
					findings = append(findings, fr.Finding)
				}
			}
			if _, ok := e.(events.ScanFinished); ok {
				return
			}
		}
	}()

	s := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules(nil))
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	<-done
	bus.Close()

	if len(findings) != 1 {
		t.Fatalf("expected 1 grouped finding, got %d: %+v", len(findings), findings)
	}

	gf := findings[0]
	if gf.Count != 3 {
		t.Errorf("expected grouped Count == 3, got %d", gf.Count)
	}
	if len(gf.Paths) != 3 {
		t.Errorf("expected 3 paths in grouped Paths, got %d", len(gf.Paths))
	}
	if gf.Path != baseDir {
		t.Errorf("expected Path to be parent directory %q, got %q", baseDir, gf.Path)
	}
	if gf.Reason == "" {
		t.Errorf("expected non-empty Reason")
	}
}

type mockYaraEngine struct {
	matches         []yara.RuleMatch
	ruleFilesSeen   int64
	skippedOversize int64
	notRunReason    string
}

func (m *mockYaraEngine) LoadRules(rulePaths []string) error { return nil }
func (m *mockYaraEngine) NewScanner() yara.Scanner           { return &mockYaraScanner{engine: m} }
func (m *mockYaraEngine) Coverage() events.YARACoverageStats {
	return events.YARACoverageStats{
		CompiledIn:      true,
		RuleFilesSeen:   m.ruleFilesSeen,
		SkippedOversize: m.skippedOversize,
		NotRunReason:    m.notRunReason,
	}
}
func (m *mockYaraEngine) Close() error       { return nil }
func (m *mockYaraEngine) RecordRuleFileSeen() { m.ruleFilesSeen++ }
func (m *mockYaraEngine) RecordSkipOversize() { m.skippedOversize++ }
func (m *mockYaraEngine) Enabled() bool       { return m.notRunReason == "" }

type mockYaraScanner struct {
	engine *mockYaraEngine
}

func (s *mockYaraScanner) Scan(target yara.ScanTarget) ([]yara.RuleMatch, error) {
	return s.engine.matches, nil
}
func (s *mockYaraScanner) Destroy() {}

func TestScanner_OversizeFileSkippedAndCounted(t *testing.T) {
	tmpDir := t.TempDir()
	smallFile := filepath.Join(tmpDir, "small.txt")
	largeFile := filepath.Join(tmpDir, "large.txt")

	if err := os.WriteFile(smallFile, []byte("short content"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(largeFile, make([]byte, 2048), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{tmpDir}
	cfg.Scan.MaxFileSize = 512
	cfg.Scan.Threads = 1

	bus := events.NewEventBus()
	defer bus.Close()

	sub := bus.Subscribe()
	defer sub.Close()

	var finishEv events.ScanFinished
	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range sub.Events() {
			if sf, ok := e.(events.ScanFinished); ok {
				finishEv = sf
				return
			}
		}
	}()

	s := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules(nil))
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	<-done

	if finishEv.Coverage.SkippedOversize != 1 {
		t.Errorf("expected SkippedOversize == 1, got %d", finishEv.Coverage.SkippedOversize)
	}
	if finishEv.Coverage.FilesScanned != 1 {
		t.Errorf("expected FilesScanned == 1, got %d", finishEv.Coverage.FilesScanned)
	}
}

func TestScanner_RulesDirFilesStillHashedAndIOCChecked(t *testing.T) {
	tmpDir := t.TempDir()
	rulesDir := filepath.Join(tmpDir, "rules")
	_ = os.MkdirAll(rulesDir, 0700)

	ruleContent := []byte("rule MaliciousLookingRule { condition: true }\n")
	rulePath := filepath.Join(rulesDir, "malicious.yar")
	if err := os.WriteFile(rulePath, ruleContent, 0600); err != nil {
		t.Fatal(err)
	}

	h := sha256.Sum256(ruleContent)
	shaStr := hex.EncodeToString(h[:])

	iocDir := filepath.Join(tmpDir, "iocs")
	_ = os.MkdirAll(iocDir, 0700)
	iocFile := filepath.Join(iocDir, "hashes.txt")
	_ = os.WriteFile(iocFile, []byte(shaStr+" # Rule_File_IOC\n"), 0600)

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{rulesDir}
	cfg.Scan.IOCDir = iocDir
	cfg.Scan.Threads = 1

	bus := events.NewEventBus()
	defer bus.Close()

	sub := bus.Subscribe()
	defer sub.Close()

	var findings []report.Finding
	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range sub.Events() {
			if fr, ok := e.(events.FindingRaised); ok {
				findings = append(findings, fr.Finding)
			}
			if _, ok := e.(events.ScanFinished); ok {
				return
			}
		}
	}()

	s := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules(nil))
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	<-done

	found := false
	for _, f := range findings {
		if f.Path == rulePath && f.Severity == report.SeverityAlert {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected file in rules dir to be hashed and trigger IOC finding (SeverityAlert), findings: %+v", findings)
	}
}

func TestScanner_RuleFileQualification(t *testing.T) {
	tmpDir := t.TempDir()

	_ = os.MkdirAll(filepath.Join(tmpDir, "d_valid"), 0700)
	validRule := filepath.Join(tmpDir, "d_valid", "valid.yar")
	_ = os.WriteFile(validRule, []byte("rule TestValid { condition: true }"), 0600)

	_ = os.MkdirAll(filepath.Join(tmpDir, "d_nul"), 0700)
	nulRule := filepath.Join(tmpDir, "d_nul", "with_nul.yar")
	_ = os.WriteFile(nulRule, []byte("rule TestNul {\x00 condition: true }"), 0600)

	_ = os.MkdirAll(filepath.Join(tmpDir, "d_elf"), 0700)
	elfRule := filepath.Join(tmpDir, "d_elf", "fake_elf.yar")
	_ = os.WriteFile(elfRule, []byte("\x7fELF rule TestElf { condition: true }"), 0600)

	_ = os.MkdirAll(filepath.Join(tmpDir, "d_shebang"), 0700)
	shebangRule := filepath.Join(tmpDir, "d_shebang", "script.yar")
	_ = os.WriteFile(shebangRule, []byte("#!/bin/bash\nrule TestBash { condition: true }"), 0600)

	_ = os.MkdirAll(filepath.Join(tmpDir, "d_random"), 0700)
	notRule := filepath.Join(tmpDir, "d_random", "random.yar")
	_ = os.WriteFile(notRule, []byte("just some plain text without rule syntax"), 0600)

	mockEngine := &mockYaraEngine{
		matches: []yara.RuleMatch{
			{
				RuleName: "Generic_Yara_Match",
				Score:    60,
				Severity: report.SeverityWarning,
			},
		},
	}

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{tmpDir}
	cfg.Scan.Threads = 1

	bus := events.NewEventBus()
	defer bus.Close()

	sub := bus.Subscribe()
	defer sub.Close()

	var findings []report.Finding
	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range sub.Events() {
			if fr, ok := e.(events.FindingRaised); ok {
				findings = append(findings, fr.Finding)
			}
			if _, ok := e.(events.ScanFinished); ok {
				return
			}
		}
	}()

	s := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules(nil), scanner.WithYARAEngine(mockEngine))
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	<-done

	var validFinding *report.Finding
	var warningFindings []report.Finding

	for i := range findings {
		f := &findings[i]
		if f.Severity == report.SeverityInfo {
			validFinding = f
		} else if f.Severity == report.SeverityWarning {
			warningFindings = append(warningFindings, *f)
		}
	}

	if validFinding == nil {
		t.Fatalf("expected finding for valid rule %s", validRule)
	}
	if validFinding.Path != validRule {
		t.Errorf("expected valid finding path %s, got: %s", validRule, validFinding.Path)
	}
	if validFinding.Severity != report.SeverityInfo {
		t.Errorf("expected valid.yar severity to be INFO, got: %s", validFinding.Severity)
	}
	if validFinding.Reason != "looks like a YARA rule file" {
		t.Errorf("expected valid.yar reason 'looks like a YARA rule file', got: %s", validFinding.Reason)
	}
	if validFinding.Metadata["is_rule_file"] != true {
		t.Errorf("expected valid.yar is_rule_file metadata to be true")
	}

	if len(warningFindings) == 0 {
		t.Fatalf("expected warning findings for non-qualifying rule files")
	}
	for _, wf := range warningFindings {
		if wf.Severity == report.SeverityInfo {
			t.Errorf("expected warning finding, got INFO: %+v", wf)
		}
	}

	if mockEngine.ruleFilesSeen != 1 {
		t.Errorf("expected ruleFilesSeen == 1, got %d", mockEngine.ruleFilesSeen)
	}
}

// ---------------------------------------------------------------------------
// Named Unit Tests for Build Tree Recognition and Grouping
// ---------------------------------------------------------------------------

func TestBuildTree_CargoTargetOneNotice(t *testing.T) {
	baseDir := filepath.Join(os.TempDir(), fmt.Sprintf("aether_test_build_cargo_%d", time.Now().UnixNano()))
	_ = os.RemoveAll(baseDir)
	if err := os.MkdirAll(filepath.Join(baseDir, "target", "debug"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(baseDir, "target", "release"), 0755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(baseDir)

	if err := os.WriteFile(filepath.Join(baseDir, "Cargo.toml"), []byte("[package]\nname=\"test\"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	elfData := []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00, 0x00}
	app1 := filepath.Join(baseDir, "target", "debug", "app1")
	app2 := filepath.Join(baseDir, "target", "release", "app2")

	if err := os.WriteFile(app1, elfData, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(app2, elfData, 0755); err != nil {
		t.Fatal(err)
	}

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{baseDir}
	cfg.Scan.ExplicitPaths = true
	cfg.Scan.Threads = 1

	bus := events.NewEventBus()
	defer bus.Close()

	var findings []report.Finding
	sub := bus.Subscribe()
	defer sub.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range sub.Events() {
			if fr, ok := e.(events.FindingRaised); ok {
				if fr.Finding.Module == "filesystem" {
					findings = append(findings, fr.Finding)
				}
			}
			if _, ok := e.(events.ScanFinished); ok {
				return
			}
		}
	}()

	s := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules(nil))
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	<-done

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 grouped finding for cargo build tree, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if f.Severity != report.SeverityNotice {
		t.Errorf("expected SeverityNotice for build tree, got %s", f.Severity)
	}
	if f.Count != 2 {
		t.Errorf("expected Count == 2, got %d", f.Count)
	}
	if f.Path != baseDir {
		t.Errorf("expected Path == %s, got %s", baseDir, f.Path)
	}
	if !bytes.Contains([]byte(f.Reason), []byte("looks like a build tree")) {
		t.Errorf("expected Reason to mention 'looks like a build tree', got: %s", f.Reason)
	}
}

func TestBuildTree_SUIDFileNotDowngraded(t *testing.T) {
	baseDir := filepath.Join(os.TempDir(), fmt.Sprintf("aether_test_build_suid_%d", time.Now().UnixNano()))
	_ = os.RemoveAll(baseDir)
	if err := os.MkdirAll(filepath.Join(baseDir, "target", "debug"), 0755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(baseDir)

	if err := os.WriteFile(filepath.Join(baseDir, "Cargo.toml"), []byte("[package]\nname=\"test\"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	elfData := []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00, 0x00}
	suidApp := filepath.Join(baseDir, "target", "debug", "suid_app")
	if err := os.WriteFile(suidApp, elfData, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(suidApp, 0755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{baseDir}
	cfg.Scan.ExplicitPaths = true
	cfg.Scan.Threads = 1

	bus := events.NewEventBus()
	defer bus.Close()

	var findings []report.Finding
	sub := bus.Subscribe()
	defer sub.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range sub.Events() {
			if fr, ok := e.(events.FindingRaised); ok {
				if fr.Finding.Module == "filesystem" {
					findings = append(findings, fr.Finding)
				}
			}
			if _, ok := e.(events.ScanFinished); ok {
				return
			}
		}
	}()

	s := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules(nil))
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	<-done

	if len(findings) == 0 {
		t.Fatalf("expected at least 1 finding for SUID binary")
	}

	for _, f := range findings {
		if f.Severity == report.SeverityNotice || f.Severity == report.SeverityInfo {
			t.Errorf("SUID file must NOT be downgraded to NOTICE/INFO: %+v", f)
		}
		if f.Severity != report.SeverityWarning && f.Severity != report.SeverityAlert {
			t.Errorf("expected SUID file severity WARNING or ALERT, got %s", f.Severity)
		}
	}
}

func TestBuildTree_NoMarkerWarning(t *testing.T) {
	baseDir := filepath.Join(os.TempDir(), fmt.Sprintf("aether_test_no_marker_%d", time.Now().UnixNano()))
	_ = os.RemoveAll(baseDir)
	if err := os.MkdirAll(filepath.Join(baseDir, "target", "debug"), 0755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(baseDir)

	elfData := []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00, 0x00}
	app := filepath.Join(baseDir, "target", "debug", "unmarked_app")
	if err := os.WriteFile(app, elfData, 0755); err != nil {
		t.Fatal(err)
	}

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{baseDir}
	cfg.Scan.ExplicitPaths = true
	cfg.Scan.Threads = 1

	bus := events.NewEventBus()
	defer bus.Close()

	var findings []report.Finding
	sub := bus.Subscribe()
	defer sub.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range sub.Events() {
			if fr, ok := e.(events.FindingRaised); ok {
				if fr.Finding.Module == "filesystem" {
					findings = append(findings, fr.Finding)
				}
			}
			if _, ok := e.(events.ScanFinished); ok {
				return
			}
		}
	}()

	s := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules(nil))
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	<-done

	if len(findings) == 0 {
		t.Fatalf("expected finding for ELF without marker")
	}

	if findings[0].Severity != report.SeverityWarning {
		t.Errorf("expected SeverityWarning for ELF without marker, got %s", findings[0].Severity)
	}
}

func TestBuildTree_BuildScriptNameNoMarkerWarning(t *testing.T) {
	baseDir := filepath.Join(os.TempDir(), fmt.Sprintf("aether_test_bsb_%d", time.Now().UnixNano()))
	_ = os.RemoveAll(baseDir)
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(baseDir)

	elfData := []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00, 0x00}
	bsb := filepath.Join(baseDir, "build-script-build")
	if err := os.WriteFile(bsb, elfData, 0755); err != nil {
		t.Fatal(err)
	}

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{baseDir}
	cfg.Scan.ExplicitPaths = true
	cfg.Scan.Threads = 1

	bus := events.NewEventBus()
	defer bus.Close()

	var findings []report.Finding
	sub := bus.Subscribe()
	defer sub.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range sub.Events() {
			if fr, ok := e.(events.FindingRaised); ok {
				if fr.Finding.Module == "filesystem" {
					findings = append(findings, fr.Finding)
				}
			}
			if _, ok := e.(events.ScanFinished); ok {
				return
			}
		}
	}()

	s := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules(nil))
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	<-done

	if len(findings) == 0 {
		t.Fatalf("expected finding for build-script-build without marker")
	}

	if findings[0].Severity != report.SeverityWarning {
		t.Errorf("expected SeverityWarning for build-script-build without marker, got %s", findings[0].Severity)
	}
}

func TestBuildTree_PlantedMarkerBesideDropperWarning(t *testing.T) {
	baseDir := filepath.Join(os.TempDir(), fmt.Sprintf("aether_test_planted_%d", time.Now().UnixNano()))
	_ = os.RemoveAll(baseDir)
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(baseDir)

	// Marker planted directly beside dropper (NOT in target, build, deps, out, dist)
	if err := os.WriteFile(filepath.Join(baseDir, "Cargo.toml"), []byte("[package]\nname=\"planted\"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	elfData := []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00, 0x00}
	dropper := filepath.Join(baseDir, "dropper")
	if err := os.WriteFile(dropper, elfData, 0755); err != nil {
		t.Fatal(err)
	}

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{baseDir}
	cfg.Scan.ExplicitPaths = true
	cfg.Scan.Threads = 1

	bus := events.NewEventBus()
	defer bus.Close()

	var findings []report.Finding
	sub := bus.Subscribe()
	defer sub.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range sub.Events() {
			if fr, ok := e.(events.FindingRaised); ok {
				if fr.Finding.Module == "filesystem" {
					findings = append(findings, fr.Finding)
				}
			}
			if _, ok := e.(events.ScanFinished); ok {
				return
			}
		}
	}()

	s := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules(nil))
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	<-done

	if len(findings) == 0 {
		t.Fatalf("expected finding for planted dropper")
	}

	if findings[0].Severity != report.SeverityWarning {
		t.Errorf("planted dropper beside marker must NOT be downgraded to NOTICE, got %s", findings[0].Severity)
	}
}

func TestBuildTree_MarkerOwnerMismatchWarning(t *testing.T) {
	baseDir := filepath.Join(os.TempDir(), fmt.Sprintf("aether_test_mismatch_%d", time.Now().UnixNano()))
	_ = os.RemoveAll(baseDir)
	if err := os.MkdirAll(filepath.Join(baseDir, "target", "debug"), 0755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(baseDir)

	if err := os.WriteFile(filepath.Join(baseDir, "Cargo.toml"), []byte("[package]\nname=\"mismatch\"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	elfPath := filepath.Join(baseDir, "target", "debug", "app")
	elfData := []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00, 0x00}
	if err := os.WriteFile(elfPath, elfData, 0755); err != nil {
		t.Fatal(err)
	}

	cfg := config.NewDefaultConfig()

	// Check with elfUid = 99999 (mismatched owner from marker which is owned by current user)
	isBuildTree, _ := scanner.CheckBuildTree(elfPath, 0755, 99999, false, cfg)
	if isBuildTree {
		t.Errorf("expected CheckBuildTree to return false on owner mismatch")
	}

	match := scanner.CheckELFInTempOrDev(elfPath, elfData, 0755, 99999, false, cfg)
	if match == nil {
		t.Fatalf("expected heuristic match for ELF in temp")
	}
	if match.Severity != report.SeverityWarning {
		t.Errorf("expected SeverityWarning on owner mismatch, got: %s", match.Severity)
	}
}

func TestGrouping_WarningNotMergedIntoNoticeGroup(t *testing.T) {
	baseDir := filepath.Join(os.TempDir(), fmt.Sprintf("aether_test_group_mixed_%d", time.Now().UnixNano()))
	_ = os.RemoveAll(baseDir)
	if err := os.MkdirAll(filepath.Join(baseDir, "target", "debug"), 0755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(baseDir)

	if err := os.WriteFile(filepath.Join(baseDir, "Cargo.toml"), []byte("[package]\nname=\"mixed\"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	elfData := []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00, 0x00}
	normal1 := filepath.Join(baseDir, "target", "debug", "normal1")
	normal2 := filepath.Join(baseDir, "target", "debug", "normal2")
	suidFile := filepath.Join(baseDir, "target", "debug", "suid_tool")

	if err := os.WriteFile(normal1, elfData, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(normal2, elfData, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(suidFile, elfData, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(suidFile, 0755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{baseDir}
	cfg.Scan.ExplicitPaths = true
	cfg.Scan.Threads = 1

	bus := events.NewEventBus()
	defer bus.Close()

	var findings []report.Finding
	sub := bus.Subscribe()
	defer sub.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range sub.Events() {
			if fr, ok := e.(events.FindingRaised); ok {
				if fr.Finding.Module == "filesystem" {
					findings = append(findings, fr.Finding)
				}
			}
			if _, ok := e.(events.ScanFinished); ok {
				return
			}
		}
	}()

	s := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules(nil))
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	<-done

	if len(findings) < 2 {
		t.Fatalf("expected at least 2 distinct findings (WARNING not merged with NOTICE), got %d: %+v", len(findings), findings)
	}

	var hasNoticeGroup, hasWarningOrAlert bool
	for _, f := range findings {
		if f.Severity == report.SeverityNotice {
			hasNoticeGroup = true
			if f.Count != 2 {
				t.Errorf("expected NOTICE group Count == 2, got %d", f.Count)
			}
		} else if f.Severity == report.SeverityWarning || f.Severity == report.SeverityAlert {
			hasWarningOrAlert = true
		}
	}

	if !hasNoticeGroup {
		t.Errorf("expected NOTICE group for normal build artifacts")
	}
	if !hasWarningOrAlert {
		t.Errorf("expected WARNING/ALERT finding for SUID artifact")
	}
}

// ---------------------------------------------------------------------------
// Rule File Abuse Unit Tests
// ---------------------------------------------------------------------------

func TestScanner_RuleFileAbuse_ELFRenamedYar(t *testing.T) {
	tmpDir := t.TempDir()
	evilRule := filepath.Join(tmpDir, "evil.yar")
	// ELF binary pretending to be .yar rule
	data := append([]byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}, []byte("rule EvilRule { condition: true }")...)
	if err := os.WriteFile(evilRule, data, 0600); err != nil {
		t.Fatal(err)
	}

	mockEngine := &mockYaraEngine{
		matches: []yara.RuleMatch{
			{RuleName: "Threat_Rule", Score: 50, Severity: report.SeverityWarning},
		},
	}

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{tmpDir}
	cfg.Scan.Threads = 1

	bus := events.NewEventBus()
	defer bus.Close()

	var findings []report.Finding
	sub := bus.Subscribe()
	defer sub.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range sub.Events() {
			if fr, ok := e.(events.FindingRaised); ok {
				findings = append(findings, fr.Finding)
			}
			if _, ok := e.(events.ScanFinished); ok {
				return
			}
		}
	}()

	s := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules(nil), scanner.WithYARAEngine(mockEngine))
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	<-done

	for _, f := range findings {
		if f.Path == evilRule {
			if f.Severity == report.SeverityInfo || f.Reason == "looks like a YARA rule file" {
				t.Fatalf("ELF binary named .yar must NOT be classified as benign rule file: %+v", f)
			}
		}
	}
}

func TestScanner_RuleFileAbuse_NulByteBinary(t *testing.T) {
	tmpDir := t.TempDir()
	nulRule := filepath.Join(tmpDir, "payload.yar")
	data := []byte("rule Payload {\x00\x01\x02 condition: true }")
	if err := os.WriteFile(nulRule, data, 0600); err != nil {
		t.Fatal(err)
	}

	mockEngine := &mockYaraEngine{
		matches: []yara.RuleMatch{
			{RuleName: "Binary_Payload", Score: 50, Severity: report.SeverityWarning},
		},
	}

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{tmpDir}
	cfg.Scan.Threads = 1

	bus := events.NewEventBus()
	defer bus.Close()

	var findings []report.Finding
	sub := bus.Subscribe()
	defer sub.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range sub.Events() {
			if fr, ok := e.(events.FindingRaised); ok {
				findings = append(findings, fr.Finding)
			}
			if _, ok := e.(events.ScanFinished); ok {
				return
			}
		}
	}()

	s := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules(nil), scanner.WithYARAEngine(mockEngine))
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	<-done

	for _, f := range findings {
		if f.Path == nulRule {
			if f.Severity == report.SeverityInfo || f.Reason == "looks like a YARA rule file" {
				t.Fatalf("Binary file with NUL byte must NOT be classified as benign rule file: %+v", f)
			}
		}
	}
}

func TestScanner_RuleFileAbuse_ShebangScript(t *testing.T) {
	tmpDir := t.TempDir()
	scriptRule := filepath.Join(tmpDir, "dropper.yar")
	data := []byte("#!/bin/bash\n# rule FakeRule { condition: true }\necho evil\n")
	if err := os.WriteFile(scriptRule, data, 0755); err != nil {
		t.Fatal(err)
	}

	mockEngine := &mockYaraEngine{
		matches: []yara.RuleMatch{
			{RuleName: "Script_Dropper", Score: 50, Severity: report.SeverityWarning},
		},
	}

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{tmpDir}
	cfg.Scan.Threads = 1

	bus := events.NewEventBus()
	defer bus.Close()

	var findings []report.Finding
	sub := bus.Subscribe()
	defer sub.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range sub.Events() {
			if fr, ok := e.(events.FindingRaised); ok {
				findings = append(findings, fr.Finding)
			}
			if _, ok := e.(events.ScanFinished); ok {
				return
			}
		}
	}()

	s := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules(nil), scanner.WithYARAEngine(mockEngine))
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	<-done

	for _, f := range findings {
		if f.Path == scriptRule {
			if f.Severity == report.SeverityInfo || f.Reason == "looks like a YARA rule file" {
				t.Fatalf("Shebang script named .yar must NOT be classified as benign rule file: %+v", f)
			}
		}
	}
}

func TestScanner_RuleFileAbuse_PrefixedMalware(t *testing.T) {
	tmpDir := t.TempDir()
	fakeRule := filepath.Join(tmpDir, "fake.yar")
	data := []byte("This is some arbitrary malware payload without any YARA rule declaration.")
	if err := os.WriteFile(fakeRule, data, 0600); err != nil {
		t.Fatal(err)
	}

	mockEngine := &mockYaraEngine{
		matches: []yara.RuleMatch{
			{RuleName: "Malware_Payload", Score: 50, Severity: report.SeverityWarning},
		},
	}

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{tmpDir}
	cfg.Scan.Threads = 1

	bus := events.NewEventBus()
	defer bus.Close()

	var findings []report.Finding
	sub := bus.Subscribe()
	defer sub.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range sub.Events() {
			if fr, ok := e.(events.FindingRaised); ok {
				findings = append(findings, fr.Finding)
			}
			if _, ok := e.(events.ScanFinished); ok {
				return
			}
		}
	}()

	s := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules(nil), scanner.WithYARAEngine(mockEngine))
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	<-done

	for _, f := range findings {
		if f.Path == fakeRule {
			if f.Severity == report.SeverityInfo || f.Reason == "looks like a YARA rule file" {
				t.Fatalf("Non-rule payload named .yar must NOT be classified as benign rule file: %+v", f)
			}
		}
	}
}

func TestScanner_RuleFileAbuse_WithIOCSignal(t *testing.T) {
	tmpDir := t.TempDir()
	ruleContent := []byte("rule MaliciousRule { condition: true }\n")
	ruleFile := filepath.Join(tmpDir, "threat.yar")
	if err := os.WriteFile(ruleFile, ruleContent, 0600); err != nil {
		t.Fatal(err)
	}

	h := sha256.Sum256(ruleContent)
	shaStr := hex.EncodeToString(h[:])

	iocDir := filepath.Join(tmpDir, "iocs")
	_ = os.MkdirAll(iocDir, 0700)
	iocFile := filepath.Join(iocDir, "hashes.txt")
	_ = os.WriteFile(iocFile, []byte(shaStr+" # Malware_Rule_IOC\n"), 0600)

	mockEngine := &mockYaraEngine{
		matches: []yara.RuleMatch{
			{RuleName: "MaliciousRule", Score: 50, Severity: report.SeverityWarning},
		},
	}

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{tmpDir}
	cfg.Scan.IOCDir = iocDir
	cfg.Scan.Threads = 1

	bus := events.NewEventBus()
	defer bus.Close()

	var findings []report.Finding
	sub := bus.Subscribe()
	defer sub.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range sub.Events() {
			if fr, ok := e.(events.FindingRaised); ok {
				findings = append(findings, fr.Finding)
			}
			if _, ok := e.(events.ScanFinished); ok {
				return
			}
		}
	}()

	s := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules(nil), scanner.WithYARAEngine(mockEngine))
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	<-done

	var hit *report.Finding
	for i := range findings {
		if findings[i].Path == ruleFile {
			hit = &findings[i]
			break
		}
	}

	if hit == nil {
		t.Fatalf("expected finding for IOC-matched rule file")
	}

	if hit.Severity != report.SeverityAlert {
		t.Errorf("expected SeverityAlert for IOC match on rule file, got: %s", hit.Severity)
	}
	if hit.Reason == "looks like a YARA rule file" {
		t.Errorf("IOC-matched rule file must NOT be downgraded to INFO 'looks like a YARA rule file'")
	}
}

// ---------------------------------------------------------------------------
// Integration Tests (skipped with -test.short)
// ---------------------------------------------------------------------------

func TestIntegration_DefaultModules_QuickScan(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "normal.txt")
	if err := os.WriteFile(testFile, []byte("clean content"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{tmpDir}
	cfg.Scan.Threads = 2

	bus := events.NewEventBus()
	defer bus.Close()

	sub := bus.Subscribe()
	defer sub.Close()

	s := scanner.NewScanner(cfg, bus, nil, nil) // uses real default modules

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	err := s.Run(ctx)
	if err != nil {
		t.Fatalf("integration scan failed: %v", err)
	}
}

func TestIntegration_DefaultModules_ModuleCount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cfg := config.NewDefaultConfig()
	bus := events.NewEventBus()
	defer bus.Close()

	s := scanner.NewScanner(cfg, bus, nil, nil)
	if s == nil {
		t.Fatal("expected scanner instance")
	}
}

func TestTopRules_RuleLevelSeverity(t *testing.T) {
	// Create composite finding with tunnel (WARNING) and unowned-unit (NOTICE)
	f := report.NewFinding("persistence", report.SeverityWarning, "/home/user/.config/systemd/user/tunnel.service", "tunnel detected", "Persistence_Autostart_Tunnel, Persistence_Systemd_Unowned_Unit")
	f.Metadata["rule_severities"] = map[string]string{
		"Persistence_Autostart_Tunnel":      "WARNING",
		"Persistence_Systemd_Unowned_Unit": "NOTICE",
	}

	cfg := config.NewDefaultConfig()
	bus := events.NewEventBus()
	defer bus.Close()
	sub := bus.Subscribe()
	defer sub.Close()

	// Let's create a fake module that reports f
	fakeMod := &fakeModule{
		name:     "persistence",
		findings: []report.Finding{f},
	}
	sWithMod := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules([]modules.Module{fakeMod}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = sWithMod.Run(ctx)

	var scanFin *events.ScanFinished
	for e := range sub.Events() {
		if sf, ok := e.(events.ScanFinished); ok {
			scanFin = &sf
			break
		}
	}

	if scanFin == nil {
		t.Fatalf("expected ScanFinished event")
	}

	ruleMap := make(map[string]report.Severity)
	for _, tr := range scanFin.TopRules {
		ruleMap[tr.RuleName] = tr.Severity
	}

	if sev, ok := ruleMap["Persistence_Autostart_Tunnel"]; !ok || sev != report.SeverityWarning {
		t.Errorf("expected Persistence_Autostart_Tunnel to be WARNING, got: %s (found: %v)", sev, ok)
	}

	if sev, ok := ruleMap["Persistence_Systemd_Unowned_Unit"]; !ok || sev != report.SeverityNotice {
		t.Errorf("expected Persistence_Systemd_Unowned_Unit to be NOTICE in Top Rules, got: %s (found: %v)", sev, ok)
	}
}

type fakeModule struct {
	name     string
	findings []report.Finding
}

func (m *fakeModule) Name() string        { return m.name }
func (m *fakeModule) Description() string { return "fake test module" }
func (m *fakeModule) Run(ctx context.Context, cfg *config.Config, rep report.Reporter) error {
	for _, f := range m.findings {
		rep.Report(f)
	}
	return nil
}

func TestCollectRootStartupNotices(t *testing.T) {
	// Non-root returns nil
	if notices := scanner.CollectRootStartupNotices(1000, "", "/usr/bin/aether", nil, nil); len(notices) != 0 {
		t.Errorf("expected non-root to have 0 notices, got: %v", notices)
	}

	// Root with untrusted binary
	mockStat := func(path string) (os.FileInfo, error) {
		if path == "/home/nick/aether" {
			return &mockStatInfo{uid: 1000, mode: 0755}, nil
		}
		return &mockStatInfo{uid: 0, mode: 0755}, nil
	}
	identityEval := func(path string) (string, error) { return path, nil }

	notices := scanner.CollectRootStartupNotices(0, "", "/home/nick/aether", mockStat, identityEval)
	if len(notices) == 0 {
		t.Fatalf("expected notices for user-owned binary under root")
	}
	foundTrustNotice := false
	for _, n := range notices {
		if strings.Contains(n, "running as root from a user-writable location") {
			foundTrustNotice = true
		}
	}
	if !foundTrustNotice {
		t.Errorf("expected trust notice, got: %v", notices)
	}
}

type mockStatInfo struct {
	uid  uint32
	mode os.FileMode
}

func (m *mockStatInfo) Name() string       { return "file" }
func (m *mockStatInfo) Size() int64        { return 100 }
func (m *mockStatInfo) Mode() os.FileMode  { return m.mode }
func (m *mockStatInfo) ModTime() time.Time { return time.Now() }
func (m *mockStatInfo) IsDir() bool        { return m.mode.IsDir() }
func (m *mockStatInfo) Sys() any {
	return &syscall.Stat_t{Uid: m.uid}
}

// Silence unused import warnings on platforms
var _ = syscall.EPERM
var _ = hex.EncodeToString
var _ = bytes.Equal
var _ = sha256.New

func TestScanner_NoopEngine_ZeroYaraFindingsAndCounts(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("hello world"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{tmpDir}
	cfg.Scan.Threads = 1

	bus := events.NewEventBus()
	defer bus.Close()

	sub := bus.Subscribe()
	defer sub.Close()

	var findings []report.Finding
	var finishEv events.ScanFinished

	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range sub.Events() {
			if fr, ok := e.(events.FindingRaised); ok {
				findings = append(findings, fr.Finding)
			}
			if sf, ok := e.(events.ScanFinished); ok {
				finishEv = sf
				return
			}
		}
	}()

	noopEngine := yara.NewNoopEngine()
	s := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules(nil), scanner.WithYARAEngine(noopEngine))
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	<-done

	for _, f := range findings {
		if f.Module == "yara" {
			t.Errorf("expected zero yara findings with NoopEngine, got: %+v", f)
		}
	}

	if finishEv.YARACoverage != nil && finishEv.YARACoverage.CompiledIn {
		t.Errorf("expected YARACoverage.CompiledIn == false with NoopEngine")
	}
	if finishEv.YARACoverage != nil && finishEv.YARACoverage.RulesLoaded != 0 {
		t.Errorf("expected YARACoverage.RulesLoaded == 0, got %d", finishEv.YARACoverage.RulesLoaded)
	}
	if finishEv.YARACoverage != nil && finishEv.YARACoverage.RuleFilesSeen != 0 {
		t.Errorf("expected YARACoverage.RuleFilesSeen == 0, got %d", finishEv.YARACoverage.RuleFilesSeen)
	}
}

func TestScanner_Oversize_SparseFilesBoundary(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. File larger than max-filesize (20MB when limit is 10MB) -> sparse file
	hugePath := filepath.Join(tmpDir, "oversize_20mb.bin")
	fHuge, err := os.Create(hugePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := fHuge.Truncate(20 * 1024 * 1024); err != nil {
		fHuge.Close()
		t.Fatal(err)
	}
	fHuge.Close()

	// 2. File between yara-max-filesize (2MB) and max-filesize (10MB) -> 5MB sparse file
	midPath := filepath.Join(tmpDir, "midsize_5mb.bin")
	fMid, err := os.Create(midPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := fMid.Truncate(5 * 1024 * 1024); err != nil {
		fMid.Close()
		t.Fatal(err)
	}
	fMid.Close()

	// 3. Small file (1KB)
	smallPath := filepath.Join(tmpDir, "small_1kb.bin")
	if err := os.WriteFile(smallPath, []byte("small file content"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{tmpDir}
	cfg.Scan.MaxFileSize = 10 * 1024 * 1024
	cfg.Scan.YaraMaxFileSize = 2 * 1024 * 1024
	cfg.Scan.Threads = 1

	mockEngine := &mockYaraEngine{
		matches: []yara.RuleMatch{
			{
				RuleName: "MockRule",
				Score:    50,
				Severity: report.SeverityNotice,
			},
		},
	}

	bus := events.NewEventBus()
	defer bus.Close()

	sub := bus.Subscribe()
	defer sub.Close()

	var finishEv events.ScanFinished
	var findings []report.Finding
	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range sub.Events() {
			if fr, ok := e.(events.FindingRaised); ok {
				findings = append(findings, fr.Finding)
			}
			if sf, ok := e.(events.ScanFinished); ok {
				finishEv = sf
				return
			}
		}
	}()

	s := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules(nil), scanner.WithYARAEngine(mockEngine))
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	<-done

	// Verify huge file (> max-filesize) is in OversizeFiles and counted in SkippedOversize
	if finishEv.Coverage.SkippedOversize != 1 {
		t.Errorf("expected SkippedOversize == 1, got %d", finishEv.Coverage.SkippedOversize)
	}
	if len(finishEv.Coverage.OversizeFiles) != 1 {
		t.Fatalf("expected 1 OversizeFiles entry, got %d: %+v", len(finishEv.Coverage.OversizeFiles), finishEv.Coverage.OversizeFiles)
	}
	if finishEv.Coverage.OversizeFiles[0].Path != hugePath {
		t.Errorf("expected OversizeFiles path %q, got %q", hugePath, finishEv.Coverage.OversizeFiles[0].Path)
	}
	if finishEv.Coverage.OversizeFiles[0].Size != 20*1024*1024 {
		t.Errorf("expected OversizeFiles size 20MB, got %d", finishEv.Coverage.OversizeFiles[0].Size)
	}

	// Mid file (5MB) was stream-hashed and inspected, but skipped by YARA
	if finishEv.Coverage.FilesScanned != 2 { // mid + small
		t.Errorf("expected FilesScanned == 2, got %d", finishEv.Coverage.FilesScanned)
	}
	if mockEngine.skippedOversize != 1 {
		t.Errorf("expected mockEngine.skippedOversize == 1 (for 5MB mid file), got %d", mockEngine.skippedOversize)
	}

	// Check YARA_Skipped_Oversize finding for mid file
	foundYaraOversize := false
	for _, f := range findings {
		if f.RuleName == "YARA_Skipped_Oversize" && f.Path == midPath {
			foundYaraOversize = true
			if f.Severity != report.SeverityInfo {
				t.Errorf("expected YARA_Skipped_Oversize to be SeverityInfo, got %s", f.Severity)
			}
		}
	}
	if !foundYaraOversize {
		t.Errorf("expected finding YARA_Skipped_Oversize for mid-sized file, findings: %+v", findings)
	}
}

func TestTopRules_EffectiveSeverityAndAckSplit(t *testing.T) {
	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{t.TempDir()}

	fA1 := report.NewFinding("persistence", report.SeverityInfo, "/etc/systemd/a1.service", "ack A1", "Persistence_AckAll")
	fA1.Metadata["acknowledged"] = true
	fA2 := report.NewFinding("persistence", report.SeverityInfo, "/etc/systemd/a2.service", "ack A2", "Persistence_AckAll")
	fA2.Metadata["acknowledged"] = true

	fB1 := report.NewFinding("persistence", report.SeverityNotice, "/etc/systemd/b1.service", "notice B1", "Persistence_Mixed")
	fB2 := report.NewFinding("persistence", report.SeverityWarning, "/etc/systemd/b2.service", "warn B2", "Persistence_Mixed")
	fB3 := report.NewFinding("persistence", report.SeverityInfo, "/etc/systemd/b3.service", "ack B3", "Persistence_Mixed")
	fB3.Metadata["acknowledged"] = true

	fC1 := report.NewFinding("persistence", report.SeverityNotice, "/etc/systemd/c1.service", "notice C1", "Persistence_NoticeOnly")

	fMod := &fakeModule{
		name:     "persistence",
		findings: []report.Finding{fA1, fA2, fB1, fB2, fB3, fC1},
	}

	bus := events.NewEventBus()
	defer bus.Close()
	sub := bus.Subscribe()
	defer sub.Close()

	s := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules([]modules.Module{fMod}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = s.Run(ctx)

	var scanFin *events.ScanFinished
	for e := range sub.Events() {
		if sf, ok := e.(events.ScanFinished); ok {
			scanFin = &sf
			break
		}
	}

	if scanFin == nil {
		t.Fatalf("expected ScanFinished event")
	}

	foundMap := make(map[string]report.RuleSummary)
	for _, tr := range scanFin.TopRules {
		key := fmt.Sprintf("%s|ack=%v", tr.RuleName, tr.Acknowledged)
		foundMap[key] = tr
	}

	// 1. Persistence_AckAll: only ack row with count 2, INFO
	if r, ok := foundMap["Persistence_AckAll|ack=true"]; !ok {
		t.Errorf("expected Persistence_AckAll (ack=true) in TopRules, got: %+v", foundMap)
	} else {
		if r.Count != 2 || r.Severity != report.SeverityInfo {
			t.Errorf("expected Persistence_AckAll ack=true count=2 sev=INFO, got count=%d sev=%s", r.Count, r.Severity)
		}
	}
	if _, ok := foundMap["Persistence_AckAll|ack=false"]; ok {
		t.Errorf("did not expect unacknowledged row for Persistence_AckAll")
	}

	// 2. Persistence_Mixed: 2 rows (unack with max sev WARNING count 2, and ack with INFO count 1)
	if r, ok := foundMap["Persistence_Mixed|ack=false"]; !ok {
		t.Errorf("expected Persistence_Mixed (ack=false) in TopRules, got: %+v", foundMap)
	} else {
		if r.Count != 2 || r.Severity != report.SeverityWarning {
			t.Errorf("expected Persistence_Mixed ack=false count=2 sev=WARNING (composite max), got count=%d sev=%s", r.Count, r.Severity)
		}
	}
	if r, ok := foundMap["Persistence_Mixed|ack=true"]; !ok {
		t.Errorf("expected Persistence_Mixed (ack=true) in TopRules, got: %+v", foundMap)
	} else {
		if r.Count != 1 || r.Severity != report.SeverityInfo {
			t.Errorf("expected Persistence_Mixed ack=true count=1 sev=INFO, got count=%d sev=%s", r.Count, r.Severity)
		}
	}

	// 3. Persistence_NoticeOnly: 1 unack row count 1 sev NOTICE
	if r, ok := foundMap["Persistence_NoticeOnly|ack=false"]; !ok {
		t.Errorf("expected Persistence_NoticeOnly (ack=false) in TopRules, got: %+v", foundMap)
	} else {
		if r.Count != 1 || r.Severity != report.SeverityNotice {
			t.Errorf("expected Persistence_NoticeOnly ack=false count=1 sev=NOTICE, got count=%d sev=%s", r.Count, r.Severity)
		}
	}
}

func TestScanner_JSONOutParsesWhenNoticeFires(t *testing.T) {
	tmpDir := t.TempDir()
	jsonOutPath := filepath.Join(tmpDir, "out.json")

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{tmpDir}
	cfg.Scan.Threads = 1

	bus := events.NewEventBus()
	defer bus.Close()

	rep, err := report.NewConcurrentReporter(jsonOutPath)
	if err != nil {
		t.Fatal(err)
	}
	defer rep.Close()

	notices := []string{
		"running as root from a user-writable location; copy the binary to a root-owned path for privileged scans",
		"3 acknowledgments in /home/user/.config/aether/acknowledged.yaml ignored because running as root (use `aether ack --system`)",
	}

	sub := bus.Subscribe()
	defer sub.Close()

	var startedEv *events.ScanStarted
	var finishedEv *events.ScanFinished
	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range sub.Events() {
			if st, ok := e.(events.ScanStarted); ok {
				startedEv = &st
			}
			if sf, ok := e.(events.ScanFinished); ok {
				finishedEv = &sf
				return
			}
		}
	}()

	s := scanner.NewScanner(cfg, bus, rep, nil, scanner.WithModules(nil), scanner.WithStartupNotices(notices))
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	<-done
	rep.Close()

	if startedEv == nil || len(startedEv.Notices) != 2 {
		t.Fatalf("expected 2 startup notices in ScanStarted, got: %v", startedEv)
	}
	if finishedEv == nil || len(finishedEv.StartupNotices) != 2 {
		t.Fatalf("expected 2 startup notices in ScanFinished, got: %v", finishedEv)
	}

	// Verify ScanFinished JSON serializes cleanly with startup notices
	sfJSON, err := json.Marshal(finishedEv)
	if err != nil {
		t.Fatalf("failed to marshal ScanFinished to JSON: %v", err)
	}
	var parsedSF map[string]interface{}
	if err := json.Unmarshal(sfJSON, &parsedSF); err != nil {
		t.Fatalf("ScanFinished JSON failed to unmarshal: %v", err)
	}
	nList, ok := parsedSF["startup_notices"].([]interface{})
	if !ok || len(nList) != 2 {
		t.Errorf("expected 2 startup_notices in ScanFinished JSON, got: %v", parsedSF["startup_notices"])
	}
}

func TestScanner_ScanStarted_BuildInfoLine(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{tmpDir}

	bus := events.NewEventBus()
	defer bus.Close()
	sub := bus.Subscribe()
	defer sub.Close()

	var startedEv *events.ScanStarted
	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range sub.Events() {
			if st, ok := e.(events.ScanStarted); ok {
				startedEv = &st
			}
			if _, ok := e.(events.ScanFinished); ok {
				return
			}
		}
	}()

	s := scanner.NewScanner(cfg, bus, nil, nil,
		scanner.WithModules(nil),
		scanner.WithBuildInfo("0.1.0-dev", "2026-10-01T10:30:47Z", "aether-yara-static"),
	)
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	<-done

	if startedEv == nil {
		t.Fatalf("expected ScanStarted event")
	}
	if startedEv.Version != "0.1.0-dev" {
		t.Errorf("expected Version '0.1.0-dev', got: %s", startedEv.Version)
	}
	if startedEv.BuildDate != "2026-10-01T10:30:47Z" {
		t.Errorf("expected BuildDate '2026-10-01T10:30:47Z', got: %s", startedEv.BuildDate)
	}
	if startedEv.BinaryName != "aether-yara-static" {
		t.Errorf("expected BinaryName 'aether-yara-static', got: %s", startedEv.BinaryName)
	}
}

func TestScanner_YaraTrustRefusalNotices(t *testing.T) {
	checks := []struct {
		failingReason string
		expectedNotice string
	}{
		{
			failingReason:  "executable not in a root-owned path",
			expectedNotice: "YARA not run: executable not in a root-owned path",
		},
		{
			failingReason:  "library path not trusted",
			expectedNotice: "YARA not run: library path not trusted",
		},
		{
			failingReason:  "RUNPATH not trusted",
			expectedNotice: "YARA not run: RUNPATH not trusted",
		},
		{
			failingReason:  "cannot verify linkage",
			expectedNotice: "YARA not run: cannot verify linkage",
		},
	}

	for _, tc := range checks {
		t.Run(tc.failingReason, func(t *testing.T) {
			tmpDir := t.TempDir()
			cfg := config.NewDefaultConfig()
			cfg.Scan.Paths = []string{tmpDir}

			bus := events.NewEventBus()
			defer bus.Close()
			sub := bus.Subscribe()
			defer sub.Close()

			var startedEv *events.ScanStarted
			var finishedEv *events.ScanFinished
			done := make(chan struct{})
			go func() {
				defer close(done)
				for e := range sub.Events() {
					if st, ok := e.(events.ScanStarted); ok {
						startedEv = &st
					}
					if sf, ok := e.(events.ScanFinished); ok {
						finishedEv = &sf
						return
					}
				}
			}()

			mockEng := &mockYaraEngine{
				notRunReason: tc.failingReason,
			}

			s := scanner.NewScanner(cfg, bus, nil, nil,
				scanner.WithModules(nil),
				scanner.WithYARAEngine(mockEng),
			)
			if err := s.Run(context.Background()); err != nil {
				t.Fatal(err)
			}

			<-done

			if startedEv == nil {
				t.Fatalf("expected ScanStarted event")
			}
			foundNotice := false
			for _, n := range startedEv.Notices {
				if n == tc.expectedNotice {
					foundNotice = true
					break
				}
			}
			if !foundNotice {
				t.Errorf("expected notice %q in ScanStarted.Notices, got: %v", tc.expectedNotice, startedEv.Notices)
			}

			if finishedEv == nil {
				t.Fatalf("expected ScanFinished event")
			}
			foundInFinished := false
			for _, mod := range finishedEv.ModulesNotRun {
				if mod == fmt.Sprintf("yara (%s)", tc.failingReason) {
					foundInFinished = true
					break
				}
			}
			if !foundInFinished {
				t.Errorf("expected 'yara (%s)' in ModulesNotRun, got: %v", tc.failingReason, finishedEv.ModulesNotRun)
			}
		})
	}
}

type mockFailingModule struct {
	name string
	err  error
}

func (m *mockFailingModule) Name() string        { return m.name }
func (m *mockFailingModule) Description() string { return "mock failing module" }
func (m *mockFailingModule) Run(ctx context.Context, cfg *config.Config, rep report.Reporter) error {
	return m.err
}

func TestScanner_FailingModuleSurfacesNoticeAndStatus(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{tmpDir}

	bus := events.NewEventBus()
	defer bus.Close()
	sub := bus.Subscribe()
	defer sub.Close()

	var outputBuf bytes.Buffer
	plainConsumer := plain.NewConsumer(&outputBuf, nil, false)

	consumeDone := make(chan struct{})
	go func() {
		defer close(consumeDone)
		_ = plainConsumer.Consume(context.Background(), sub)
	}()

	failingMod := &mockFailingModule{
		name: "test_failing_module",
		err:  errors.New("simulated database failure"),
	}

	s := scanner.NewScanner(cfg, bus, nil, nil,
		scanner.WithModules([]modules.Module{failingMod}),
	)

	err := s.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected scanner run error: %v", err)
	}

	<-consumeDone
	plainOutput := outputBuf.String()

	// 1. Verify Module finished line contains Status: FAILED
	if !strings.Contains(plainOutput, "Module finished: test_failing_module") || !strings.Contains(plainOutput, "Status: FAILED") {
		t.Errorf("expected plain output to contain 'Status: FAILED' for failing module, got:\n%s", plainOutput)
	}

	// 2. Verify explicit Notice line is surfaced for the error
	if !strings.Contains(plainOutput, "[AETHER] [NOTICE] Module test_failing_module failed: simulated database failure") {
		t.Errorf("expected plain output to contain '[AETHER] [NOTICE] Module test_failing_module failed: ...', got:\n%s", plainOutput)
	}

	// 3. Verify Modules Not Run lists the failed module
	if !strings.Contains(plainOutput, "Modules Not Run: test_failing_module (failed)") {
		t.Errorf("expected plain output to contain 'Modules Not Run: test_failing_module (failed)', got:\n%s", plainOutput)
	}

	// 4. Verify Final Verdict mentions the failed module
	if !strings.Contains(plainOutput, "modules not run: test_failing_module (failed)") {
		t.Errorf("expected Final Verdict to mention 'modules not run: test_failing_module (failed)', got:\n%s", plainOutput)
	}
}



