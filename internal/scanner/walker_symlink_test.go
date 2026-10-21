package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/scanner"
)

func TestScanner_SymlinkRoot_ScansTargetContents(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Create real target directory with a file and a subfolder with a file
	targetDir := filepath.Join(tmpDir, "real_target")
	if err := os.MkdirAll(filepath.Join(targetDir, "sub"), 0755); err != nil {
		t.Fatal(err)
	}

	payloadPath := filepath.Join(targetDir, "sub", "test_file.sh")
	if err := os.WriteFile(payloadPath, []byte("#!/bin/sh\necho safe\n"), 0755); err != nil {
		t.Fatal(err)
	}

	// 2. Create a symlink pointing to real_target (mimicking /bin -> /usr/bin)
	symlinkRoot := filepath.Join(tmpDir, "symlink_root")
	if err := os.Symlink(targetDir, symlinkRoot); err != nil {
		t.Fatal(err)
	}

	// 3. Configure scanner to target ONLY the symlink root
	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{symlinkRoot}
	cfg.Scan.Quick = false

	bus := events.NewEventBus()
	defer bus.Close()
	sc := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules(nil))

	targets := sc.ResolveTargets()
	if len(targets) != 1 {
		t.Fatalf("expected 1 resolved target, got %d: %v", len(targets), targets)
	}
	// Verify that targets resolved to real_target
	realTargetClean, _ := filepath.EvalSymlinks(targetDir)
	if targets[0] != realTargetClean {
		t.Fatalf("expected resolved target %q, got %q", realTargetClean, targets[0])
	}

	// 4. Run scanner and assert that files inside target were scanned
	sub := bus.Subscribe()
	defer sub.Close()

	err := sc.Run(context.Background())
	if err != nil {
		t.Fatalf("scanner run failed: %v", err)
	}

	var finishedEv *events.ScanFinished
	for ev := range sub.Events() {
		if sf, ok := ev.(events.ScanFinished); ok {
			finishedEv = &sf
			break
		}
	}

	if finishedEv == nil {
		t.Fatal("expected ScanFinished event but got none")
	}

	if finishedEv.FilesScanned < 1 {
		t.Fatalf("expected at least 1 file scanned through symlink root, got %d", finishedEv.FilesScanned)
	}
}
