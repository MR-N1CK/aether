package container_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/modules/container"
	"aether/internal/report"
)

type mockReporter struct {
	findings []report.Finding
}

func (m *mockReporter) Report(f report.Finding) {
	m.findings = append(m.findings, f)
}

func (m *mockReporter) Findings() []report.Finding {
	return m.findings
}

func (m *mockReporter) Summary() (int, int, int, int, int) {
	return len(m.findings), 0, 0, 0, 0
}

func (m *mockReporter) Close() error {
	return nil
}

func TestContainerModule_WorldWritableSocket(t *testing.T) {
	root := t.TempDir()
	sockDir := filepath.Join(root, "var/run")
	if err := os.MkdirAll(sockDir, 0755); err != nil {
		t.Fatal(err)
	}

	sockPath := filepath.Join(sockDir, "docker.sock")
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_ = os.Chmod(sockPath, 0666) // World-writable

	bus := events.NewEventBus()
	mod := container.NewModuleWithRoots(root, "", nil, bus, nil)
	rep := &mockReporter{}

	if err := mod.Run(context.Background(), config.NewDefaultConfig(), rep); err != nil {
		t.Fatalf("unexpected error running module: %v", err)
	}

	var foundWorldWritable bool
	for _, f := range rep.findings {
		if f.RuleName == "Container_Socket_World_Writable" {
			foundWorldWritable = true
			if f.Severity != report.SeverityAlert {
				t.Errorf("expected SeverityAlert, got: %s", f.Severity)
			}
			if f.Metadata["score"] != 85 {
				t.Errorf("expected score 85, got: %v", f.Metadata["score"])
			}
		}
	}

	if !foundWorldWritable {
		t.Errorf("expected Container_Socket_World_Writable finding, got: %+v", rep.findings)
	}
}

func TestContainerModule_MountedSocketInsideContainer(t *testing.T) {
	root := t.TempDir()

	// 1. Simulate container indicator (/.dockerenv)
	if err := os.WriteFile(filepath.Join(root, ".dockerenv"), []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	// 2. Create mounted socket with standard permissions (0660)
	sockDir := filepath.Join(root, "run")
	if err := os.MkdirAll(sockDir, 0755); err != nil {
		t.Fatal(err)
	}
	sockPath := filepath.Join(sockDir, "docker.sock")
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_ = os.Chmod(sockPath, 0660) // Restricted permission, but mounted inside container

	bus := events.NewEventBus()
	mod := container.NewModuleWithRoots(root, "", nil, bus, nil)
	rep := &mockReporter{}

	if err := mod.Run(context.Background(), config.NewDefaultConfig(), rep); err != nil {
		t.Fatalf("unexpected error running module: %v", err)
	}

	var foundEscape bool
	for _, f := range rep.findings {
		if f.RuleName == "Container_Escape_Mounted_Docker_Socket" {
			foundEscape = true
			if f.Severity != report.SeverityAlert {
				t.Errorf("expected SeverityAlert, got: %s", f.Severity)
			}
			if f.Metadata["score"] != 90 {
				t.Errorf("expected score 90, got: %v", f.Metadata["score"])
			}
		}
	}

	if !foundEscape {
		t.Errorf("expected Container_Escape_Mounted_Docker_Socket finding, got: %+v", rep.findings)
	}

	cov := mod.Coverage()
	if !cov.InsideContainer || cov.RuntimeDetected != "docker" {
		t.Errorf("expected InsideContainer=true (docker), got: %+v", cov)
	}
}

func TestContainerModule_CleanHost(t *testing.T) {
	root := t.TempDir()
	bus := events.NewEventBus()
	mod := container.NewModuleWithRoots(root, "", nil, bus, nil)
	rep := &mockReporter{}

	if err := mod.Run(context.Background(), config.NewDefaultConfig(), rep); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rep.findings) != 0 {
		t.Errorf("expected 0 findings for clean host, got: %+v", rep.findings)
	}
}
