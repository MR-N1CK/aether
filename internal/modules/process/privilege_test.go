package process_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"aether/internal/config"
	"aether/internal/modules/process"
	"aether/internal/report"
)

type privMemoryReporter struct {
	findings []report.Finding
}

func (r *privMemoryReporter) Report(f report.Finding) {
	r.findings = append(r.findings, f)
}
func (r *privMemoryReporter) Findings() []report.Finding          { return r.findings }
func (r *privMemoryReporter) Summary() (int, int, int, int, int) { return 0, 0, 0, 0, 0 }
func (r *privMemoryReporter) Close() error                         { return nil }

func TestProcessNonRootPermissionDenied(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	_ = os.MkdirAll(proc, 0755)

	// PID 1001: restricted process (mode 0000 on /proc/<pid>)
	pid1001 := filepath.Join(proc, "1001")
	_ = os.MkdirAll(pid1001, 0000)
	defer os.Chmod(pid1001, 0755) // cleanup permission

	cfg := config.NewDefaultConfig()
	rep := &privMemoryReporter{}
	mod := process.NewModuleWithRoots(root, proc, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error running process module: %v", err)
	}

	cov := mod.Coverage()
	if cov.SkippedPermission < 1 {
		t.Errorf("expected SkippedPermission >= 1, got %d", cov.SkippedPermission)
	}

	// Must NOT emit speculative ALERT
	for _, f := range rep.findings {
		if f.Severity == report.SeverityAlert {
			t.Errorf("unreadable process must never trigger speculative ALERT: %s", f.RuleName)
		}
	}
}

func TestProcessUnreadableMapsRecordsCoverageGap(t *testing.T) {
	info := &process.ProcessInfo{
		PID:  2001,
		Comm: "restricted_app",
		Maps: []process.MapEntry{
			{StartAddr: 0x1000, EndAddr: 0x2000, Perms: "r-xp", Pathname: "memfd:payload (deleted)"},
		},
	}

	cfg := config.NewDefaultConfig()
	sig := process.CheckFilelessExecution(info, cfg)

	if sig != nil {
		t.Errorf("unreadable memfd mapping must not emit finding, got %+v", sig)
	}

	if len(info.CoverageGaps) == 0 {
		t.Errorf("expected coverage gap recorded for unreadable mapping")
	}
}
