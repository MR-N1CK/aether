package kernel

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"aether/internal/report"
)

func TestCheckEBPFProbes_Kprobes(t *testing.T) {
	tmpDir := t.TempDir()
	traceDir := filepath.Join(tmpDir, "sys/kernel/debug/tracing")
	if err := os.MkdirAll(traceDir, 0755); err != nil {
		t.Fatalf("failed creating test tracefs dir: %v", err)
	}

	content := `
# Tracer: nop
# format: p[:[GRP/]NAME] [MOD:]SYM[+offs]|MEMADDR [FETCHARGS]
p:kprobes/benign_probe ext4_file_write_iter
r:kprobes/ret_commit commit_creds
p:kprobes/hook_exec __x64_sys_execve
`
	if err := os.WriteFile(filepath.Join(traceDir, "kprobe_events"), []byte(content), 0644); err != nil {
		t.Fatalf("failed writing test kprobe_events: %v", err)
	}

	findings := CheckEBPFProbes(context.Background(), tmpDir, "", nil, nil)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings for sensitive kprobes, got %d", len(findings))
	}

	for _, f := range findings {
		if f.RuleName != "Kernel_eBPF_Persistent_Probe" {
			t.Errorf("expected rule Kernel_eBPF_Persistent_Probe, got %s", f.RuleName)
		}
		if f.Severity != report.SeverityWarning {
			t.Errorf("expected WARNING severity, got %v", f.Severity)
		}
	}
}

func TestCheckEBPFProbes_PinnedBPF(t *testing.T) {
	tmpDir := t.TempDir()
	bpfDir := filepath.Join(tmpDir, "sys/fs/bpf")
	if err := os.MkdirAll(bpfDir, 0755); err != nil {
		t.Fatalf("failed creating test bpffs dir: %v", err)
	}

	// 1. Standard systemd directory (benign, should be skipped)
	sysdDir := filepath.Join(bpfDir, "systemd")
	_ = os.MkdirAll(sysdDir, 0755)
	_ = os.WriteFile(filepath.Join(sysdDir, "ip_accounting"), []byte("data"), 0644)

	// 2. Suspicious pinned files
	_ = os.WriteFile(filepath.Join(bpfDir, ".hidden_bpf_map"), []byte("data"), 0644)
	_ = os.WriteFile(filepath.Join(bpfDir, "bpfdoor_filter"), []byte("data"), 0644)

	findings := CheckEBPFProbes(context.Background(), tmpDir, "", nil, nil)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings for suspicious pinned bpf objects, got %d", len(findings))
	}
}

func TestCheckEBPFProbes_Clean(t *testing.T) {
	tmpDir := t.TempDir()
	bpfDir := filepath.Join(tmpDir, "sys/fs/bpf")
	if err := os.MkdirAll(filepath.Join(bpfDir, "xdp"), 0755); err != nil {
		t.Fatalf("failed creating test dir: %v", err)
	}
	_ = os.WriteFile(filepath.Join(bpfDir, "xdp", "standard_prog"), []byte("data"), 0644)

	findings := CheckEBPFProbes(context.Background(), tmpDir, "", nil, nil)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean bpffs, got %d", len(findings))
	}
}
