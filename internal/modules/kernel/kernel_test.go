package kernel_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aether/internal/config"
	"aether/internal/modules/kernel"
	"aether/internal/report"
)

type memoryReporter struct {
	findings []report.Finding
}

func (r *memoryReporter) Report(f report.Finding) {
	r.findings = append(r.findings, f)
}
func (r *memoryReporter) Findings() []report.Finding      { return r.findings }
func (r *memoryReporter) Summary() (int, int, int, int, int) { return 0, 0, 0, 0, 0 }
func (r *memoryReporter) Close() error                     { return nil }

func TestKernel_TaintTable_AllBits(t *testing.T) {
	// Table-driven test for every bit in Documentation/admin-guide/tainted-kernels.rst
	// Expected 18 documented bits (0..17)
	if len(kernel.TaintTable) != 18 {
		t.Fatalf("expected 18 taint table entries, got %d", len(kernel.TaintTable))
	}

	for i, entry := range kernel.TaintTable {
		if entry.Bit != uint(i) {
			t.Errorf("entry %d: expected bit %d, got %d", i, i, entry.Bit)
		}
		expectedVal := uint64(1) << uint(i)
		if entry.Value != expectedVal {
			t.Errorf("entry %d: expected value %d, got %d", i, expectedVal, entry.Value)
		}

		active, chars := kernel.DecodeTaint(entry.Value)
		if len(active) != 1 || active[0].FlagChar != entry.FlagChar {
			t.Errorf("entry %d: decode failed for flag %c (got chars %s)", i, entry.FlagChar, chars)
		}
	}
}

func TestKernel_Taint12289_InfoOnly(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	procSys := filepath.Join(proc, "sys/kernel")
	_ = os.MkdirAll(procSys, 0755)

	// 12289 = 1 (P) + 4096 (O) + 8192 (E)
	_ = os.WriteFile(filepath.Join(procSys, "tainted"), []byte("12289\n"), 0644)

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := kernel.NewModuleWithRoots(root, proc, "", nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error running kernel module: %v", err)
	}

	for _, f := range rep.findings {
		if f.Severity == report.SeverityWarning || f.Severity == report.SeverityAlert || f.Severity == report.SeverityNotice {
			t.Errorf("taint 12289 (P+O+E) must only produce INFO findings, got %s: %s (%s)", f.Severity, f.RuleName, f.Reason)
		}
	}

	cov := mod.Coverage()
	if cov.TaintValue != 12289 {
		t.Errorf("expected TaintValue == 12289, got %d", cov.TaintValue)
	}
	if cov.TaintSeverity != "INFO" {
		t.Errorf("expected TaintSeverity == INFO, got %s", cov.TaintSeverity)
	}
}

func TestKernel_Taint_ForcedModule_Notice(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	procSys := filepath.Join(proc, "sys/kernel")
	_ = os.MkdirAll(procSys, 0755)

	// Taint 2 (bit 1, 'F' - forced module load)
	_ = os.WriteFile(filepath.Join(procSys, "tainted"), []byte("2\n"), 0644)

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := kernel.NewModuleWithRoots(root, proc, "", nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundNotice bool
	for _, f := range rep.findings {
		if f.RuleName == "Kernel_Taint_Forced_Module" && f.Severity == report.SeverityNotice {
			foundNotice = true
		}
	}
	if !foundNotice {
		t.Errorf("expected NOTICE finding Kernel_Taint_Forced_Module for taint value 2 (F)")
	}
}

func TestKernel_HiddenLKM_TwoPassVerification(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	sys := filepath.Join(root, "sys/module")
	_ = os.MkdirAll(proc, 0755)
	_ = os.MkdirAll(sys, 0755)

	// 1. /proc/modules contains "ext4" and "overlay"
	procModulesContent := `ext4 983040 1 - Live 0x0000000000000000
overlay 151552 0 - Live 0x0000000000000000
`
	_ = os.WriteFile(filepath.Join(proc, "modules"), []byte(procModulesContent), 0644)

	// 2. /sys/module contains:
	// - ext4: initstate="live"
	// - overlay: initstate="live"
	// - 8250: built-in (no initstate file)
	// - transient_coming: initstate="coming" (must be ignored)
	// - diamorphine: initstate="live" (hidden rootkit: present in sysfs, missing from /proc/modules!)
	_ = os.MkdirAll(filepath.Join(sys, "ext4"), 0755)
	_ = os.WriteFile(filepath.Join(sys, "ext4/initstate"), []byte("live\n"), 0644)

	_ = os.MkdirAll(filepath.Join(sys, "overlay"), 0755)
	_ = os.WriteFile(filepath.Join(sys, "overlay/initstate"), []byte("live\n"), 0644)

	_ = os.MkdirAll(filepath.Join(sys, "8250"), 0755)

	_ = os.MkdirAll(filepath.Join(sys, "transient_coming"), 0755)
	_ = os.WriteFile(filepath.Join(sys, "transient_coming/initstate"), []byte("coming\n"), 0644)

	_ = os.MkdirAll(filepath.Join(sys, "diamorphine"), 0755)
	_ = os.WriteFile(filepath.Join(sys, "diamorphine/initstate"), []byte("live\n"), 0644)

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := kernel.NewModuleWithRoots(root, proc, sys, nil, nil, nil)
	mod.SetTestDelay(5 * time.Millisecond) // Fast delay for test

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error running kernel module: %v", err)
	}

	var foundHiddenRootkit, foundComingModule bool
	for _, f := range rep.findings {
		if f.RuleName == "Kernel_Hidden_LKM_Module" && strings.Contains(f.Reason, "diamorphine") {
			foundHiddenRootkit = true
			if f.Severity != report.SeverityWarning {
				t.Errorf("expected WARNING for hidden module, got %s", f.Severity)
			}
		}
		if strings.Contains(f.Reason, "transient_coming") {
			foundComingModule = true
		}
	}

	if !foundHiddenRootkit {
		t.Errorf("expected Kernel_Hidden_LKM_Module finding for diamorphine")
	}
	if foundComingModule {
		t.Errorf("module with initstate=coming must be ignored")
	}
}

func TestKernel_Modprobe_InstallHooks(t *testing.T) {
	root := t.TempDir()
	etcModprobe := filepath.Join(root, "etc/modprobe.d")
	_ = os.MkdirAll(etcModprobe, 0755)

	// Clean modprobe config: "install sound-slot-0 /bin/true"
	cleanContent := `# Benign modprobe disable
install sound-slot-0 /bin/true
install usb-storage /bin/false
`
	_ = os.WriteFile(filepath.Join(etcModprobe, "clean.conf"), []byte(cleanContent), 0644)

	// Malicious modprobe config: "install dccp /tmp/evil.sh"
	evilContent := `# Malicious install hook
install dccp /tmp/evil.sh
`
	_ = os.WriteFile(filepath.Join(etcModprobe, "evil.conf"), []byte(evilContent), 0644)

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := kernel.NewModuleWithRoots(root, "", "", nil, nil, nil)
	mod.SetTestDelay(5 * time.Millisecond)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundEvilHook, foundCleanHook bool
	for _, f := range rep.findings {
		if f.RuleName == "Kernel_Modprobe_Install_Command" {
			if strings.Contains(f.Reason, "dccp") {
				foundEvilHook = true
				if f.Severity != report.SeverityWarning {
					t.Errorf("expected WARNING for /tmp install hook, got %s", f.Severity)
				}
			}
			if strings.Contains(f.Reason, "sound-slot-0") || strings.Contains(f.Reason, "usb-storage") {
				foundCleanHook = true
			}
		}
	}

	if !foundEvilHook {
		t.Errorf("expected Kernel_Modprobe_Install_Command finding for dccp")
	}
	if foundCleanHook {
		t.Errorf("install ... /bin/true must be clean and not flagged")
	}
}
