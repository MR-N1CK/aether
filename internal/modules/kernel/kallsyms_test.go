package kernel

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildKernelFixture materializes a virtual /proc + /sys tree:
//   - proc/kallsyms with module owners
//   - proc/modules with visible modules
//   - sys/module/<name>/initstate=live for live modules
func buildKernelFixture(t *testing.T, kallsyms, procModules string, liveModules []string) string {
	t.Helper()
	root := t.TempDir()
	procDir := filepath.Join(root, "proc")
	sysDir := filepath.Join(root, "sys")
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "kallsyms"), []byte(kallsyms), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "modules"), []byte(procModules), 0644); err != nil {
		t.Fatal(err)
	}
	// sysRoot convention (matching the live module): the /sys/module path itself.
	moduleDir := filepath.Join(sysDir, "module")
	for _, name := range liveModules {
		dir := filepath.Join(moduleDir, name)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "initstate"), []byte("live"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestKallsymsReadAll(t *testing.T) {
	kallsyms := `ffffffffc0201000 T hid_generic_probe [hid_generic]
ffffffffc0202000 t hid_generic_remove [hid_generic]
ffffffff81000000 T startup_64
ffffffffc0300000 T evil_hidden_hook [evil_rootkit]
`
	got := kallsymsReadAll([]byte(kallsyms))
	if !got["hid_generic"] || !got["evil_rootkit"] {
		t.Fatalf("expected hid_generic and evil_rootkit owners, got %v", got)
	}
	if len(got) != 2 {
		t.Errorf("builtin/unbracketed symbols must be skipped, got %v", got)
	}
}

func TestCheckKallsymsHiddenModules_DetectsDKOM(t *testing.T) {
	// evil_rootkit owns kallsyms symbols but is hidden from BOTH module lists
	// (DKOM unlink). hid_generic is fully visible. real_hidden is hidden from
	// /proc/modules but still live in sysfs — the two-pass check's territory,
	// NOT the kallsyms check's (it stays visible in sysfs).
	root := buildKernelFixture(t,
		`ffffffffc0300000 T evil_hook [evil_rootkit]
ffffffffc0201000 T hid_probe [hid_generic]
ffffffffc0100000 T ghost_init [ghost_lkm]
`,
		"hid_generic 16384 0 - Live 0x0\n",
		[]string{"hid_generic", "ghost_lkm"})

	cov := KernelCoverage{}
	findings := CheckKallsymsHiddenModules(
		filepath.Join(root, "proc"), filepath.Join(root, "sys", "module"), &cov, slog.Default())

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 DKOM finding for evil_rootkit, got %d: %+v", len(findings), findings)
	}
	if findings[0].RuleName != "Kernel_Module_Hidden_Kallsyms" {
		t.Errorf("unexpected rule: %s", findings[0].RuleName)
	}
	if findings[0].Severity != "ALERT" {
		t.Errorf("expected ALERT severity, got %s", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Reason, "evil_rootkit") {
		t.Errorf("reason must name the hidden module: %s", findings[0].Reason)
	}
}

func TestCheckKallsymsHiddenModules_ConsistentKernelClean(t *testing.T) {
	root := buildKernelFixture(t,
		`ffffffffc0201000 T hid_probe [hid_generic]
ffffffffc0300000 T btrfs_ioctl [btrfs]
`,
		"hid_generic 16384 0 - Live 0x0\nbtrfs 1566720 0 - Live 0x0\n",
		[]string{"hid_generic", "btrfs"})

	cov := KernelCoverage{}
	findings := CheckKallsymsHiddenModules(
		filepath.Join(root, "proc"), filepath.Join(root, "sys", "module"), &cov, slog.Default())
	if len(findings) != 0 {
		t.Fatalf("consistent kernel must be clean, got %+v", findings)
	}
}

func TestCheckKallsymsHiddenModules_EmptyTableDegrades(t *testing.T) {
	// Unprivileged reader / kptr_restrict: kallsyms exists but is empty.
	root := buildKernelFixture(t, "", "", nil)

	cov := KernelCoverage{}
	findings := CheckKallsymsHiddenModules(
		filepath.Join(root, "proc"), filepath.Join(root, "sys", "module"), &cov, slog.Default())
	if len(findings) != 0 {
		t.Fatalf("empty kallsyms table must degrade to a coverage note, got %+v", findings)
	}
	if cov.GapsNote == "" {
		t.Error("degraded check must record a coverage gap note")
	}
}
