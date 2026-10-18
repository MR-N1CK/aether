package persistence

import (
	"os"
	"path/filepath"
	"testing"

	"aether/internal/report"
)

// buildUnitRefFixture lays out a minimal systemd tree under a temp rootFS:
//
//	etc/systemd/system/evil.service                 (admin unit, ExecStart=/opt/rms/teamtalk)
//	etc/systemd/system/multi-user.target.wants/evil.service -> ../evil.service
//	usr/lib/systemd/system/othersvc.service         (packaged unit, NOT enabled)
//	etc/systemd/system/monitor.service              (admin unit via absolute link target)
//	usr/lib/systemd/system/monitor.service          (link destination)
//	etc/systemd/system/graphical.target.wants/monitor.service -> /usr/lib/systemd/system/monitor.service
func buildUnitRefFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	mk := func(rel, content string) string {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	mk("etc/systemd/system/evil.service", `[Unit]
Description=benign looking relay
[Service]
Type=simple
ExecStart=/opt/rms/teamtalk --quiet
ExecStartPre=/bin/sh -c 'echo start'
`)
	mk("usr/lib/systemd/system/othersvc.service", `[Unit]
Description=packaged but disabled
[Service]
ExecStart=/usr/bin/othersvc
`)
	mk("usr/lib/systemd/system/monitor.service", `[Unit]
Description=link destination
[Service]
ExecStart=/usr/local/bin/monitor
`)

	// Relative enablement symlink into ../evil.service.
	wantsDir := filepath.Join(root, "etc/systemd/system/multi-user.target.wants")
	if err := os.MkdirAll(wantsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../evil.service", filepath.Join(wantsDir, "evil.service")); err != nil {
		t.Fatal(err)
	}

	// Absolute enablement symlink.
	wantsDir2 := filepath.Join(root, "etc/systemd/system/graphical.target.wants")
	if err := os.MkdirAll(wantsDir2, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/lib/systemd/system/monitor.service", filepath.Join(wantsDir2, "monitor.service")); err != nil {
		t.Fatal(err)
	}

	return root
}

func TestCollectEnabledUnitRefs(t *testing.T) {
	root := buildUnitRefFixture(t)
	refs := CollectEnabledUnitRefs(root, 0)

	if got := refs["/opt/rms/teamtalk"]; len(got) != 1 || got[0] != "evil.service" {
		t.Errorf("expected evil.service for /opt/rms/teamtalk, got %v", got)
	}
	if got := refs["/usr/local/bin/monitor"]; len(got) != 1 || got[0] != "monitor.service" {
		t.Errorf("expected monitor.service via absolute wants-link, got %v", got)
	}
	// Packaged unit without enablement symlink must NOT appear.
	if got, ok := refs["/usr/bin/othersvc"]; ok {
		t.Errorf("disabled packaged unit must not be correlated, got %v", got)
	}
	// Shell wrapper binaries referenced by an enabled unit are indexed too.
	if got, ok := refs["/bin/sh"]; !ok || len(got) == 0 {
		t.Errorf("expected /bin/sh reference from evil.service ExecStartPre, got %v", got)
	}
}

func TestCollectEnabledUnitRefs_GeneratorUnitsAlwaysOn(t *testing.T) {
	root := t.TempDir()
	genDir := filepath.Join(root, "run/systemd/generator/mnt-media.mount.wants")
	if err := os.MkdirAll(genDir, 0o755); err != nil {
		t.Fatal(err)
	}
	unit := `[Unit]
Description=generator output
[Service]
ExecStart=/opt/vendor/agent
`
	if err := os.WriteFile(filepath.Join(genDir, "agent.service"), []byte(unit), 0o644); err != nil {
		t.Fatal(err)
	}

	refs := CollectEnabledUnitRefs(root, 0)
	if got := refs["/opt/vendor/agent"]; len(got) != 1 || got[0] != "agent.service" {
		t.Errorf("generator-produced unit must be treated as enabled, got %v", got)
	}
}

func TestCollectEnabledUnitRefs_EmptyRoot(t *testing.T) {
	root := t.TempDir()
	refs := CollectEnabledUnitRefs(root, 0)
	if len(refs) != 0 {
		t.Errorf("expected no refs for empty root, got %v", refs)
	}
	// Nonexistent root must be a silent no-op as well.
	refs = CollectEnabledUnitRefs(filepath.Join(root, "missing"), 0)
	if len(refs) != 0 {
		t.Errorf("expected no refs for missing root, got %v", refs)
	}
}

func TestCollectEnabledUnitRefs_Cap(t *testing.T) {
	root := t.TempDir()
	unitDir := filepath.Join(root, "etc/systemd/system")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// One admin unit referencing many distinct absolute targets.
	var content string
	for i := 0; i < 24; i++ {
		content += "ExecStartPost=/opt/cap/bin" + string(rune('a'+i)) + "\n"
	}
	if err := os.WriteFile(filepath.Join(unitDir, "capped.service"), []byte("[Service]\n"+content), 0o644); err != nil {
		t.Fatal(err)
	}

	refs := CollectEnabledUnitRefs(root, 5)
	if len(refs) != 5 {
		t.Errorf("expected ref cap of 5, got %d", len(refs))
	}
}

func TestAnnotateEnabledUnitRefs(t *testing.T) {
	root := buildUnitRefFixture(t)

	findings := []report.Finding{
		{Path: "/opt/rms/teamtalk", RuleName: "Suspicious_Relay", Severity: report.SeverityWarning},
		{Path: "/usr/bin/untouched", RuleName: "Other"},
		{Path: "/usr/local/bin/monitor -> /usr/local/bin/monitor", RuleName: "ProcPath"},
	}
	count := AnnotateEnabledUnitRefs(root, findings)
	if count != 2 {
		t.Fatalf("expected 2 annotated findings, got %d", count)
	}

	first := findings[0].Metadata
	if first == nil || first["enabled_units"] != "evil.service" {
		t.Errorf("expected enabled_units=evil.service, got %v", first)
	}
	if first != nil && first["enabled_unit"] != "evil.service" {
		t.Errorf("expected enabled_unit=evil.service, got %v", first)
	}
	if findings[1].Metadata != nil {
		t.Errorf("unmatched finding must stay untouched, got %v", findings[1].Metadata)
	}
	third := findings[2].Metadata
	if third == nil || third["enabled_unit"] != "monitor.service" {
		t.Errorf("process-style path (with comm suffix) must normalize for match, got %v", third)
	}

	// Idempotent: a second pass must not double-annotate.
	if n := AnnotateEnabledUnitRefs(root, findings); n != 0 {
		t.Errorf("second pass must be a no-op, annotated %d", n)
	}

	// Empty findings slice: cheap no-op that must not hit the crawl.
	if n := AnnotateEnabledUnitRefs(root, nil); n != 0 {
		t.Errorf("nil findings must return 0, got %d", n)
	}
}
