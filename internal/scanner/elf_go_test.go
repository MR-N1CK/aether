package scanner

import (
	"bytes"
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"aether/internal/report"
)

// buildGoFixture compiles a small stdlib-only Go program in a temp dir.
// Compiling fresh fixtures (never executing them) keeps the test
// toolchain-independent and offline; execution of targets remains forbidden.
func buildGoFixture(t *testing.T, ldflags string) []byte {
	t.Helper()

	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not available in test environment")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	payload := `package main

import (
	"net"
	"os/exec"
)

// Package-level initializer keeps os/exec linked even under linker DCE.
var probe = exec.Command("true")

func main() {
	if c, err := net.Dial("tcp", "127.0.0.1:1"); err == nil {
		c.Close()
	}
	_ = probe
}
`
	if err := os.WriteFile(src, []byte(payload), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	bin := filepath.Join(dir, "fixture")
	cmd := exec.Command(goTool, "build", "-ldflags="+ldflags, "-o", bin, src)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("go build failed in test environment: %v: %s", err, out)
	}

	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("read built fixture: %v", err)
	}
	return data
}

func TestRecoverGoStaticProfile_Unstripped(t *testing.T) {
	data := buildGoFixture(t, "")
	ef, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse ELF: %v", err)
	}
	defer ef.Close()

	prof := RecoverGoStaticProfile(data, ef)
	if !prof.IsGo {
		t.Fatal("expected buildinfo to identify the fixture as a Go binary")
	}
	if !prof.Has("go_net_client") {
		t.Errorf("expected go_net_client capability, got: %v", prof.Caps)
	}
	if !prof.Has("go_process_exec") {
		t.Errorf("expected go_process_exec capability, got: %v", prof.Caps)
	}
}

func TestRecoverGoStaticProfile_StrippedEvadesSymtab(t *testing.T) {
	// -w -s strips DWARF and the symbol table — the implant build. pclntab
	// survives because the Go runtime requires it.
	data := buildGoFixture(t, "-s -w")
	ef, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse ELF: %v", err)
	}
	defer ef.Close()

	if ef.Section(".symtab") != nil {
		t.Fatalf("expected stripped fixture without .symtab")
	}

	prof := RecoverGoStaticProfile(data, ef)
	if !prof.IsGo {
		t.Fatal("expected buildinfo to identify the stripped fixture as Go")
	}
	if !prof.Has("go_net_client") || !prof.Has("go_process_exec") {
		t.Errorf("expected net+exec capabilities from pclntab, got: %v", prof.Caps)
	}
}

func TestAnalyzeELF_GoProfile_EscalationSemantics(t *testing.T) {
	data := buildGoFixture(t, "")

	// Home-directory tool: network+exec but no hostile context -> NOTICE
	// profile, no MALICIOUS verdict.
	matches := AnalyzeELFExecutable("/home/dev/.local/bin/tool", data, 0o755, nil, nil)
	var profile *HeuristicMatch
	for i := range matches {
		if matches[i].Name == "ELF_Static_Go_Capability_Profile" {
			profile = matches[i]
		}
	}
	if profile == nil {
		t.Fatalf("expected ELF_Static_Go_Capability_Profile for unowned Go binary, got %v", matches)
	}
	if profile.Severity != report.SeverityNotice {
		t.Errorf("expected NOTICE for home-dir tool, got %v", profile.Severity)
	}
	if len(profile.Corroboration) != 0 {
		t.Errorf("home-dir tool must not carry escalation corroboration, got %v", profile.Corroboration)
	}

	// Same binary staged in a volatile path: WARNING + corroboration signals
	// (network + exec + volatile path) that adjudicate to MALICIOUS.
	matches = AnalyzeELFExecutable("/tmp/.cache/tool", data, 0o755, nil, nil)
	profile = nil
	for i := range matches {
		if matches[i].Name == "ELF_Static_Go_Capability_Profile" {
			profile = matches[i]
		}
	}
	if profile == nil {
		t.Fatalf("expected profile match in volatile path, got %v", matches)
	}
	if profile.Severity != report.SeverityWarning {
		t.Errorf("expected WARNING for volatile-path staging, got %v", profile.Severity)
	}
	if len(profile.Corroboration) < 3 {
		t.Errorf("expected net+exec+volatile corroboration signals, got %v", profile.Corroboration)
	}

	f := report.NewFinding("filesystem", profile.Severity, "/tmp/.cache/tool", profile.Reason, profile.Name)
	verdict := report.DetermineVerdict(&f, nil, true, false, false, profile.Corroboration)
	if verdict != report.VerdictMalicious {
		t.Errorf("expected MALICIOUS for net+exec Go implant staged in volatile path, got %v", verdict)
	}
}
