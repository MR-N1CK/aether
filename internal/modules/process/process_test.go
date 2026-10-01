package process_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"aether/internal/config"
	"aether/internal/modules/process"
	"aether/internal/report"
)

func TestCheckDeletedExe(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// 1. Package upgrade under /usr -> NOTICE
	infoPkg := &process.ProcessInfo{
		PID: 101,
		Exe: "/usr/bin/bash (deleted)",
	}
	sigPkg := process.CheckDeletedExe(infoPkg, cfg)
	if sigPkg == nil {
		t.Fatalf("expected signal for deleted package binary")
	}
	if sigPkg.Severity != report.SeverityNotice {
		t.Errorf("expected NOTICE severity for /usr deleted binary, got %s", sigPkg.Severity)
	}
	if sigPkg.Score != 25 {
		t.Errorf("expected score 25, got %d", sigPkg.Score)
	}

	// 2. Deleted under /tmp -> ALERT (85)
	infoTemp := &process.ProcessInfo{
		PID: 102,
		Exe: "/tmp/evil_miner (deleted)",
	}
	sigTemp := process.CheckDeletedExe(infoTemp, cfg)
	if sigTemp == nil {
		t.Fatalf("expected signal for deleted temp binary")
	}
	if sigTemp.Severity != report.SeverityAlert {
		t.Errorf("expected ALERT severity for /tmp deleted binary, got %s", sigTemp.Severity)
	}
	if sigTemp.Score != 85 {
		t.Errorf("expected score 85, got %d", sigTemp.Score)
	}

	// 3. Regular non-deleted binary -> nil
	infoRegular := &process.ProcessInfo{
		PID: 103,
		Exe: "/usr/bin/bash",
	}
	if sig := process.CheckDeletedExe(infoRegular, cfg); sig != nil {
		t.Errorf("expected nil for non-deleted binary, got %+v", sig)
	}
}

func TestCheckFilelessExecution(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// 1. Plain JIT mapping: anonymous mapping (empty pathname or [anon:...]) must NOT be flagged!
	infoJIT := &process.ProcessInfo{
		PID: 201,
		Maps: []process.MapEntry{
			{StartAddr: 0x1000, EndAddr: 0x2000, Perms: "rwxp", Pathname: ""},
			{StartAddr: 0x2000, EndAddr: 0x3000, Perms: "r-xp", Pathname: "[anon:v8-jit]"},
			{StartAddr: 0x3000, EndAddr: 0x4000, Perms: "rw-p", Pathname: "[heap]"},
		},
	}
	if sig := process.CheckFilelessExecution(infoJIT, cfg); sig != nil {
		t.Errorf("plain JIT mapping should NOT be flagged, got %+v", sig)
	}

	// 2. memfd mapping with unreadable memory -> records coverage gap instead of speculative finding
	infoMemfd := &process.ProcessInfo{
		PID: 202,
		Maps: []process.MapEntry{
			{StartAddr: 0x1000, EndAddr: 0x2000, Perms: "r-xp", Pathname: "memfd:malware (deleted)"},
		},
	}
	sigMemfd := process.CheckFilelessExecution(infoMemfd, cfg)
	if sigMemfd != nil {
		t.Fatalf("expected nil signal (coverage gap) for unreadable memfd mapping, got %+v", sigMemfd)
	}
	if len(infoMemfd.CoverageGaps) == 0 {
		t.Fatalf("expected coverage gap recorded for unreadable memfd mapping")
	}
}

func TestCheckMasquerading(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// 1. Real kernel thread: [kworker/0:0] with empty exe -> NOT flagged
	kthread := &process.ProcessInfo{
		PID:  2,
		Comm: "[kworker/0:0]",
		Exe:  "",
	}
	if sig := process.CheckMasquerading(kthread, cfg); sig != nil {
		t.Errorf("real kernel thread should NOT be flagged, got %+v", sig)
	}

	// 2. Userland process masquerading as [kworker/0:0] with non-empty exe -> WARNING (60)
	fakeKthread := &process.ProcessInfo{
		PID:  301,
		Comm: "[kworker/0:0]",
		Exe:  "/tmp/malware",
	}
	sigKthread := process.CheckMasquerading(fakeKthread, cfg)
	if sigKthread == nil {
		t.Fatalf("expected signal for masquerading kernel thread")
	}
	if sigKthread.Score != 60 || sigKthread.Severity != report.SeverityWarning {
		t.Errorf("expected WARNING score 60, got score %d severity %s", sigKthread.Score, sigKthread.Severity)
	}

	// 3. Fake sshd in /tmp -> WARNING (60)
	fakeSSHD := &process.ProcessInfo{
		PID:  302,
		Comm: "sshd",
		Exe:  "/tmp/sshd",
	}
	sigSSHD := process.CheckMasquerading(fakeSSHD, cfg)
	if sigSSHD == nil {
		t.Fatalf("expected signal for masquerading system daemon")
	}
	if sigSSHD.Score != 60 {
		t.Errorf("expected score 60 for fake sshd, got %d", sigSSHD.Score)
	}

	// 4. Legitimate sshd in /usr/sbin/sshd -> NOT flagged
	realSSHD := &process.ProcessInfo{
		PID:  303,
		Comm: "sshd",
		Exe:  "/usr/sbin/sshd",
	}
	if sig := process.CheckMasquerading(realSSHD, cfg); sig != nil {
		t.Errorf("legitimate sshd should NOT be flagged, got %+v", sig)
	}
}

func TestCheckRootWritableExe(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// 1. Root process (Euid 0) with binary in /tmp -> WARNING (70)
	rootTemp := &process.ProcessInfo{
		PID:  401,
		Euid: 0,
		Exe:  "/tmp/service",
	}
	sigRoot := process.CheckRootWritableExe(rootTemp, cfg)
	if sigRoot == nil {
		t.Fatalf("expected signal for root process with exe in /tmp")
	}
	if sigRoot.Score != 70 || sigRoot.Severity != report.SeverityWarning {
		t.Errorf("expected score 70 WARNING, got %d %s", sigRoot.Score, sigRoot.Severity)
	}

	// 2. Non-root process in /tmp -> nil from CheckRootWritableExe
	nonRootTemp := &process.ProcessInfo{
		PID:  402,
		Euid: 1000,
		Exe:  "/tmp/my_app",
	}
	if sig := process.CheckRootWritableExe(nonRootTemp, cfg); sig != nil {
		t.Errorf("non-root process should not trigger CheckRootWritableExe, got %+v", sig)
	}
}

func TestContainerNamespaceScoreReduction(t *testing.T) {
	cfg := config.NewDefaultConfig()

	signals := []*process.ProcessSignal{
		{
			RuleName:    "Process_Exe_Or_Cwd_In_Temp",
			Reason:      "Process operating in temporary directory",
			Score:       55,
			Severity:    report.SeverityWarning,
			IsPathBased: true,
		},
	}

	info := &process.ProcessInfo{
		PID:   501,
		MntNs: "mnt:[4026532888]",
	}

	selfMntNs := "mnt:[4026531840]"
	isContainer := process.ApplyContainerScoreAdjustment(signals, info, selfMntNs, cfg.Scan.ContainerScoreReduction)
	if !isContainer {
		t.Fatalf("expected isContainer to be true")
	}

	// 55 - 20 = 35 (below 50, so severity drops to NOTICE)
	if signals[0].Score != 35 {
		t.Errorf("expected container reduced score 35, got %d", signals[0].Score)
	}
	if signals[0].Severity != report.SeverityNotice {
		t.Errorf("expected container reduced severity NOTICE, got %s", signals[0].Severity)
	}
}

func TestHiddenPIDTwoPassFiltering(t *testing.T) {
	// Candidate 100: transient in pass 1, but visible in readdir pass 2 -> FILTERED OUT
	// Candidate 200: transient in pass 1, vanished by pass 2 -> FILTERED OUT
	// Candidate 300: missing in pass 1 AND missing in pass 2 AND active in stat -> CONFIRMED
	discrepantPass1 := []int{100, 200, 300}
	readdirPass2 := map[int]bool{
		100: true,  // Now in readdir
		400: true,
	}

	isPIDActivePass2 := func(pid int) bool {
		// 200 is dead/exited; 300 is still active
		return pid == 300
	}

	confirmed := process.FilterTwoPassDiscrepancies(discrepantPass1, readdirPass2, isPIDActivePass2)
	if len(confirmed) != 1 || confirmed[0] != 300 {
		t.Fatalf("expected only PID 300 confirmed, got %v", confirmed)
	}
}

func TestDetectHidepid(t *testing.T) {
	mountinfoWithHidepid := `22 1 0:20 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw,hidepid=2`
	tmpFile, err := os.CreateTemp(t.TempDir(), "mountinfo*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer tmpFile.Close()
	_, _ = tmpFile.WriteString(mountinfoWithHidepid)

	hasHidepid, reason := process.DetectHidepid(tmpFile.Name())
	if !hasHidepid {
		t.Errorf("expected hidepid to be detected")
	}
	if reason == "" {
		t.Errorf("expected non-empty reason")
	}

	mountinfoStandard := `22 1 0:20 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw`
	tmpFile2, err := os.CreateTemp(t.TempDir(), "mountinfo_clean*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer tmpFile2.Close()
	_, _ = tmpFile2.WriteString(mountinfoStandard)

	hasHidepid2, _ := process.DetectHidepid(tmpFile2.Name())
	if hasHidepid2 {
		t.Errorf("expected standard mountinfo NOT to trigger hidepid")
	}
}

func TestVanishingProcess(t *testing.T) {
	// A non-existent PID must return ErrProcessVanished
	_, err := process.ReadProcessInfo(99999999)
	if err != process.ErrProcessVanished {
		t.Errorf("expected ErrProcessVanished for non-existent PID, got %v", err)
	}
}

func TestRealProcessTempAndDeletedExecution(t *testing.T) {
	// Copy /bin/sleep to t.TempDir()
	srcSleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep binary not found on system, skipping live execution test")
	}

	tempDir := t.TempDir()
	tempSleep := filepath.Join(tempDir, "aether_test_sleep")

	srcData, err := os.ReadFile(srcSleep)
	if err != nil {
		t.Fatalf("failed to read sleep binary: %v", err)
	}
	if err := os.WriteFile(tempSleep, srcData, 0755); err != nil {
		t.Fatalf("failed to write temp sleep binary: %v", err)
	}

	// 1. Launch tempSleep
	cmd := exec.Command(tempSleep, "5")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start test process: %v", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	pid := cmd.Process.Pid
	time.Sleep(50 * time.Millisecond) // Give procfs time to register

	// Read process info
	info, err := process.ReadProcessInfo(pid)
	if err != nil {
		t.Fatalf("failed to read procfs for started process %d: %v", pid, err)
	}

	cfg := config.NewDefaultConfig()

	// Assert temp-dir execution detection
	sigTemp := process.CheckExeOrCwdInTemp(info, cfg)
	if sigTemp == nil {
		t.Errorf("expected CheckExeOrCwdInTemp to detect process running from %s", tempDir)
	} else if sigTemp.Score != 55 {
		t.Errorf("expected score 55, got %d", sigTemp.Score)
	}

	// 2. Unlink the running binary while it executes
	if err := os.Remove(tempSleep); err != nil {
		t.Fatalf("failed to unlink running binary: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Re-read process info
	infoDeleted, err := process.ReadProcessInfo(pid)
	if err != nil {
		t.Fatalf("failed to re-read procfs after unlinking: %v", err)
	}

	// Assert deleted detection
	sigDeleted := process.CheckDeletedExe(infoDeleted, cfg)
	if sigDeleted == nil {
		t.Errorf("expected CheckDeletedExe to detect unlinked process binary")
	} else if sigDeleted.Severity != report.SeverityAlert {
		t.Errorf("expected ALERT for deleted binary in /tmp, got %s", sigDeleted.Severity)
	}

	// Test signal consolidation & tiered escalation:
	// Strong + Weak = WARNING (raised score, capped below ALERT)
	var signals []*process.ProcessSignal
	if sigTemp != nil {
		signals = append(signals, sigTemp)
	}
	if sigDeleted != nil {
		signals = append(signals, sigDeleted)
	}

	finding := process.ConsolidateProcessSignals(signals, infoDeleted, false)
	if finding == nil {
		t.Fatalf("expected consolidated finding")
	}
	if finding.Severity != report.SeverityWarning {
		t.Errorf("strong + weak signals MUST NOT escalate to ALERT, expected WARNING, got %s", finding.Severity)
	}
	if finding.Metadata["score"].(int) < 100 {
		t.Errorf("expected raised score >= 100, got %v", finding.Metadata["score"])
	}

	// Strong + Strong = ALERT!
	strongSignals := []*process.ProcessSignal{
		sigDeleted, // Strong (85)
		{
			RuleName: "Process_Kernel_Thread_Masquerade",
			Reason:   "masquerading as kernel thread",
			Score:    60,
			IsStrong: true,
		},
	}
	strongFinding := process.ConsolidateProcessSignals(strongSignals, infoDeleted, false)
	if strongFinding == nil {
		t.Fatalf("expected consolidated finding for strong+strong")
	}
	if strongFinding.Severity != report.SeverityAlert {
		t.Errorf("strong + strong signals MUST escalate to ALERT, got %s", strongFinding.Severity)
	}
}

func TestProcessModuleRun(t *testing.T) {
	cfg := config.NewDefaultConfig()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rep, err := report.NewConcurrentReporter("")
	if err != nil {
		t.Fatalf("failed to create reporter: %v", err)
	}
	defer rep.Close()

	mod := process.NewModule(nil, nil, nil)
	if mod.Name() != "process" {
		t.Errorf("expected module name 'process', got %s", mod.Name())
	}

	err = mod.Run(ctx, cfg, rep)
	if err != nil {
		t.Fatalf("process module run returned error: %v", err)
	}

	cov := mod.Coverage()
	if cov.Inspected == 0 && cov.Limited == 0 {
		t.Errorf("expected inspected or limited processes > 0, got inspected=%d limited=%d", cov.Inspected, cov.Limited)
	}
}

func TestProcess_KernelThreadAndZombieDetection(t *testing.T) {
	// 1. Real kernel thread stat string: flags field contains 0x00200000 (2129984 = 0x208040)
	kthreadStat := "2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 3 0 0 20 0 1 0 4 0 0"
	infoKThread := &process.ProcessInfo{PID: 2}
	process.ParseStatString(kthreadStat, infoKThread)
	if !process.IsKernelThread(infoKThread) {
		t.Errorf("expected PF_KTHREAD to be identified as kernel thread")
	}

	// 2. Fallback PPid == 2 kernel thread
	infoFallback := &process.ProcessInfo{PID: 99, PPid: 2}
	if !process.IsKernelThread(infoFallback) {
		t.Errorf("expected PPid 2 with empty exe/cmdline to be identified as kernel thread")
	}

	// 3. Zombie process: State: Z in status
	zombieStatus := "Name:\tdefunct_proc\nState:\tZ (zombie)\nTgid:\t1234\nPid:\t1234\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n"
	infoZombie := &process.ProcessInfo{PID: 1234}
	process.ParseStatusString(zombieStatus, infoZombie)
	if !infoZombie.IsZombie {
		t.Fatalf("expected IsZombie to be true for State: Z")
	}
	if process.IsKernelThread(infoZombie) {
		t.Errorf("zombie process must NEVER be counted as a kernel thread")
	}
}

func TestCheckDeletedExe_ReplacedOnDisk(t *testing.T) {
	cfg := config.NewDefaultConfig()
	cfg.Scan.TempDirs = []string{"/custom/temp_dir"}
	tmpDir := t.TempDir()

	// 1. Outside temp dirs: binary was replaced on disk with a new file
	binPath := filepath.Join(tmpDir, "zed-editor")
	if err := os.WriteFile(binPath, []byte("version 1"), 0755); err != nil {
		t.Fatal(err)
	}

	var st1 unix.Stat_t
	if err := unix.Stat(binPath, &st1); err != nil {
		t.Fatal(err)
	}

	// Remove old binary and create new version
	if err := os.Remove(binPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binPath, []byte("version 2 new content"), 0755); err != nil {
		t.Fatal(err)
	}

	var st2 unix.Stat_t
	if err := unix.Stat(binPath, &st2); err != nil {
		t.Fatal(err)
	}

	info := &process.ProcessInfo{
		PID:     0, // Will fallback to host path in statInProcessNamespace
		Exe:     binPath + " (deleted)",
		ExeStat: &st1,
	}

	sig := process.CheckDeletedExe(info, cfg)
	if sig == nil {
		t.Fatalf("expected signal for replaced binary")
	}
	if sig.RuleName != "Process_Deleted_Binary_Replaced" {
		t.Errorf("expected Process_Deleted_Binary_Replaced, got %s", sig.RuleName)
	}
	if sig.Severity != report.SeverityNotice {
		t.Errorf("expected NOTICE severity for replaced binary, got %s", sig.Severity)
	}
	if sig.Score != 25 {
		t.Errorf("expected score 25, got %d", sig.Score)
	}
	if !strings.Contains(sig.Reason, "binary was replaced on disk") {
		t.Errorf("expected reason to mention 'binary was replaced on disk', got: %s", sig.Reason)
	}

	// 2. Temp directory: NEVER downgrades even if replaced on disk
	cfgTemp := config.NewDefaultConfig()
	cfgTemp.Scan.TempDirs = []string{tmpDir}

	sigTempReplaced := process.CheckDeletedExe(info, cfgTemp)
	if sigTempReplaced == nil {
		t.Fatalf("expected signal for temp replaced binary")
	}
	if sigTempReplaced.RuleName != "Process_Deleted_Binary_Suspicious_Location" {
		t.Errorf("temp binary must NEVER downgrade on replace, got rule %s", sigTempReplaced.RuleName)
	}
	if sigTempReplaced.Score != 85 || sigTempReplaced.Severity != report.SeverityAlert {
		t.Errorf("expected score 85 and ALERT severity for temp binary, got %d %s", sigTempReplaced.Score, sigTempReplaced.Severity)
	}
	if !sigTempReplaced.IsStrong {
		t.Errorf("temp deleted binary must have IsStrong=true")
	}
}

func TestCheckDeletedExe_Locations(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// 1. Package directories (/opt) -> NOTICE
	infoOpt := &process.ProcessInfo{
		PID: 901,
		Exe: "/opt/vendor/app/bin/worker (deleted)",
	}
	sigOpt := process.CheckDeletedExe(infoOpt, cfg)
	if sigOpt == nil || sigOpt.RuleName != "Process_Deleted_Binary_Package_Upgrade" {
		t.Fatalf("expected Process_Deleted_Binary_Package_Upgrade for /opt, got %+v", sigOpt)
	}
	if sigOpt.Severity != report.SeverityNotice {
		t.Errorf("expected NOTICE for /opt, got %s", sigOpt.Severity)
	}

	// 2. App-managed under /home (.local/share, .local/*.app, .cache, snap, flatpak, AppImage) -> NOTICE
	testCasesAppManaged := []string{
		"/home/user/.local/share/app/bin/tool (deleted)",
		"/home/user/.local/zed.app/libexec/zed-editor (deleted)",
		"/home/user/.cache/myapp/bin/runner (deleted)",
		"/home/user/snap/mytool/current/bin/app (deleted)",
		"/home/user/.local/share/flatpak/app/bin (deleted)",
		"/home/user/Applications/AppImage-tool (deleted)",
	}
	for _, tc := range testCasesAppManaged {
		info := &process.ProcessInfo{PID: 902, Exe: tc}
		sig := process.CheckDeletedExe(info, cfg)
		if sig == nil || sig.RuleName != "Process_Deleted_Binary_App_Managed" {
			t.Errorf("expected Process_Deleted_Binary_App_Managed for %s, got %+v", tc, sig)
		} else if sig.Severity != report.SeverityNotice {
			t.Errorf("expected NOTICE for %s, got %s", tc, sig.Severity)
		}
	}

	// 3. User home non-app-managed -> WARNING (60)
	infoHome := &process.ProcessInfo{
		PID: 903,
		Exe: "/home/user/my_custom_script (deleted)",
	}
	sigHome := process.CheckDeletedExe(infoHome, cfg)
	if sigHome == nil || sigHome.RuleName != "Process_Deleted_Binary_Home" {
		t.Fatalf("expected Process_Deleted_Binary_Home, got %+v", sigHome)
	}
	if sigHome.Severity != report.SeverityWarning || sigHome.Score != 60 {
		t.Errorf("expected WARNING score 60 for user home deleted binary, got %s %d", sigHome.Severity, sigHome.Score)
	}

	// 4. Other location outside package dirs, home, and temp -> WARNING (55)
	infoOther := &process.ProcessInfo{
		PID: 904,
		Exe: "/srv/custom_service/bin/daemon (deleted)",
	}
	sigOther := process.CheckDeletedExe(infoOther, cfg)
	if sigOther == nil || sigOther.RuleName != "Process_Deleted_Binary" {
		t.Fatalf("expected Process_Deleted_Binary, got %+v", sigOther)
	}
	if sigOther.Severity != report.SeverityWarning || sigOther.Score != 55 {
		t.Errorf("expected WARNING score 55 for other location, got %s %d", sigOther.Severity, sigOther.Score)
	}
	if !strings.Contains(sigOther.Reason, "/srv/custom_service/bin/daemon") {
		t.Errorf("expected reason to name actual location, got: %s", sigOther.Reason)
	}
}

func TestProcess_CoverageAndTimings(t *testing.T) {
	cfg := config.NewDefaultConfig()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rep, err := report.NewConcurrentReporter("")
	if err != nil {
		t.Fatalf("failed to create reporter: %v", err)
	}
	defer rep.Close()

	mod := process.NewModule(nil, nil, nil)
	err = mod.Run(ctx, cfg, rep)
	if err != nil {
		t.Fatalf("process module run returned error: %v", err)
	}

	cov := mod.Coverage()
	if cov.DurationBreakdown == nil {
		t.Fatal("expected DurationBreakdown to be non-nil")
	}
	if cov.DurationBreakdown.Total == 0 {
		t.Errorf("expected non-zero Total duration")
	}
	if cov.NotHashed < 0 {
		t.Errorf("expected NotHashed >= 0, got %d", cov.NotHashed)
	}
}

func TestProcess_GroupingKeyAndReasonFormatting(t *testing.T) {
	info1 := &process.ProcessInfo{
		PID:   1001,
		Exe:   "/opt/app/worker",
		MntNs: "mnt:[4026531840]",
	}
	info2 := &process.ProcessInfo{
		PID:   1002,
		Exe:   "/opt/app/worker",
		MntNs: "mnt:[4026531840]",
	}
	info3 := &process.ProcessInfo{
		PID:   1003,
		Exe:   "/opt/app/worker",
		MntNs: "mnt:[4026532999]", // Different mount namespace (container)
	}

	sig := &process.ProcessSignal{
		RuleName: "Process_Deleted_Binary_Package_Upgrade",
		Reason:   "Process binary was deleted from /opt/app/worker",
		Score:    25,
		Severity: report.SeverityNotice,
	}

	f1 := process.ConsolidateProcessSignals([]*process.ProcessSignal{sig}, info1, false)
	f2 := process.ConsolidateProcessSignals([]*process.ProcessSignal{sig}, info2, false)
	f3 := process.ConsolidateProcessSignals([]*process.ProcessSignal{sig}, info3, true)

	if f1 == nil || f2 == nil || f3 == nil {
		t.Fatalf("expected findings from ConsolidateProcessSignals")
	}

	type processGroupKey struct {
		ruleName string
		exePath  string
		mntNs    string
	}
	type groupedFinding struct {
		finding report.Finding
		pids    []int
	}

	groups := make(map[processGroupKey]*groupedFinding)
	for _, item := range []struct {
		f    *report.Finding
		info *process.ProcessInfo
	}{
		{f1, info1},
		{f2, info2},
		{f3, info3},
	} {
		key := processGroupKey{
			ruleName: item.f.RuleName,
			exePath:  item.info.Exe,
			mntNs:    item.info.MntNs,
		}
		if g, ok := groups[key]; ok {
			g.pids = append(g.pids, item.info.PID)
		} else {
			groups[key] = &groupedFinding{
				finding: *item.f,
				pids:    []int{item.info.PID},
			}
		}
	}

	if len(groups) != 2 {
		t.Fatalf("expected 2 groups (host vs container mntNs), got %d", len(groups))
	}

	hostKey := processGroupKey{ruleName: "Process_Deleted_Binary_Package_Upgrade", exePath: "/opt/app/worker", mntNs: "mnt:[4026531840]"}
	hostGroup := groups[hostKey]
	if hostGroup == nil {
		t.Fatalf("expected host group")
	}
	if len(hostGroup.pids) != 2 {
		t.Errorf("expected 2 PIDs in host group, got %d", len(hostGroup.pids))
	}

	containerKey := processGroupKey{ruleName: "Process_Deleted_Binary_Package_Upgrade", exePath: "/opt/app/worker", mntNs: "mnt:[4026532999]"}
	containerGroup := groups[containerKey]
	if containerGroup == nil {
		t.Fatalf("expected container group")
	}
	if len(containerGroup.pids) != 1 {
		t.Errorf("expected 1 PID in container group, got %d", len(containerGroup.pids))
	}
}

type testFindingReporter struct {
	findings []report.Finding
}

func (r *testFindingReporter) Report(f report.Finding) {
	r.findings = append(r.findings, f)
}
func (r *testFindingReporter) Findings() []report.Finding        { return r.findings }
func (r *testFindingReporter) Summary() (int, int, int, int, int) { return 0, 0, 0, 0, 0 }
func (r *testFindingReporter) Close() error                      { return nil }

func TestProcessModule_SelfPIDExclusion(t *testing.T) {
	mod := process.NewModule(nil, nil, nil)
	cfg := config.NewDefaultConfig()
	rep := &testFindingReporter{}

	ctx := context.Background()
	if err := mod.Run(ctx, cfg, rep); err != nil {
		t.Fatalf("module run failed: %v", err)
	}

	selfPID := os.Getpid()
	for _, f := range rep.findings {
		if pidVal, ok := f.Metadata["pid"].(int); ok && pidVal == selfPID {
			t.Errorf("self PID %d was emitted in process findings: %+v", selfPID, f)
		}
		if pidsVal, ok := f.Metadata["pids"].([]int); ok {
			for _, p := range pidsVal {
				if p == selfPID {
					t.Errorf("self PID %d was included in grouped process findings: %+v", selfPID, f)
				}
			}
		}
	}
}

func TestConsolidateProcessSignals_RuleSeverities(t *testing.T) {
	sig1 := &process.ProcessSignal{
		RuleName: "Process_Deleted_Binary_Home",
		Reason:   "deleted from home",
		Score:    60,
		Severity: report.SeverityWarning,
	}
	sig2 := &process.ProcessSignal{
		RuleName: "Process_Root_NonRoot_Owned_Exe",
		Reason:   "non-root owner",
		Score:    20,
		Severity: report.SeverityNotice,
	}

	info := &process.ProcessInfo{
		PID:  99999,
		Exe:  "/home/user/app (deleted)",
		Comm: "app",
	}

	f := process.ConsolidateProcessSignals([]*process.ProcessSignal{sig1, sig2}, info, false)
	if f == nil {
		t.Fatalf("expected non-nil finding")
	}

	ruleSevs, ok := f.Metadata["rule_severities"].(map[string]string)
	if !ok {
		t.Fatalf("expected rule_severities map in metadata, got %+v", f.Metadata["rule_severities"])
	}

	if ruleSevs["Process_Deleted_Binary_Home"] != "WARNING" {
		t.Errorf("expected WARNING for Process_Deleted_Binary_Home, got %s", ruleSevs["Process_Deleted_Binary_Home"])
	}
	if ruleSevs["Process_Root_NonRoot_Owned_Exe"] != "NOTICE" {
		t.Errorf("expected NOTICE for Process_Root_NonRoot_Owned_Exe, got %s", ruleSevs["Process_Root_NonRoot_Owned_Exe"])
	}
}

