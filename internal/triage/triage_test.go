package triage_test

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"gopkg.in/yaml.v3"

	"aether/internal/report"
	"aether/internal/triage"
)

func TestTriage_MatchingPin_DowngradesToInfo(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	targetFile := filepath.Join(tmpDir, "test.service")
	if err := os.WriteFile(targetFile, []byte("ExecStart=/usr/bin/mytool\n"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	h, err := triage.HashFile(targetFile, 0)
	if err != nil {
		t.Fatalf("HashFile failed: %v", err)
	}

	ackPath := filepath.Join(tmpDir, "acknowledged.yaml")
	entry := triage.AckEntry{
		Path:       targetFile,
		Rule:       "Persistence_Test_Rule",
		FileSHA256: h,
		Reason:     "known internal service",
		AddedBy:    "admin",
	}
	if err := triage.WriteAckEntry(ackPath, entry); err != nil {
		t.Fatalf("WriteAckEntry failed: %v", err)
	}

	eng, err := triage.LoadEngine(ackPath, "")
	if err != nil {
		t.Fatalf("LoadEngine failed: %v", err)
	}

	f := report.NewFinding("persistence", report.SeverityWarning, targetFile, "suspicious service", "Persistence_Test_Rule")
	f.Metadata["score"] = 65

	acked := eng.Evaluate(&f, "")
	if !acked {
		t.Fatalf("expected finding to be acknowledged, got false")
	}

	if f.Severity != report.SeverityInfo {
		t.Errorf("expected SeverityInfo (downgraded), got %s", f.Severity)
	}
	if f.Metadata["acknowledged"] != true {
		t.Errorf("expected metadata acknowledged=true")
	}
	if f.Metadata["original_severity"] != "WARNING" {
		t.Errorf("expected original_severity=WARNING, got %v", f.Metadata["original_severity"])
	}
}

func TestTriage_ModifiedFile_VoidsAck(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	targetFile := filepath.Join(tmpDir, "test.service")
	if err := os.WriteFile(targetFile, []byte("ExecStart=/usr/bin/mytool\n"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	h, err := triage.HashFile(targetFile, 0)
	if err != nil {
		t.Fatalf("HashFile failed: %v", err)
	}

	ackPath := filepath.Join(tmpDir, "acknowledged.yaml")
	entry := triage.AckEntry{
		Path:       targetFile,
		Rule:       "Persistence_Test_Rule",
		FileSHA256: h,
		Reason:     "known internal service",
	}
	if err := triage.WriteAckEntry(ackPath, entry); err != nil {
		t.Fatalf("WriteAckEntry failed: %v", err)
	}

	eng, err := triage.LoadEngine(ackPath, "")
	if err != nil {
		t.Fatalf("LoadEngine failed: %v", err)
	}

	// Modify file
	if err := os.WriteFile(targetFile, []byte("ExecStart=/usr/bin/mytool --modified\n"), 0644); err != nil {
		t.Fatalf("failed to modify test file: %v", err)
	}

	f := report.NewFinding("persistence", report.SeverityWarning, targetFile, "suspicious service", "Persistence_Test_Rule")
	acked := eng.Evaluate(&f, "")
	if acked {
		t.Fatalf("modified file MUST NOT be acknowledged")
	}

	if f.Severity != report.SeverityWarning {
		t.Errorf("expected finding to remain WARNING, got %s", f.Severity)
	}
	if f.Metadata["ack_void"] != true {
		t.Errorf("expected ack_void=true in metadata")
	}
	if !strings.Contains(f.Reason, "acknowledged file was modified") {
		t.Errorf("expected reason to mention 'acknowledged file was modified', got: %s", f.Reason)
	}
}

func TestTriage_LineHashPin(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	profileFile := filepath.Join(tmpDir, ".bashrc")
	line := "alias sudo='sudo -E'"
	content := "# user profile\n" + line + "\nexport FOO=1\n"
	if err := os.WriteFile(profileFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write profile: %v", err)
	}

	lineHash := triage.HashLine(line)
	ackPath := filepath.Join(tmpDir, "acknowledged.yaml")
	entry := triage.AckEntry{
		Path:        profileFile,
		Rule:        "Persistence_Profile_Privileged_Alias",
		LineSHA256:  lineHash,
		LineContent: line,
		Reason:      "user preference for sudo -E",
	}
	if err := triage.WriteAckEntry(ackPath, entry); err != nil {
		t.Fatalf("WriteAckEntry failed: %v", err)
	}

	eng, err := triage.LoadEngine(ackPath, "")
	if err != nil {
		t.Fatalf("LoadEngine failed: %v", err)
	}

	// Test 1: Matching line
	f := report.NewFinding("persistence", report.SeverityWarning, profileFile, "alias overrides sudo", "Persistence_Profile_Privileged_Alias")
	f.Metadata["line_content"] = line
	if !eng.Evaluate(&f, "") {
		t.Fatalf("expected line-pinned finding to be acknowledged")
	}
	if f.Severity != report.SeverityInfo {
		t.Errorf("expected INFO, got %s", f.Severity)
	}

	// Test 2: Modified line
	f2 := report.NewFinding("persistence", report.SeverityWarning, profileFile, "alias overrides sudo", "Persistence_Profile_Privileged_Alias")
	f2.Metadata["line_content"] = "alias sudo='sudo -i /tmp/evil'"
	// Rewrite file to remove the original pinned line
	_ = os.WriteFile(profileFile, []byte("alias sudo='sudo -i /tmp/evil'\n"), 0644)
	if eng.Evaluate(&f2, "") {
		t.Fatalf("modified line MUST NOT be acknowledged")
	}
	if f2.Metadata["ack_void"] != true {
		t.Errorf("expected ack_void=true on modified line")
	}
}

func TestTriage_ReferencedTargetHashPin(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	unitFile := filepath.Join(tmpDir, "worker.service")
	scriptFile := filepath.Join(tmpDir, "agent.sh")

	if err := os.WriteFile(scriptFile, []byte("#!/bin/bash\necho hello\n"), 0755); err != nil {
		t.Fatalf("failed to write script: %v", err)
	}
	scriptHash, _ := triage.HashFile(scriptFile, 0)

	unitContent := "[Unit]\nDescription=Worker\n[Service]\nExecStart=" + scriptFile + "\n"
	if err := os.WriteFile(unitFile, []byte(unitContent), 0644); err != nil {
		t.Fatalf("failed to write unit: %v", err)
	}
	unitHash, _ := triage.HashFile(unitFile, 0)

	ackPath := filepath.Join(tmpDir, "acknowledged.yaml")
	entry := triage.AckEntry{
		Path:       unitFile,
		Rule:       "Persistence_Test",
		FileSHA256: unitHash,
		ExecTargetHashes: map[string]string{
			scriptFile: scriptHash,
		},
		Reason: "approved worker",
	}
	if err := triage.WriteAckEntry(ackPath, entry); err != nil {
		t.Fatalf("WriteAckEntry failed: %v", err)
	}

	eng, err := triage.LoadEngine(ackPath, "")
	if err != nil {
		t.Fatalf("LoadEngine failed: %v", err)
	}

	// 1. Script unchanged -> acknowledged
	f := report.NewFinding("persistence", report.SeverityWarning, unitFile, "suspicious script exec", "Persistence_Test")
	if !eng.Evaluate(&f, "") {
		t.Fatalf("expected approved worker to be acknowledged")
	}

	// 2. Script modified -> voids acknowledgment
	if err := os.WriteFile(scriptFile, []byte("#!/bin/bash\necho modified\n"), 0755); err != nil {
		t.Fatalf("failed to modify script: %v", err)
	}
	f2 := report.NewFinding("persistence", report.SeverityWarning, unitFile, "suspicious script exec", "Persistence_Test")
	if eng.Evaluate(&f2, "") {
		t.Fatalf("worker with modified script MUST NOT be acknowledged")
	}
	if f2.Metadata["ack_void"] != true {
		t.Errorf("expected ack_void=true")
	}
}

func TestTriage_AlertAndIOC_NeverAckable(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	targetFile := filepath.Join(tmpDir, "miner.service")
	_ = os.WriteFile(targetFile, []byte("ExecStart=/tmp/miner\n"), 0644)
	h, _ := triage.HashFile(targetFile, 0)

	ackPath := filepath.Join(tmpDir, "acknowledged.yaml")
	entry := triage.AckEntry{
		Path:       targetFile,
		Rule:       "Persistence_Reverse_Shell_Primitive",
		FileSHA256: h,
		Reason:     "trying to ack alert",
	}
	_ = triage.WriteAckEntry(ackPath, entry)
	eng, _ := triage.LoadEngine(ackPath, "")

	// 1. SeverityAlert finding
	fAlert := report.NewFinding("persistence", report.SeverityAlert, targetFile, "rev shell", "Persistence_Reverse_Shell_Primitive")
	if eng.Evaluate(&fAlert, "") {
		t.Errorf("ALERT findings must NEVER be acknowledged")
	}

	// 2. IOC finding
	fIOC := report.NewFinding("persistence", report.SeverityWarning, targetFile, "ioc match", "IOC_Hash_Hit")
	fIOC.Metadata["is_ioc_match"] = true
	if eng.Evaluate(&fIOC, "") {
		t.Errorf("IOC findings must NEVER be acknowledged")
	}

	// 3. High confidence finding
	fHC := report.NewFinding("persistence", report.SeverityWarning, targetFile, "high conf", "Persistence_Reverse_Shell_Primitive")
	fHC.Metadata["high_confidence"] = true
	if eng.Evaluate(&fHC, "") {
		t.Errorf("High confidence findings must NEVER be acknowledged")
	}
}

func TestTriage_PathOutsideUserHome_Skipped(t *testing.T) {
	tmpDir := t.TempDir()
	fakeHome := filepath.Join(tmpDir, "home", "alice")
	_ = os.MkdirAll(fakeHome, 0755)
	t.Setenv("HOME", fakeHome)

	ackPath := filepath.Join(fakeHome, "acknowledged.yaml")
	entry := triage.AckEntry{
		Path:   "/etc/shadow",
		Rule:   "Persistence_Test",
		Reason: "attempt to ack system file from user config",
	}
	_ = triage.WriteAckEntry(ackPath, entry)

	eng, err := triage.LoadEngine(ackPath, "")
	if err != nil {
		t.Fatalf("LoadEngine failed: %v", err)
	}

	// Path outside user home should be skipped
	if len(eng.Entries()) != 0 {
		t.Errorf("expected 0 entries loaded (path outside home skipped), got %d", len(eng.Entries()))
	}
}

func TestTriage_InsecurePermissions_Rejected(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("skipping in root environment")
	}

	tmpDir := t.TempDir()
	ackPath := filepath.Join(tmpDir, "acknowledged.yaml")

	af := triage.AckFile{
		Entries: []triage.AckEntry{
			{Path: "/home/user/foo", Reason: "test"},
		},
	}
	data, _ := yaml.Marshal(&af)
	// Pin umask: under a 022 umask (CI containers) WriteFile(0666) lands as
	// 0644 and the insecure-permission precondition never materializes.
	oldUmask := syscall.Umask(0)
	defer syscall.Umask(oldUmask)
	_ = os.WriteFile(ackPath, data, 0666) // group/world writable!

	_, err := triage.LoadEngine(ackPath, "")
	if err == nil {
		t.Fatalf("expected error for group/world writable ack file, got nil")
	}
	if !strings.Contains(err.Error(), "insecure permissions") {
		t.Errorf("expected insecure permissions error, got: %v", err)
	}
}

func TestTriage_SystemAcksRootExecution(t *testing.T) {
	tmpDir := t.TempDir()
	etcDir := filepath.Join(tmpDir, "etc/aether")
	_ = os.MkdirAll(etcDir, 0700)
	sysAckPath := filepath.Join(etcDir, "acknowledged.yaml")

	userHome := filepath.Join(tmpDir, "home/alice")
	unitDir := filepath.Join(userHome, ".config/systemd/user")
	_ = os.MkdirAll(unitDir, 0755)
	unitFile := filepath.Join(unitDir, "myunit.service")
	_ = os.WriteFile(unitFile, []byte("ExecStart=/usr/bin/alice-tool\n"), 0644)

	unitHash, err := triage.HashFile(unitFile, 0)
	if err != nil {
		t.Fatalf("failed to hash unit file: %v", err)
	}

	entry := triage.AckEntry{
		Path:       unitFile,
		Rule:       "Persistence_Systemd_Unowned_Unit",
		FileSHA256: unitHash,
		Reason:     "approved user unit acknowledged by system admin",
		AddedBy:    "root",
	}

	if err := triage.WriteAckEntry(sysAckPath, entry); err != nil {
		t.Fatalf("WriteAckEntry failed: %v", err)
	}

	// Verify file mode is 0600
	st, err := os.Stat(sysAckPath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0600 {
		t.Errorf("expected permissions 0600, got %04o", perm)
	}

	// Load engine with rootFS (simulating root execution loading /etc/aether/acknowledged.yaml)
	eng, err := triage.LoadEngine("", tmpDir)
	if err != nil {
		t.Fatalf("LoadEngine failed: %v", err)
	}

	f := report.NewFinding("persistence", report.SeverityWarning, unitFile, "unowned user service", "Persistence_Systemd_Unowned_Unit")
	if !eng.Evaluate(&f, "") {
		t.Fatalf("expected system-acknowledged user unit to be acknowledged in root scan")
	}
	if f.Severity != report.SeverityInfo {
		t.Errorf("expected SeverityInfo, got: %s", f.Severity)
	}

	// Modify the unit file -> must void acknowledgment
	_ = os.WriteFile(unitFile, []byte("ExecStart=/usr/bin/alice-tool --tampered\n"), 0644)
	f2 := report.NewFinding("persistence", report.SeverityWarning, unitFile, "unowned user service", "Persistence_Systemd_Unowned_Unit")
	if eng.Evaluate(&f2, "") {
		t.Fatalf("modified unit MUST NOT be acknowledged")
	}
	if f2.Metadata["ack_void"] != true {
		t.Errorf("expected ack_void=true on modified unit")
	}
}

func TestCountAckEntries(t *testing.T) {
	tmpDir := t.TempDir()
	ackPath := filepath.Join(tmpDir, "acknowledged.yaml")

	// 1. Missing file -> error
	if _, err := triage.CountAckEntries(filepath.Join(tmpDir, "missing.yaml")); err == nil {
		t.Errorf("expected error for missing file")
	}

	// 2. Empty file
	_ = os.WriteFile(ackPath, []byte("entries: []\n"), 0600)
	if c, err := triage.CountAckEntries(ackPath); err != nil || c != 0 {
		t.Errorf("expected 0 entries, got %d (err: %v)", c, err)
	}

	// 3. File with 2 entries
	af := triage.AckFile{
		Entries: []triage.AckEntry{
			{Path: "/path1", Reason: "r1"},
			{Path: "/path2", Reason: "r2"},
		},
	}
	data, _ := yaml.Marshal(&af)
	_ = os.WriteFile(ackPath, data, 0600)

	if c, err := triage.CountAckEntries(ackPath); err != nil || c != 2 {
		t.Errorf("expected 2 entries, got %d (err: %v)", c, err)
	}
}
