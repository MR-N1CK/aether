package scanner_test

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"

	"aether/internal/config"
	"aether/internal/report"
	"aether/internal/scanner"
)

func TestCheckELFInTempOrDev(t *testing.T) {
	elfHeader := []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}
	nonELFHeader := []byte{'#', '!', '/', 'b', 'i', 'n', '/', 's', 'h'}
	cfg := config.NewDefaultConfig()

	// 1. Non-ELF file in /tmp -> should not match
	if m := scanner.CheckELFInTempOrDev("/tmp/script.sh", nonELFHeader, 0755, 0, false, cfg); m != nil {
		t.Errorf("expected nil for non-ELF, got %+v", m)
	}

	// 2. Executable ELF in /tmp without extra signals (owned by root uid=0) -> WARNING (score 55)
	m1 := scanner.CheckELFInTempOrDev("/tmp/test_elf", elfHeader, 0755, 0, false, cfg)
	if m1 == nil || m1.Severity != report.SeverityWarning || m1.Score != 55 {
		t.Errorf("expected WARNING (55) for standard ELF in /tmp, got: %+v", m1)
	}

	// 3. ELF in /tmp with hidden name + executable bit -> Escalated to ALERT (score 85)
	m2 := scanner.CheckELFInTempOrDev("/tmp/.hidden_elf", elfHeader, 0755, 0, false, cfg)
	if m2 == nil || m2.Severity != report.SeverityAlert || m2.Score != 85 {
		t.Errorf("expected ALERT (85) for hidden executable ELF in /tmp, got: %+v", m2)
	}

	// 4. ELF in /tmp with other signal (e.g. IOC hit) -> Escalated to ALERT (score 85)
	m3 := scanner.CheckELFInTempOrDev("/tmp/normal_name", elfHeader, 0644, 0, true, cfg)
	if m3 == nil || m3.Severity != report.SeverityAlert || m3.Score != 85 {
		t.Errorf("expected ALERT (85) for ELF in /tmp with other signal, got: %+v", m3)
	}

	// 5. ELF regular file in /dev -> ALERT (score 85)
	m4 := scanner.CheckELFInTempOrDev("/dev/fake_char", elfHeader, 0755, 0, false, cfg)
	if m4 == nil || m4.Severity != report.SeverityAlert || m4.Score != 85 {
		t.Errorf("expected ALERT (85) for regular ELF file in /dev, got: %+v", m4)
	}

	// 6. Executable ELF in /dev/shm -> WARNING (score 55)
	m5 := scanner.CheckELFInTempOrDev("/dev/shm/miner", elfHeader, 0755, 0, false, cfg)
	if m5 == nil || m5.Severity != report.SeverityWarning || m5.Score != 55 {
		t.Errorf("expected WARNING (55) for ELF in /dev/shm, got: %+v", m5)
	}

	// 7. Non-executable ELF in /tmp owned by current invoking non-root user -> NOTICE (score 25)
	currentUID := uint32(os.Getuid())
	m6 := scanner.CheckELFInTempOrDev("/tmp/cached_lib.so", elfHeader, 0644, currentUID, false, cfg)
	if os.Geteuid() != 0 {
		if m6 == nil || m6.Severity != report.SeverityNotice || m6.Score != 25 {
			t.Errorf("expected NOTICE (25) for non-executable ELF owned by non-root user in /tmp, got: %+v", m6)
		}
	}

	// 8. Non-executable ELF in /tmp owned by current non-root user BUT with IOC signal -> Escalated to ALERT (score 85)
	m7 := scanner.CheckELFInTempOrDev("/tmp/cached_lib.so", elfHeader, 0644, currentUID, true, cfg)
	if m7 == nil || m7.Severity != report.SeverityAlert || m7.Score != 85 {
		t.Errorf("expected ALERT (85) for non-executable ELF with IOC match in /tmp, got: %+v", m7)
	}
}

func TestCheckHiddenExecutableInSystemDirs(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// 1. Non-executable hidden file in /usr/bin -> nil
	if m := scanner.CheckHiddenExecutableInSystemDirs("/usr/bin/.hidden", 0644, cfg); m != nil {
		t.Errorf("expected nil for non-executable, got %+v", m)
	}

	// 2. Normal executable in /usr/bin -> nil
	if m := scanner.CheckHiddenExecutableInSystemDirs("/usr/bin/cat", 0755, cfg); m != nil {
		t.Errorf("expected nil for normal binary, got %+v", m)
	}

	// 3. Hidden executable in /usr/bin -> WARNING (score 65)
	m := scanner.CheckHiddenExecutableInSystemDirs("/usr/bin/.stealth", 0755, cfg)
	if m == nil || m.Severity != report.SeverityWarning || m.Score != 65 {
		t.Errorf("expected WARNING (65) for hidden executable in /usr/bin, got: %+v", m)
	}

	// 4. Hidden executable in /home/user -> nil (not system dir)
	if m := scanner.CheckHiddenExecutableInSystemDirs("/home/user/.bashrc", 0755, cfg); m != nil {
		t.Errorf("expected nil for user directory, got %+v", m)
	}
}

func TestCheckSuspiciousSUID(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// 1. SUID in standard path /usr/bin/passwd -> nil
	suidMode := uint32(unix.S_ISUID | 0755)
	if m := scanner.CheckSuspiciousSUID("/usr/bin/passwd", suidMode, cfg); m != nil {
		t.Errorf("expected nil for standard SUID /usr/bin/passwd, got %+v", m)
	}

	// 2. Non-SUID in /tmp -> nil
	if m := scanner.CheckSuspiciousSUID("/tmp/tool", 0755, cfg); m != nil {
		t.Errorf("expected nil for non-SUID file, got %+v", m)
	}

	// 3. SUID executable in /tmp/rootshell -> ALERT (score 85)
	m := scanner.CheckSuspiciousSUID("/tmp/rootshell", suidMode, cfg)
	if m == nil || m.Severity != report.SeverityAlert || m.Score != 85 {
		t.Errorf("expected ALERT (85) for SUID file in /tmp, got: %+v", m)
	}
}

func TestCheckWorldWritableInEtc(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// 1. Normal permissions in /etc/hosts (0644) -> nil
	if m := scanner.CheckWorldWritableInEtc("/etc/hosts", 0644, cfg); m != nil {
		t.Errorf("expected nil for 0644 in /etc, got %+v", m)
	}

	// 2. World writable in /tmp (0666) -> nil (not in /etc)
	if m := scanner.CheckWorldWritableInEtc("/tmp/scratch", 0666, cfg); m != nil {
		t.Errorf("expected nil for /tmp, got %+v", m)
	}

	// 3. World writable in /etc/cron.d/job (0666) -> WARNING (score 60)
	m := scanner.CheckWorldWritableInEtc("/etc/cron.d/job", 0666, cfg)
	if m == nil || m.Severity != report.SeverityWarning || m.Score != 60 {
		t.Errorf("expected WARNING (60) for world-writable file in /etc, got: %+v", m)
	}
}
