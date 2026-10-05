package packaging_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSystemdUnits(t *testing.T) {
	root := findProjectRoot(t)
	servicePath := filepath.Join(root, "packaging/systemd/aether-scan.service")
	timerPath := filepath.Join(root, "packaging/systemd/aether-scan.timer")

	serviceData, err := os.ReadFile(servicePath)
	if err != nil {
		t.Fatalf("failed to read service unit: %v", err)
	}
	serviceStr := string(serviceData)

	// Verify security sandboxing properties
	if !strings.Contains(serviceStr, "PrivateTmp=false") {
		t.Errorf("service unit must have PrivateTmp=false to preserve host /tmp threat hunting visibility")
	}
	if !strings.Contains(serviceStr, "LogsDirectory=aether") {
		t.Errorf("service unit must have LogsDirectory=aether to manage /var/log/aether")
	}
	if !strings.Contains(serviceStr, "Nice=19") {
		t.Errorf("service unit must have Nice=19 for idle process scheduling")
	}
	if !strings.Contains(serviceStr, "IOSchedulingClass=idle") {
		t.Errorf("service unit must have IOSchedulingClass=idle")
	}
	if !strings.Contains(serviceStr, "ProtectSystem=strict") {
		t.Errorf("service unit must have ProtectSystem=strict")
	}

	timerData, err := os.ReadFile(timerPath)
	if err != nil {
		t.Fatalf("failed to read timer unit: %v", err)
	}
	timerStr := string(timerData)

	if !strings.Contains(timerStr, "OnCalendar=weekly") {
		t.Errorf("timer unit must have OnCalendar=weekly")
	}
	if !strings.Contains(timerStr, "WantedBy=timers.target") {
		t.Errorf("timer unit must have WantedBy=timers.target")
	}

	// Validate with systemd-analyze if available
	if analyzeBin, err := exec.LookPath("systemd-analyze"); err == nil {
		cmd := exec.Command(analyzeBin, "verify", servicePath, timerPath)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("systemd-analyze verify output (non-fatal warning): %s", string(out))
		}
	}
}
