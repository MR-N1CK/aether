package packaging_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRpmPackage(t *testing.T) {
	root := findProjectRoot(t)
	rpmPath := filepath.Join(root, "dist/aether-1.0.0-1.x86_64.rpm")

	if _, err := os.Stat(rpmPath); os.IsNotExist(err) {
		t.Skip("dist/aether-1.0.0-1.x86_64.rpm not found; run make package first")
	}

	rpmBin, err := exec.LookPath("rpm")
	if err != nil {
		t.Skip("rpm binary not installed; skipping rpm inspection")
	}

	// 1. Verify file listing via rpm -qlp
	cmd := exec.Command(rpmBin, "-qlp", rpmPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("rpm -qlp failed on %s: %v (output: %s)", rpmPath, err, string(out))
	}

	fileList := string(out)
	requiredFiles := []string{
		"/usr/bin/aether",
		"/etc/aether/config.yaml",
		"/usr/lib/systemd/system/aether-scan.service",
		"/usr/lib/systemd/system/aether-scan.timer",
		"/usr/share/man/man1/aether.1",
	}

	for _, rf := range requiredFiles {
		if !strings.Contains(fileList, rf) {
			t.Errorf("RPM package missing required file: %s", rf)
		}
	}

	// 2. Verify scriptlets via rpm -qp --scripts
	cmd = exec.Command(rpmBin, "-qp", "--scripts", rpmPath)
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("rpm -qp --scripts failed: %v", err)
	}
	scriptsStr := string(out)

	// FR-015 check
	if strings.Contains(scriptsStr, "systemctl start") || strings.Contains(scriptsStr, "aether scan") {
		t.Errorf("FR-015 violation: RPM scriptlets must not auto-start services or scans")
	}

	// FR-018 check
	if !strings.Contains(scriptsStr, "systemctl stop") {
		t.Errorf("FR-018 violation: RPM preun scriptlet must stop systemd units")
	}
}
