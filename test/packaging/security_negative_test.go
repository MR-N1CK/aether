package packaging_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecurityNegatives(t *testing.T) {
	root := findProjectRoot(t)

	// 1. Maintainer scripts and installer must not contain network fetch commands
	scripts := []string{
		"install.sh",
		"packaging/deb/postinst",
		"packaging/deb/prerm",
		"packaging/deb/postrm",
		"packaging/rpm/aether.spec",
	}

	networkPatterns := []string{"curl ", "wget ", "nc -", "socat ", "fetch "}
	for _, relPath := range scripts {
		fullPath := filepath.Join(root, relPath)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			t.Fatalf("failed to read %s: %v", relPath, err)
		}
		content := string(data)
		for _, netCmd := range networkPatterns {
			if strings.Contains(content, netCmd) {
				t.Errorf("Principle III violation: script %s contains network command %q", relPath, netCmd)
			}
		}
	}

	// 2. Packaging scripts must not execute scanned targets or run scans on install (FR-015)
	for _, relPath := range []string{"packaging/deb/postinst", "packaging/rpm/aether.spec"} {
		data, _ := os.ReadFile(filepath.Join(root, relPath))
		content := string(data)
		if strings.Contains(content, "aether scan") || strings.Contains(content, "systemctl start") {
			t.Errorf("FR-015 violation: %s must not trigger automatic scan or service start on install", relPath)
		}
	}

	// 3. Uninstallation must explicitly preserve /var/log/aether (FR-017)
	installShData, _ := os.ReadFile(filepath.Join(root, "install.sh"))
	if !strings.Contains(string(installShData), "Preserved /var/log/aether/") {
		t.Errorf("FR-017 violation: install.sh uninstall must preserve /var/log/aether/")
	}

	// 4. Systemd unit sandboxing invariants (FR-025)
	serviceData, _ := os.ReadFile(filepath.Join(root, "packaging/systemd/aether-scan.service"))
	serviceStr := string(serviceData)
	if !strings.Contains(serviceStr, "PrivateTmp=false") {
		t.Errorf("FR-025 violation: systemd service must keep PrivateTmp=false for threat hunter visibility")
	}
	if !strings.Contains(serviceStr, "LogsDirectory=aether") {
		t.Errorf("FR-025 violation: systemd service must configure LogsDirectory=aether")
	}
}
