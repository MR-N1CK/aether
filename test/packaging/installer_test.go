package packaging_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestInstallerSecurity(t *testing.T) {
	root := findProjectRoot(t)
	installScript := filepath.Join(root, "install.sh")

	// Verify install.sh exists and is executable
	info, err := os.Stat(installScript)
	if err != nil {
		t.Fatalf("install.sh not found: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Errorf("install.sh is not executable (mode: %v)", info.Mode())
	}

	// Test unprivileged installation in an isolated temporary HOME
	tmpHome, err := os.MkdirTemp("", "aether-installer-test-*")
	if err != nil {
		t.Fatalf("failed to create temp home: %v", err)
	}
	defer os.RemoveAll(tmpHome)

	// Ensure bin/aether or bin/aether-yara-static exists
	binPath := filepath.Join(root, "bin/aether")
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		t.Skip("bin/aether not found; run make build-pure first.")
	}

	cmd := exec.Command(installScript, "install")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "HOME="+tmpHome)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("unprivileged install failed: %v (output: %s)", err, string(out))
	}

	installedBin := filepath.Join(tmpHome, ".local/bin/aether")
	if _, err := os.Stat(installedBin); os.IsNotExist(err) {
		t.Errorf("expected installed binary at %s, not found", installedBin)
	}

	// Test unprivileged uninstallation
	uninstCmd := exec.Command(installScript, "uninstall")
	uninstCmd.Dir = root
	uninstCmd.Env = append(os.Environ(), "HOME="+tmpHome)
	uninstOut, err := uninstCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("unprivileged uninstall failed: %v (output: %s)", err, string(uninstOut))
	}

	if _, err := os.Stat(installedBin); !os.IsNotExist(err) {
		t.Errorf("expected %s to be removed after uninstall", installedBin)
	}
}
