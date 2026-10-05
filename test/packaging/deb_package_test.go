package packaging_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDebPackage(t *testing.T) {
	root := findProjectRoot(t)
	debPath := filepath.Join(root, "dist/aether_1.0.0_amd64.deb")

	if _, err := os.Stat(debPath); os.IsNotExist(err) {
		t.Skip("dist/aether_1.0.0_amd64.deb not found; run make package first")
	}

	dpkgBin, err := exec.LookPath("dpkg-deb")
	if err != nil {
		t.Skip("dpkg-deb not installed; skipping deb inspection")
	}

	tmpDir, err := os.MkdirTemp("", "aether-deb-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	controlDir := filepath.Join(tmpDir, "DEBIAN")
	dataDir := filepath.Join(tmpDir, "data")
	os.MkdirAll(controlDir, 0755)
	os.MkdirAll(dataDir, 0755)

	// Extract control
	cmd := exec.Command(dpkgBin, "-e", debPath, controlDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to extract deb control: %v (output: %s)", err, string(out))
	}

	// Extract data
	cmd = exec.Command(dpkgBin, "-x", debPath, dataDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to extract deb data: %v (output: %s)", err, string(out))
	}

	// 1. Verify control file
	controlData, err := os.ReadFile(filepath.Join(controlDir, "control"))
	if err != nil {
		t.Fatalf("failed to read control file: %v", err)
	}
	controlStr := string(controlData)
	if !strings.Contains(controlStr, "Package: aether") {
		t.Errorf("control missing Package: aether")
	}
	if !strings.Contains(controlStr, "Architecture: amd64") {
		t.Errorf("control missing Architecture: amd64")
	}

	// 2. Verify conffiles
	conffilesData, err := os.ReadFile(filepath.Join(controlDir, "conffiles"))
	if err != nil {
		t.Fatalf("failed to read conffiles: %v", err)
	}
	if !strings.Contains(string(conffilesData), "/etc/aether/config.yaml") {
		t.Errorf("conffiles missing /etc/aether/config.yaml")
	}

	// 3. Verify postinst does NOT auto-start services/scans (FR-015)
	postinstData, err := os.ReadFile(filepath.Join(controlDir, "postinst"))
	if err != nil {
		t.Fatalf("failed to read postinst: %v", err)
	}
	postinstStr := string(postinstData)
	if strings.Contains(postinstStr, "systemctl start") || strings.Contains(postinstStr, "systemctl enable") {
		t.Errorf("FR-015 violation: postinst must not start or enable systemd units")
	}
	if strings.Contains(postinstStr, "aether scan") {
		t.Errorf("FR-015 violation: postinst must not initiate background scans")
	}

	// 4. Verify prerm stops units on removal (FR-018)
	prermData, err := os.ReadFile(filepath.Join(controlDir, "prerm"))
	if err != nil {
		t.Fatalf("failed to read prerm: %v", err)
	}
	prermStr := string(prermData)
	if !strings.Contains(prermStr, "systemctl stop") {
		t.Errorf("FR-018 violation: prerm must stop systemd units on removal")
	}

	// 5. Verify payload files
	if _, err := os.Stat(filepath.Join(dataDir, "usr/bin/aether")); os.IsNotExist(err) {
		t.Errorf("missing /usr/bin/aether in deb package")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "etc/aether/config.yaml")); os.IsNotExist(err) {
		t.Errorf("missing /etc/aether/config.yaml in deb package")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "lib/systemd/system/aether-scan.service")); os.IsNotExist(err) {
		t.Errorf("missing /lib/systemd/system/aether-scan.service in deb package")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "usr/share/man/man1/aether.1")); os.IsNotExist(err) {
		t.Errorf("missing man page /usr/share/man/man1/aether.1 in deb package")
	}
}
