package packaging_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestStandaloneArchive(t *testing.T) {
	root := findProjectRoot(t)
	tarPath := filepath.Join(root, "dist/aether-1.0.0-linux-amd64.tar.gz")
	manifestPath := filepath.Join(root, "dist/release-manifest.json")
	shaSumsPath := filepath.Join(root, "dist/SHA256SUMS")

	if _, err := os.Stat(tarPath); os.IsNotExist(err) {
		t.Skip("dist/aether-1.0.0-linux-amd64.tar.gz not found; run make package first")
	}

	// 1. Verify SHA256SUMS covers 8 files
	sumsData, err := os.ReadFile(shaSumsPath)
	if err != nil {
		t.Fatalf("failed to read SHA256SUMS: %v", err)
	}
	sumsLines := strings.Split(strings.TrimSpace(string(sumsData)), "\n")
	if len(sumsLines) != 8 {
		t.Errorf("expected 8 lines in SHA256SUMS (7 packages + manifest), got %d:\n%s", len(sumsLines), string(sumsData))
	}

	// Verify SHA-256 of tarball matches line in SHA256SUMS
	f, err := os.Open(tarPath)
	if err != nil {
		t.Fatalf("failed to open tarball: %v", err)
	}
	defer f.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		t.Fatalf("failed to hash tarball: %v", err)
	}
	actualHash := hex.EncodeToString(hasher.Sum(nil))

	foundHash := false
	for _, line := range sumsLines {
		if strings.Contains(line, "aether-1.0.0-linux-amd64.tar.gz") && strings.HasPrefix(line, actualHash) {
			foundHash = true
			break
		}
	}
	if !foundHash {
		t.Errorf("computed hash %s not found in SHA256SUMS", actualHash)
	}

	// 2. Unpack tarball into temp directory and test execution
	tmpDir, err := os.MkdirTemp("", "aether-tar-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cmd := exec.Command("tar", "-xzf", tarPath, "-C", tmpDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to unpack tarball: %v (output: %s)", err, string(out))
	}

	extractedBin := filepath.Join(tmpDir, "aether/aether")
	if _, err := os.Stat(extractedBin); os.IsNotExist(err) {
		t.Fatalf("extracted binary %s not found", extractedBin)
	}

	cmd = exec.Command(extractedBin, "version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("extracted aether version failed: %v (output: %s)", err, string(out))
	}
	if !strings.Contains(string(out), "Aether Threat Hunter v1.0.0") {
		t.Errorf("unexpected version output from unpacked binary: %s", string(out))
	}

	// 3. Validate release-manifest.json
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read release-manifest.json: %v", err)
	}

	var manifest struct {
		SchemaVersion string `json:"schema_version"`
		Version       string `json:"version"`
		Artifacts     []struct {
			Name      string `json:"name"`
			Format    string `json:"format"`
			Variant   string `json:"variant"`
			SizeBytes int64  `json:"size_bytes"`
			SHA256    string `json:"sha256"`
		} `json:"artifacts"`
	}

	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatalf("invalid release-manifest.json: %v", err)
	}

	if manifest.SchemaVersion != "1.0.0" {
		t.Errorf("expected schema_version 1.0.0, got %s", manifest.SchemaVersion)
	}
	if len(manifest.Artifacts) != 7 {
		t.Errorf("manifest must contain exactly 7 software packages, got %d", len(manifest.Artifacts))
	}

	// Ensure manifest does NOT contain SHA256SUMS or itself
	manifestStr := string(manifestData)
	if strings.Contains(manifestStr, "SHA256SUMS") {
		t.Errorf("circular reference error: release-manifest.json must not reference SHA256SUMS")
	}
}
