package packaging_test

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestReproducibility(t *testing.T) {
	root := findProjectRoot(t)

	// Create two isolated temporary build directories
	tmpDir1, err := os.MkdirTemp("", "aether-repro-1-*")
	if err != nil {
		t.Fatalf("failed to create temp dir 1: %v", err)
	}
	defer os.RemoveAll(tmpDir1)

	tmpDir2, err := os.MkdirTemp("", "aether-repro-2-*")
	if err != nil {
		t.Fatalf("failed to create temp dir 2: %v", err)
	}
	defer os.RemoveAll(tmpDir2)

	fixedEpoch := "1760000000"
	fixedDate := "2025-10-09T08:53:20Z"
	fixedCommit := "4ac64f4"
	ldflags := "-s -w -X 'main.version=1.0.0' -X 'main.commit=" + fixedCommit + "' -X 'main.buildDate=" + fixedDate + "'"

	bin1 := filepath.Join(tmpDir1, "aether")
	bin2 := filepath.Join(tmpDir2, "aether")

	// Build 1
	cmd1 := exec.Command("go", "build", "-trimpath", "-ldflags="+ldflags, "-o", bin1, "./cmd/aether")
	cmd1.Dir = root
	cmd1.Env = append(os.Environ(), "CGO_ENABLED=0", "SOURCE_DATE_EPOCH="+fixedEpoch)
	if out, err := cmd1.CombinedOutput(); err != nil {
		t.Fatalf("build 1 failed: %v (output: %s)", err, string(out))
	}

	// Build 2
	cmd2 := exec.Command("go", "build", "-trimpath", "-ldflags="+ldflags, "-o", bin2, "./cmd/aether")
	cmd2.Dir = root
	cmd2.Env = append(os.Environ(), "CGO_ENABLED=0", "SOURCE_DATE_EPOCH="+fixedEpoch)
	if out, err := cmd2.CombinedOutput(); err != nil {
		t.Fatalf("build 2 failed: %v (output: %s)", err, string(out))
	}

	hashFile := func(path string) string {
		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("failed to open %s: %v", path, err)
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			t.Fatalf("failed to hash %s: %v", path, err)
		}
		return hex.EncodeToString(h.Sum(nil))
	}

	hash1 := hashFile(bin1)
	hash2 := hashFile(bin2)

	if hash1 != hash2 {
		t.Errorf("non-deterministic build detected! Hash 1: %s, Hash 2: %s", hash1, hash2)
	} else {
		t.Logf("Deterministic build verified: %s", hash1)
	}
}
