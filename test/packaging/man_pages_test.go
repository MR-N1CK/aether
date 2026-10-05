package packaging_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestManPages(t *testing.T) {
	root := findProjectRoot(t)
	manPages := []string{
		"man/man1/aether.1",
		"man/man1/aether-scan.1",
		"man/man1/aether-ack.1",
		"man/man1/aether-rules.1",
	}

	for _, relPath := range manPages {
		fullPath := filepath.Join(root, relPath)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			t.Fatalf("man page %s not found: %v", relPath, err)
		}

		content := string(data)
		if len(strings.TrimSpace(content)) == 0 {
			t.Errorf("man page %s is empty", relPath)
		}

		// Verify standard roff header
		if !strings.HasPrefix(content, ".TH ") {
			t.Errorf("man page %s missing standard .TH header", relPath)
		}

		// Test formatting with 'man -l' if available
		if manBin, err := exec.LookPath("man"); err == nil {
			cmd := exec.Command(manBin, "-l", fullPath)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("man -l failed on %s: %v (output: %s)", relPath, err, string(out))
			}
		}
	}

	// Specific assertion for verdict terms in aether-scan.1
	scanMan, err := os.ReadFile(filepath.Join(root, "man/man1/aether-scan.1"))
	if err != nil {
		t.Fatalf("failed to read aether-scan.1: %v", err)
	}
	scanStr := string(scanMan)
	requiredVerdicts := []string{"MALICIOUS", "SUSPICIOUS", "SAFE", "UNKNOWN"}
	for _, v := range requiredVerdicts {
		if !strings.Contains(scanStr, v) {
			t.Errorf("aether-scan.1 missing required verdict tier: %s", v)
		}
	}
}
