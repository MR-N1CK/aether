package packaging_test

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReleaseVerificationRunner(t *testing.T) {
	root := findProjectRoot(t)
	scriptPath := filepath.Join(root, "scripts/verify-release.sh")

	info, err := os.Stat(scriptPath)
	if err != nil {
		t.Fatalf("scripts/verify-release.sh not found: %v", err)
	}

	if info.Mode()&0111 == 0 {
		t.Errorf("scripts/verify-release.sh is not executable")
	}

	// Verify content covers all 7 gates offline
	data, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("failed to read scripts/verify-release.sh: %v", err)
	}
	content := string(data)

	expectedGates := []string{
		"go test ./...",
		"go test -tags yara ./...",
		"go test -race -short ./...",
		"go test -v ./test/benchmark/...",
		"go test -v ./test/realworld/...",
		"go test -v ./test/packaging/...",
	}

	for _, g := range expectedGates {
		if !containsSubstr(content, g) {
			t.Errorf("scripts/verify-release.sh missing quality gate command: %s", g)
		}
	}
}

func containsSubstr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
