package scanner_test

import (
	"os"
	"path/filepath"
	"testing"

	"aether/internal/scanner"
)

func TestOpenReadOnly(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "sample.txt")
	content := []byte("forensic purity test")
	if err := os.WriteFile(testFile, content, 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Verify OpenReadOnly opens properly
	f, err := scanner.OpenReadOnly(testFile)
	if err != nil {
		t.Fatalf("OpenReadOnly failed: %v", err)
	}
	defer f.Close()

	// Verify write fails on read-only handle
	_, err = f.Write([]byte("malicious append"))
	if err == nil {
		t.Errorf("expected write to fail on read-only file handle, but succeeded")
	}

	// Verify ReadFileReadOnly reads content properly
	data, err := scanner.ReadFileReadOnly(testFile, 1024)
	if err != nil {
		t.Fatalf("ReadFileReadOnly failed: %v", err)
	}
	if string(data) != string(content) {
		t.Errorf("expected %q, got %q", string(content), string(data))
	}
}
