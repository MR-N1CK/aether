package packaging_test

import (
	"debug/elf"
	"os"
	"path/filepath"
	"testing"
)

func TestDistroCompatibility(t *testing.T) {
	root := findProjectRoot(t)

	// Pure-Go binary check
	pureBin := filepath.Join(root, "bin/aether")
	if _, err := os.Stat(pureBin); os.IsNotExist(err) {
		t.Skip("bin/aether not found; run make build-pure first")
	}

	f, err := elf.Open(pureBin)
	if err != nil {
		t.Fatalf("failed to open ELF binary: %v", err)
	}
	defer f.Close()

	// Verify pure-Go has no PT_INTERP (completely independent of libc/musl)
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_INTERP {
			t.Errorf("pure-Go static binary must not contain PT_INTERP interpreter")
		}
	}
}
