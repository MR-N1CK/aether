package packaging_test

import (
	"debug/elf"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func findProjectRoot(t *testing.T) string {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate project root containing go.mod from %s", dir)
		}
		dir = parent
	}
}

func TestPureGoBinaryContracts(t *testing.T) {
	root := findProjectRoot(t)
	pureBinaries := []struct {
		relPath string
		arch    elf.Machine
	}{
		{"bin/aether", elf.EM_X86_64},
		{"bin/aether-linux-amd64", elf.EM_X86_64},
		{"bin/aether-linux-arm64", elf.EM_AARCH64},
	}

	for _, tc := range pureBinaries {
		binPath := filepath.Join(root, tc.relPath)
		if _, err := os.Stat(binPath); os.IsNotExist(err) {
			t.Logf("Binary %s not found; skipping. Run make build-pure / make build-cross first.", tc.relPath)
			continue
		}

		t.Run(tc.relPath, func(t *testing.T) {
			f, err := elf.Open(binPath)
			if err != nil {
				t.Fatalf("failed to open ELF binary %s: %v", binPath, err)
			}
			defer f.Close()

			if f.Machine != tc.arch {
				t.Errorf("expected machine %v, got %v", tc.arch, f.Machine)
			}

			// Pure-Go static binary must not have dynamic library dependencies
			libs, err := f.ImportedLibraries()
			if err == nil && len(libs) > 0 {
				t.Errorf("pure-Go binary %s has unexpected dynamic library dependencies: %v", tc.relPath, libs)
			}
		})
	}
}

func TestStaticYaraBinaryContracts(t *testing.T) {
	root := findProjectRoot(t)
	yaraBinPath := filepath.Join(root, "bin/aether-yara-static")
	if _, err := os.Stat(yaraBinPath); os.IsNotExist(err) {
		t.Skip("Static YARA-X binary bin/aether-yara-static not found; skipping. Run make build-yara-static first.")
	}

	f, err := elf.Open(yaraBinPath)
	if err != nil {
		t.Fatalf("failed to open ELF binary %s: %v", yaraBinPath, err)
	}
	defer f.Close()

	if f.Machine != elf.EM_X86_64 {
		t.Errorf("YARA-X static binary must be x86_64, got machine %v", f.Machine)
	}

	libs, err := f.ImportedLibraries()
	if err != nil {
		t.Fatalf("failed to inspect imported libraries: %v", err)
	}

	// Verify libstdc++ is statically linked into the binary (not present in DT_NEEDED)
	for _, lib := range libs {
		if strings.Contains(lib, "libstdc++") {
			t.Errorf("libstdc++ should be statically bundled, but found dynamic dependency: %s", lib)
		}
		if strings.Contains(lib, "libyara_x") {
			t.Errorf("libyara_x_capi should be statically bundled, but found dynamic dependency: %s", lib)
		}
	}
}
