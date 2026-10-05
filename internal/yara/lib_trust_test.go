package yara

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type mockFileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	isDir   bool
	uid     uint32
}

func (m mockFileInfo) Name() string       { return m.name }
func (m mockFileInfo) Size() int64        { return m.size }
func (m mockFileInfo) Mode() fs.FileMode  { return m.mode }
func (m mockFileInfo) ModTime() time.Time { return m.modTime }
func (m mockFileInfo) IsDir() bool        { return m.isDir }
func (m mockFileInfo) Sys() any {
	return &syscall.Stat_t{
		Uid: m.uid,
	}
}

func TestEvaluateLibraryTrust(t *testing.T) {
	trustedMaps := `
7f5bf7600000-7f5bf7a00000 r--p 00000000 08:02 123456 /usr/local/lib/libyara_x_capi.so.1
7f5bf7a00000-7f5bf8000000 r-xp 00400000 08:02 123456 /usr/local/lib/libyara_x_capi.so.1
`
	homeMaps := `
7f5bf7600000-7f5bf7a00000 r--p 00000000 08:02 123456 /home/alice/.local/lib/libyara_x_capi.so.1
`
	symlinkMaps := `
7f5bf7600000-7f5bf7a00000 r--p 00000000 08:02 123456 /usr/local/lib/libyara_x_capi.so
`
	emptyMaps := `
7f5bf7600000-7f5bf7a00000 r--p 00000000 08:02 999999 /usr/lib/libc.so.6
`

	// Helper to create mock filesystem tree
	makeMockFS := func(nodes map[string]mockFileInfo) StatFunc {
		return func(path string) (os.FileInfo, error) {
			clean := filepath.Clean(path)
			if info, ok := nodes[clean]; ok {
				return info, nil
			}
			return nil, fmt.Errorf("file not found: %s", clean)
		}
	}

	trustedFS := map[string]mockFileInfo{
		"/":                                         {name: "/", mode: 0755 | os.ModeDir, isDir: true, uid: 0},
		"/usr":                                      {name: "usr", mode: 0755 | os.ModeDir, isDir: true, uid: 0},
		"/usr/bin":                                  {name: "bin", mode: 0755 | os.ModeDir, isDir: true, uid: 0},
		"/usr/bin/aether":                           {name: "aether", mode: 0755, isDir: false, uid: 0},
		"/usr/local":                                {name: "local", mode: 0755 | os.ModeDir, isDir: true, uid: 0},
		"/usr/local/bin":                            {name: "bin", mode: 0755 | os.ModeDir, isDir: true, uid: 0},
		"/usr/local/bin/aether":                     {name: "aether", mode: 0755, isDir: false, uid: 0},
		"/usr/local/lib":                            {name: "lib", mode: 0755 | os.ModeDir, isDir: true, uid: 0},
		"/usr/local/lib/libyara_x_capi.so.1":        {name: "libyara_x_capi.so.1", mode: 0755, isDir: false, uid: 0},
		"/usr/local/lib/libyara_x_capi.so":          {name: "libyara_x_capi.so", mode: 0755, isDir: false, uid: 0},
		"/home":                                     {name: "home", mode: 0755 | os.ModeDir, isDir: true, uid: 0},
		"/home/alice":                               {name: "alice", mode: 0750 | os.ModeDir, isDir: true, uid: 1000},
		"/home/alice/.local":                        {name: ".local", mode: 0755 | os.ModeDir, isDir: true, uid: 1000},
		"/home/alice/.local/lib":                    {name: "lib", mode: 0755 | os.ModeDir, isDir: true, uid: 1000},
		"/home/alice/.local/lib/libyara_x_capi.so.1": {name: "libyara_x_capi.so.1", mode: 0755, isDir: false, uid: 1000},
	}

	identityEval := func(p string) (string, error) { return p, nil }

	dynamicParser := func(exePath string) (*ElfLinkage, error) {
		return &ElfLinkage{
			NeededLibraries: []string{"libyara_x_capi.so.1", "libc.so.6"},
			Runpaths:        []string{"/usr/local/lib"},
		}, nil
	}

	staticParser := func(exePath string) (*ElfLinkage, error) {
		return &ElfLinkage{
			NeededLibraries: []string{"libc.so.6"},
			Runpaths:        nil,
		}, nil
	}

	t.Run("NonRootAllowedEvenWithDevBuild", func(t *testing.T) {
		trusted, reason := EvaluateLibraryTrust(
			1000,
			true, // devRpath = true
			"/usr/local/bin/aether",
			dynamicParser,
			homeMaps,
			func(k string) string { return "" },
			makeMockFS(trustedFS),
			identityEval,
		)
		if !trusted {
			t.Errorf("expected non-root to be trusted, got false: %s", reason)
		}
	})

	t.Run("StaticBuildPassesWithoutMaps", func(t *testing.T) {
		trusted, reason := EvaluateLibraryTrust(
			0,
			false,
			"/usr/local/bin/aether",
			staticParser, // No libyara_x_capi in NeededLibraries
			emptyMaps,
			func(k string) string { return "" },
			makeMockFS(trustedFS),
			identityEval,
		)
		if !trusted {
			t.Errorf("expected static build to be trusted even with empty maps, got false: %s", reason)
		}
		if reason != "" {
			t.Errorf("unexpected reason for static build: %s", reason)
		}
	})

	t.Run("RootRejectsDevRpath", func(t *testing.T) {
		trusted, reason := EvaluateLibraryTrust(
			0,
			true, // devRpath = true
			"/usr/local/bin/aether",
			dynamicParser,
			trustedMaps,
			func(k string) string { return "" },
			makeMockFS(trustedFS),
			identityEval,
		)
		if trusted {
			t.Errorf("expected root to reject devRpath build, got true")
		}
		if !strings.Contains(reason, "dev rpath build not permitted") {
			t.Errorf("unexpected reason: %s", reason)
		}
	})

	t.Run("RootRejectsLDLibraryPath", func(t *testing.T) {
		trusted, reason := EvaluateLibraryTrust(
			0,
			false,
			"/usr/local/bin/aether",
			dynamicParser,
			trustedMaps,
			func(k string) string {
				if k == "LD_LIBRARY_PATH" {
					return "/some/dir"
				}
				return ""
			},
			makeMockFS(trustedFS),
			identityEval,
		)
		if trusted {
			t.Errorf("expected rejection when LD_LIBRARY_PATH is set, got true")
		}
		if reason != "library path not trusted" {
			t.Errorf("expected 'library path not trusted', got: %s", reason)
		}
	})

	t.Run("RootRejectsLDPreload", func(t *testing.T) {
		trusted, reason := EvaluateLibraryTrust(
			0,
			false,
			"/usr/local/bin/aether",
			dynamicParser,
			trustedMaps,
			func(k string) string {
				if k == "LD_PRELOAD" {
					return "/some/lib.so"
				}
				return ""
			},
			makeMockFS(trustedFS),
			identityEval,
		)
		if trusted {
			t.Errorf("expected rejection when LD_PRELOAD is set, got true")
		}
		if reason != "library path not trusted" {
			t.Errorf("expected 'library path not trusted', got: %s", reason)
		}
	})

	t.Run("RootRejectsExecutablePath", func(t *testing.T) {
		trusted, reason := EvaluateLibraryTrust(
			0,
			false,
			"/home/alice/aether", // not root-owned
			dynamicParser,
			trustedMaps,
			func(k string) string { return "" },
			makeMockFS(trustedFS),
			identityEval,
		)
		if trusted {
			t.Errorf("expected rejection when executable is not in root path, got true")
		}
		if reason != "executable not in a root-owned path" {
			t.Errorf("expected 'executable not in a root-owned path', got: %s", reason)
		}
	})

	t.Run("RootRejectsUnparsableELFLinkage", func(t *testing.T) {
		unparsableParser := func(exePath string) (*ElfLinkage, error) {
			return nil, errors.New("corrupt ELF header")
		}
		trusted, reason := EvaluateLibraryTrust(
			0,
			false,
			"/usr/local/bin/aether",
			unparsableParser,
			trustedMaps,
			func(k string) string { return "" },
			makeMockFS(trustedFS),
			identityEval,
		)
		if trusted {
			t.Errorf("expected rejection when ELF cannot be parsed as root, got true")
		}
		if reason != "cannot verify linkage" {
			t.Errorf("expected 'cannot verify linkage', got: %s", reason)
		}
	})

	t.Run("RootRejectsHomeRunpath", func(t *testing.T) {
		homeRunpathParser := func(exePath string) (*ElfLinkage, error) {
			return &ElfLinkage{
				NeededLibraries: []string{"libyara_x_capi.so.1"},
				Runpaths:        []string{"/usr/local/lib", "/home/alice/.local/lib"},
			}, nil
		}
		trusted, reason := EvaluateLibraryTrust(
			0,
			false,
			"/usr/local/bin/aether",
			homeRunpathParser,
			trustedMaps,
			func(k string) string { return "" },
			makeMockFS(trustedFS),
			identityEval,
		)
		if trusted {
			t.Errorf("expected rejection for home RUNPATH, got true")
		}
		if reason != "RUNPATH not trusted" {
			t.Errorf("expected 'RUNPATH not trusted', got: %s", reason)
		}
	})

	t.Run("RootRejectsLibMissingFromMaps", func(t *testing.T) {
		trusted, reason := EvaluateLibraryTrust(
			0,
			false,
			"/usr/local/bin/aether",
			dynamicParser, // libyara_x_capi is NEEDED
			emptyMaps,     // missing from maps
			func(k string) string { return "" },
			makeMockFS(trustedFS),
			identityEval,
		)
		if trusted {
			t.Errorf("expected rejection when lib is missing from maps, got true")
		}
		if reason != "library path not trusted" {
			t.Errorf("expected 'library path not trusted', got: %s", reason)
		}
	})

	t.Run("RootRejectsHomeDirLib", func(t *testing.T) {
		trusted, reason := EvaluateLibraryTrust(
			0,
			false,
			"/usr/local/bin/aether",
			dynamicParser,
			homeMaps,
			func(k string) string { return "" },
			makeMockFS(trustedFS),
			identityEval,
		)
		if trusted {
			t.Errorf("expected rejection for home directory library, got true")
		}
		if reason != "library path not trusted" {
			t.Errorf("expected 'library path not trusted', got: %s", reason)
		}
	})

	t.Run("RootRejectsGroupWritableAncestor", func(t *testing.T) {
		insecureFS := make(map[string]mockFileInfo)
		for k, v := range trustedFS {
			insecureFS[k] = v
		}
		// Make /usr/local group-writable (0775)
		insecureFS["/usr/local"] = mockFileInfo{name: "local", mode: 0775 | os.ModeDir, isDir: true, uid: 0}

		noRunpathParser := func(exePath string) (*ElfLinkage, error) {
			return &ElfLinkage{
				NeededLibraries: []string{"libyara_x_capi.so.1", "libc.so.6"},
				Runpaths:        nil,
			}, nil
		}

		trusted, reason := EvaluateLibraryTrust(
			0,
			false,
			"/usr/bin/aether",
			noRunpathParser,
			trustedMaps,
			func(k string) string { return "" },
			makeMockFS(insecureFS),
			identityEval,
		)
		if trusted {
			t.Errorf("expected rejection for group-writable ancestor, got true")
		}
		if reason != "library path not trusted" {
			t.Errorf("expected 'library path not trusted', got: %s", reason)
		}
	})

	t.Run("RootRejectsSymlinkToUntrustedPath", func(t *testing.T) {
		trusted, reason := EvaluateLibraryTrust(
			0,
			false,
			"/usr/local/bin/aether",
			dynamicParser,
			symlinkMaps,
			func(k string) string { return "" },
			makeMockFS(trustedFS),
			func(p string) (string, error) {
				if p == "/usr/local/lib/libyara_x_capi.so" {
					return "/home/alice/.local/lib/libyara_x_capi.so.1", nil
				}
				return p, nil
			},
		)
		if trusted {
			t.Errorf("expected rejection for symlink pointing to untrusted path, got true")
		}
		if reason != "library path not trusted" {
			t.Errorf("expected 'library path not trusted', got: %s", reason)
		}
	})

	t.Run("FullyTrustedPathPasses", func(t *testing.T) {
		trusted, reason := EvaluateLibraryTrust(
			0,
			false,
			"/usr/local/bin/aether",
			dynamicParser,
			trustedMaps,
			func(k string) string { return "" },
			makeMockFS(trustedFS),
			identityEval,
		)
		if !trusted {
			t.Errorf("expected trusted path to pass, got false: %s", reason)
		}
		if reason != "" {
			t.Errorf("unexpected reason: %s", reason)
		}
	})

	t.Run("VerifyRootOwnedPathHelper", func(t *testing.T) {
		trusted, reason := VerifyRootOwnedPath("/usr/local/lib/libyara_x_capi.so.1", makeMockFS(trustedFS), identityEval)
		if !trusted {
			t.Errorf("expected root-owned path to pass, got false: %s", reason)
		}

		userBinaryFS := map[string]mockFileInfo{
			"/":                 {name: "/", mode: 0755 | os.ModeDir, isDir: true, uid: 0},
			"/home":             {name: "home", mode: 0755 | os.ModeDir, isDir: true, uid: 0},
			"/home/nick":        {name: "nick", mode: 0755 | os.ModeDir, isDir: true, uid: 1000},
			"/home/nick/aether": {name: "aether", mode: 0755, isDir: false, uid: 1000},
		}
		trustedUserBin, userBinReason := VerifyRootOwnedPath("/home/nick/aether", makeMockFS(userBinaryFS), identityEval)
		if trustedUserBin {
			t.Errorf("expected user-owned binary to be rejected for root execution")
		}
		if !strings.Contains(userBinReason, "UID 1000, expected 0") {
			t.Errorf("unexpected reason for user-owned binary: %s", userBinReason)
		}
	})

	t.Run("DefaultElfParser_OnCurrentBinary", func(t *testing.T) {
		linkage, err := DefaultElfParser("/proc/self/exe")
		if err != nil {
			t.Logf("DefaultElfParser on /proc/self/exe returned error (allowed in test environments): %v", err)
		} else {
			t.Logf("DefaultElfParser parsed /proc/self/exe: Needed=%v, Runpaths=%v", linkage.NeededLibraries, linkage.Runpaths)
		}
	})
}

func TestRefusal_ExecutableNotInRootOwnedPath(t *testing.T) {
	mockFS := func(path string) (os.FileInfo, error) {
		if filepath.Clean(path) == "/home/user/aether" {
			return &mockFileInfo{name: "aether", mode: 0755, isDir: false, uid: 1000}, nil
		}
		return &mockFileInfo{name: "dir", mode: 0755 | os.ModeDir, isDir: true, uid: 0}, nil
	}
	identityEval := func(p string) (string, error) { return p, nil }
	parser := func(p string) (*ElfLinkage, error) {
		return &ElfLinkage{NeededLibraries: []string{"libyara_x_capi.so.1"}}, nil
	}

	emptyEnv := func(k string) string { return "" }

	trusted, reason := EvaluateLibraryTrust(0, false, "/home/user/aether", parser, "", emptyEnv, mockFS, identityEval)
	if trusted {
		t.Fatal("expected refusal for user-owned executable")
	}
	expected := "executable not in a root-owned path"
	if reason != expected {
		t.Fatalf("expected reason %q, got %q", expected, reason)
	}
}

func TestRefusal_LibraryPathNotTrusted(t *testing.T) {
	trustedFS := func(path string) (os.FileInfo, error) {
		clean := filepath.Clean(path)
		if strings.HasPrefix(clean, "/home/user") {
			return &mockFileInfo{name: "untrusted", mode: 0755, isDir: false, uid: 1000}, nil
		}
		return &mockFileInfo{name: "root", mode: 0755, isDir: false, uid: 0}, nil
	}
	identityEval := func(p string) (string, error) { return p, nil }
	parser := func(p string) (*ElfLinkage, error) {
		return &ElfLinkage{NeededLibraries: []string{"libyara_x_capi.so.1"}}, nil
	}
	untrustedMaps := "7f5bf7600000-7f5bf7a00000 r-xp 00000000 08:02 123 /home/user/libyara_x_capi.so.1\n"
	emptyEnv := func(k string) string { return "" }

	trusted, reason := EvaluateLibraryTrust(0, false, "/usr/bin/aether", parser, untrustedMaps, emptyEnv, trustedFS, identityEval)
	if trusted {
		t.Fatal("expected refusal for untrusted library path in maps")
	}
	expected := "library path not trusted"
	if reason != expected {
		t.Fatalf("expected reason %q, got %q", expected, reason)
	}
}

func TestRefusal_RunpathNotTrusted(t *testing.T) {
	mockFS := func(path string) (os.FileInfo, error) {
		clean := filepath.Clean(path)
		if strings.HasPrefix(clean, "/home/user") {
			return &mockFileInfo{name: "home", mode: 0755 | os.ModeDir, isDir: true, uid: 1000}, nil
		}
		return &mockFileInfo{name: "root", mode: 0755 | os.ModeDir, isDir: true, uid: 0}, nil
	}
	identityEval := func(p string) (string, error) { return p, nil }
	parser := func(p string) (*ElfLinkage, error) {
		return &ElfLinkage{
			NeededLibraries: []string{"libyara_x_capi.so.1"},
			Runpaths:        []string{"/home/user/.local/lib"},
		}, nil
	}
	emptyEnv := func(k string) string { return "" }

	trusted, reason := EvaluateLibraryTrust(0, false, "/usr/bin/aether", parser, "", emptyEnv, mockFS, identityEval)
	if trusted {
		t.Fatal("expected refusal for untrusted RUNPATH")
	}
	expected := "RUNPATH not trusted"
	if reason != expected {
		t.Fatalf("expected reason %q, got %q", expected, reason)
	}
}

func TestRefusal_CannotVerifyLinkage(t *testing.T) {
	mockFS := func(path string) (os.FileInfo, error) {
		return &mockFileInfo{name: "file", mode: 0755, isDir: false, uid: 0}, nil
	}
	identityEval := func(p string) (string, error) { return p, nil }
	brokenParser := func(p string) (*ElfLinkage, error) {
		return nil, errors.New("cannot open ELF binary")
	}
	emptyEnv := func(k string) string { return "" }

	trusted, reason := EvaluateLibraryTrust(0, false, "/usr/bin/aether", brokenParser, "", emptyEnv, mockFS, identityEval)
	if trusted {
		t.Fatal("expected refusal when linkage cannot be verified")
	}
	expected := "cannot verify linkage"
	if reason != expected {
		t.Fatalf("expected reason %q, got %q", expected, reason)
	}
}


