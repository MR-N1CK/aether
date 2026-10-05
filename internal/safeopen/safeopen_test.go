package safeopen_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"aether/internal/safeopen"
)

func TestResolveUnderRoot_ConfinementAndLoops(t *testing.T) {
	fakeRoot := t.TempDir()

	// 1. Create a sentinel file on the host OUTSIDE fakeRoot
	hostDir := t.TempDir()
	sentinelPath := filepath.Join(hostDir, "sentinel_host_secret.txt")
	if err := os.WriteFile(sentinelPath, []byte("HOST_SECRET_NEVER_READ"), 0600); err != nil {
		t.Fatalf("failed to write host sentinel: %v", err)
	}

	// 2. Setup directory tree in fakeRoot
	etcDir := filepath.Join(fakeRoot, "etc")
	if err := os.MkdirAll(etcDir, 0755); err != nil {
		t.Fatalf("failed to mkdir: %v", err)
	}
	subDir := filepath.Join(fakeRoot, "var/log")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("failed to mkdir: %v", err)
	}

	// Normal regular file
	normalFile := filepath.Join(etcDir, "normal.conf")
	if err := os.WriteFile(normalFile, []byte("normal_content"), 0644); err != nil {
		t.Fatalf("failed to write normal file: %v", err)
	}

	// (a) Absolute symlink: etc/shadow -> /etc/shadow (re-rooted in chroot, loops on self)
	if err := os.Symlink("/etc/shadow", filepath.Join(etcDir, "shadow")); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	// (b) Relative symlink: etc/passwd -> ../../../etc/passwd (cannot escape, loops on self)
	if err := os.Symlink("../../../etc/passwd", filepath.Join(etcDir, "passwd")); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	// (c) Symlink cycle: linkA -> linkB, linkB -> linkA
	if err := os.Symlink("linkB", filepath.Join(etcDir, "linkA")); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}
	if err := os.Symlink("linkA", filepath.Join(etcDir, "linkB")); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	// (d) Symlink pointing directly to host sentinel path (e.g. /tmp/.../sentinel_host_secret.txt)
	if err := os.Symlink(sentinelPath, filepath.Join(etcDir, "rogue_sentinel")); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	// Test 1: Normal file resolution
	hostPath, virtPath, isSym, err := safeopen.ResolveUnderRoot(fakeRoot, "/etc/normal.conf")
	if err != nil {
		t.Fatalf("expected nil error for normal file, got: %v", err)
	}
	if virtPath != "/etc/normal.conf" {
		t.Errorf("expected virtPath /etc/normal.conf, got: %q", virtPath)
	}
	if hostPath != normalFile {
		t.Errorf("expected hostPath %q, got: %q", normalFile, hostPath)
	}
	if isSym {
		t.Errorf("expected isSymlink=false for regular file")
	}

	// Test 2: Absolute symlink loop detection (etc/shadow -> /etc/shadow)
	_, _, isSym, err = safeopen.ResolveUnderRoot(fakeRoot, "/etc/shadow")
	if !errors.Is(err, safeopen.ErrSymlinkLoop) {
		t.Errorf("expected ErrSymlinkLoop for absolute symlink loop, got: %v", err)
	}
	if !isSym {
		t.Errorf("expected isSymlink=true")
	}

	// Test 3: Relative escaping symlink loop detection (etc/passwd -> ../../../etc/passwd)
	_, _, isSym, err = safeopen.ResolveUnderRoot(fakeRoot, "/etc/passwd")
	if !errors.Is(err, safeopen.ErrSymlinkLoop) {
		t.Errorf("expected ErrSymlinkLoop for climbing relative symlink loop, got: %v", err)
	}
	if !isSym {
		t.Errorf("expected isSymlink=true")
	}

	// Test 4: Mutual symlink cycle (linkA <-> linkB)
	_, _, isSym, err = safeopen.ResolveUnderRoot(fakeRoot, "/etc/linkA")
	if !errors.Is(err, safeopen.ErrSymlinkLoop) {
		t.Errorf("expected ErrSymlinkLoop for mutual cycle, got: %v", err)
	}

	// Test 5: Host isolation sentinel test
	// Reading rogue_sentinel MUST NOT read the host sentinel file!
	data, err := safeopen.ReadFileReadOnlyUnderRoot(fakeRoot, "/etc/rogue_sentinel", 1024)
	if err == nil {
		t.Fatalf("expected error reading rogue sentinel, but succeeded and got: %q", string(data))
	}
	if string(data) == "HOST_SECRET_NEVER_READ" {
		t.Fatalf("CRITICAL SECURITY FAILURE: Read host secret outside root!")
	}

	// Test 6: Climbing .. cannot escape root
	hostPath, virtPath, _, _ = safeopen.ResolveUnderRoot(fakeRoot, "../../../../../../../../../etc/normal.conf")
	if virtPath != "/etc/normal.conf" {
		t.Errorf("expected virtPath /etc/normal.conf, got: %q", virtPath)
	}
	if hostPath != normalFile {
		t.Errorf("expected hostPath %q, got: %q", normalFile, hostPath)
	}
}
