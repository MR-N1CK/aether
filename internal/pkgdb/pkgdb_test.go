package pkgdb_test

import (
	"os"
	"path/filepath"
	"testing"

	"aether/internal/pkgdb"
)

func TestPkgDB_Debian(t *testing.T) {
	root := t.TempDir()

	dpkgInfo := filepath.Join(root, "var/lib/dpkg/info")
	if err := os.MkdirAll(dpkgInfo, 0755); err != nil {
		t.Fatal(err)
	}

	// 1. Standard list file
	coreutilsList := filepath.Join(dpkgInfo, "coreutils.list")
	coreutilsContent := `/bin/ls
/bin/cat
/usr/bin/wc
/etc/coreutils.conf
`
	if err := os.WriteFile(coreutilsList, []byte(coreutilsContent), 0644); err != nil {
		t.Fatal(err)
	}

	// 2. Arch-qualified list file: libc6:amd64.list
	libc6List := filepath.Join(dpkgInfo, "libc6:amd64.list")
	libc6Content := `/lib/x86_64-linux-gnu/libc.so.6
/usr/lib/locale
`
	if err := os.WriteFile(libc6List, []byte(libc6Content), 0644); err != nil {
		t.Fatal(err)
	}

	// 3. Diversions
	diversionsPath := filepath.Join(root, "var/lib/dpkg/diversions")
	diversionsContent := `/bin/sh
/bin/sh.distrib
dash
`
	if err := os.WriteFile(diversionsPath, []byte(diversionsContent), 0644); err != nil {
		t.Fatal(err)
	}

	db := pkgdb.New(root)
	if !db.IsAvailable() {
		t.Fatalf("expected db to be available, got status: %s", db.StatusNote())
	}

	// Check coreutils with merged-/usr normalization
	// Looking up /bin/ls or /usr/bin/ls must both return "coreutils"
	if pkg, ok := db.Owner("/bin/ls"); !ok || pkg != "coreutils" {
		t.Errorf("expected /bin/ls -> coreutils, got %q (ok=%v)", pkg, ok)
	}
	if pkg, ok := db.Owner("/usr/bin/ls"); !ok || pkg != "coreutils" {
		t.Errorf("expected /usr/bin/ls -> coreutils, got %q (ok=%v)", pkg, ok)
	}
	if pkg, ok := db.Owner("/usr/bin/wc"); !ok || pkg != "coreutils" {
		t.Errorf("expected /usr/bin/wc -> coreutils, got %q (ok=%v)", pkg, ok)
	}

	// Check arch-qualified package libc6
	if pkg, ok := db.Owner("/lib/x86_64-linux-gnu/libc.so.6"); !ok || pkg != "libc6" {
		t.Errorf("expected libc6, got %q (ok=%v)", pkg, ok)
	}
	// Merged-/usr /usr/lib/...
	if pkg, ok := db.Owner("/usr/lib/x86_64-linux-gnu/libc.so.6"); !ok || pkg != "libc6" {
		t.Errorf("expected merged-/usr /usr/lib/... -> libc6, got %q (ok=%v)", pkg, ok)
	}

	// Check diverted file
	if pkg, ok := db.Owner("/bin/sh"); !ok || pkg != "dash" {
		t.Errorf("expected diversion /bin/sh -> dash, got %q (ok=%v)", pkg, ok)
	}
	if pkg, ok := db.Owner("/usr/bin/sh.distrib"); !ok || pkg != "dash" {
		t.Errorf("expected diversion /usr/bin/sh.distrib -> dash, got %q (ok=%v)", pkg, ok)
	}

	// Unowned path
	if pkg, ok := db.Owner("/usr/local/bin/custom"); ok {
		t.Errorf("expected unowned path to return false, got %q", pkg)
	}
}

func TestPkgDB_Pacman(t *testing.T) {
	root := t.TempDir()

	pacmanLocal := filepath.Join(root, "var/lib/pacman/local/systemd-255.4-1")
	if err := os.MkdirAll(pacmanLocal, 0755); err != nil {
		t.Fatal(err)
	}

	filesPath := filepath.Join(pacmanLocal, "files")
	filesContent := `%FILES%
usr/
usr/bin/
usr/bin/systemctl
usr/lib/systemd/system/
usr/lib/systemd/system/systemd-journald.service
`
	if err := os.WriteFile(filesPath, []byte(filesContent), 0644); err != nil {
		t.Fatal(err)
	}

	db := pkgdb.New(root)
	if !db.IsAvailable() {
		t.Fatalf("expected pacman db to be available, got status: %s", db.StatusNote())
	}

	if pkg, ok := db.Owner("/usr/bin/systemctl"); !ok || pkg != "systemd" {
		t.Errorf("expected /usr/bin/systemctl -> systemd, got %q (ok=%v)", pkg, ok)
	}
	if pkg, ok := db.Owner("/bin/systemctl"); !ok || pkg != "systemd" {
		t.Errorf("expected /bin/systemctl -> systemd (merged-/usr), got %q (ok=%v)", pkg, ok)
	}
	if pkg, ok := db.Owner("/usr/lib/systemd/system/systemd-journald.service"); !ok || pkg != "systemd" {
		t.Errorf("expected unit file -> systemd, got %q (ok=%v)", pkg, ok)
	}
}

func TestPkgDB_RPMGracefulDegradation(t *testing.T) {
	root := t.TempDir()

	rpmDir := filepath.Join(root, "var/lib/rpm")
	if err := os.MkdirAll(rpmDir, 0755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(rpmDir, "rpmdb.sqlite"), []byte("sqlite_rpm"), 0644)

	db := pkgdb.New(root)
	if db.IsAvailable() {
		t.Fatalf("expected RPM db to be unavailable in pure Go")
	}
	if !filepath.IsAbs(root) {
		t.Errorf("root should be absolute")
	}
	if db.StatusNote() != "RPM package database pure-Go reader unavailable; skipping package ownership scoring" {
		t.Errorf("unexpected status note: %s", db.StatusNote())
	}
}

func TestPkgDB_RealSystemRoot(t *testing.T) {
	if _, err := os.Stat("/var/lib/dpkg/info"); os.IsNotExist(err) {
		t.Skip("skipping real system root test: /var/lib/dpkg/info does not exist on this host")
	}

	db := pkgdb.New("")
	if !db.IsAvailable() {
		t.Fatalf("expected real system root pkgdb to be available, got status: %s", db.StatusNote())
	}

	// Test standard system paths
	testPaths := []string{"/bin/bash", "/bin/sh", "/usr/bin/dpkg", "/bin/ls"}
	foundAny := false
	for _, p := range testPaths {
		if pkg, ok := db.Owner(p); ok {
			foundAny = true
			t.Logf("verified ownership on real host: %s -> %s", p, pkg)
			break
		}
	}
	if !foundAny {
		t.Errorf("expected at least one standard system file to be owned by an installed package")
	}
}

func TestPkgDB_VerifyDigest(t *testing.T) {
	root := t.TempDir()

	dpkgInfo := filepath.Join(root, "var/lib/dpkg/info")
	if err := os.MkdirAll(dpkgInfo, 0755); err != nil {
		t.Fatal(err)
	}

	// Create list file
	coreutilsList := filepath.Join(dpkgInfo, "coreutils.list")
	coreutilsContent := `/bin/ls
/usr/bin/wc
/etc/coreutils.conf
`
	if err := os.WriteFile(coreutilsList, []byte(coreutilsContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Create md5sums file (format: 32-char hex md5, two spaces, path relative to root without leading slash)
	coreutilsMd5sums := filepath.Join(dpkgInfo, "coreutils.md5sums")
	md5Content := `d41d8cd98f00b204e9800998ecf8427e  bin/ls
0123456789abcdef0123456789abcdef  usr/bin/wc
`
	if err := os.WriteFile(coreutilsMd5sums, []byte(md5Content), 0644); err != nil {
		t.Fatal(err)
	}

	db := pkgdb.New(root)
	if !db.IsAvailable() {
		t.Fatalf("expected db to be available, got status: %s", db.StatusNote())
	}

	// 1. Exact match
	match, expected, hasDigest := db.VerifyDigest("/bin/ls", "d41d8cd98f00b204e9800998ecf8427e")
	if !hasDigest || !match || expected != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("expected match for /bin/ls, got match=%v, expected=%q, hasDigest=%v", match, expected, hasDigest)
	}

	// 2. Merged-/usr resolution match (/bin/ls -> /usr/bin/ls)
	match, expected, hasDigest = db.VerifyDigest("/usr/bin/ls", "d41d8cd98f00b204e9800998ecf8427e")
	if !hasDigest || !match || expected != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("expected match for /usr/bin/ls, got match=%v, expected=%q, hasDigest=%v", match, expected, hasDigest)
	}

	// 3. Case insensitivity
	match, expected, hasDigest = db.VerifyDigest("/bin/ls", "D41D8CD98F00B204E9800998ECF8427E")
	if !hasDigest || !match {
		t.Errorf("expected case-insensitive match for /bin/ls, got match=%v, hasDigest=%v", match, hasDigest)
	}

	// 4. Mismatch (trojaned binary)
	match, expected, hasDigest = db.VerifyDigest("/bin/ls", "deadbeefdeadbeefdeadbeefdeadbeef")
	if !hasDigest || match || expected != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("expected mismatch for /bin/ls, got match=%v, expected=%q, hasDigest=%v", match, expected, hasDigest)
	}

	// 5. Owned file but no digest recorded in .md5sums (e.g. config file)
	match, expected, hasDigest = db.VerifyDigest("/etc/coreutils.conf", "d41d8cd98f00b204e9800998ecf8427e")
	if hasDigest || !match || expected != "" {
		t.Errorf("expected hasDigest=false for file without digest entry, got match=%v, expected=%q, hasDigest=%v", match, expected, hasDigest)
	}

	// 6. Unknown file
	match, expected, hasDigest = db.VerifyDigest("/usr/local/bin/custom", "d41d8cd98f00b204e9800998ecf8427e")
	if hasDigest || !match || expected != "" {
		t.Errorf("expected hasDigest=false for unknown file, got match=%v, expected=%q, hasDigest=%v", match, expected, hasDigest)
	}
}
