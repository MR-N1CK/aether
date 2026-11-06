package pkgdb

import (
	"os"
	"strings"
	"testing"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
)

func TestBuildRpmMaps(t *testing.T) {
	pkgs := []rpmPkg{
		{
			name: "coreutils",
			files: []rpmFile{
				{path: "/usr/bin/ls", digest: "D41D8CD98F00B204E9800998ECF8427E", digestAlgo: rpmdb.PGPHASHALGO_MD5},
				{path: "/bin/ls", digest: "D41D8CD98F00B204E9800998ECF8427E", digestAlgo: rpmdb.PGPHASHALGO_MD5},
				{path: "/usr/share/doc/README", digest: "aaaa", digestAlgo: rpmdb.PGPHASHALGO_MD5}, // non-system: ownership only
				{path: "", digest: "bbbb", digestAlgo: rpmdb.PGPHASHALGO_MD5},                      // skipped
			},
		},
		{
			name: "glibc",
			files: []rpmFile{
				{path: "/usr/lib64/libc.so.6", digest: "ABCDEF", digestAlgo: rpmdb.PGPHASHALGO_SHA256},
				{path: "/usr/bin/getconf", digest: "", digestAlgo: rpmdb.PGPHASHALGO_SHA256}, // empty digest: ownership only
			},
		},
	}

	owner, md5s, sha256s := buildRpmMaps(pkgs)

	// Ownership: dual-key merged-/usr mapping.
	if got := owner["/usr/bin/ls"]; got != "coreutils" {
		t.Errorf("owner[/usr/bin/ls] = %q, want coreutils", got)
	}
	if got := owner["/bin/ls"]; got != "coreutils" {
		t.Errorf("legacy /bin/ls key must be stored too, got %q", got)
	}
	if got := owner["/usr/share/doc/README"]; got != "coreutils" {
		t.Errorf("non-system file must still be owned: %q", got)
	}
	if got := owner["/usr/lib64/libc.so.6"]; got != "glibc" {
		t.Errorf("owner[/usr/lib64/libc.so.6] = %q, want glibc", got)
	}

	// MD5 digests: system binaries only, lowercased.
	if got := md5s["/usr/bin/ls"]; got != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("md5[/usr/bin/ls] = %q (want lowercase digest)", got)
	}
	if _, ok := md5s["/usr/share/doc/README"]; ok {
		t.Error("non-system path must not enter the digest map")
	}
	if _, ok := md5s["/usr/lib64/libc.so.6"]; ok {
		t.Error("SHA-256 digest must not land in the MD5 map")
	}

	// SHA-256 digests: system binaries only, empty digests skipped.
	if got := sha256s["/usr/lib64/libc.so.6"]; got != "abcdef" {
		t.Errorf("sha256[/usr/lib64/libc.so.6] = %q, want abcdef", got)
	}
	if _, ok := sha256s["/usr/bin/getconf"]; ok {
		t.Error("empty digest must be skipped")
	}
}

func TestDB_VerifyDigestSHA256(t *testing.T) {
	root := t.TempDir()
	db := New(root)
	// Force init on an empty root (no package DBs found), then inject RPM
	// SHA-256 state directly — white-box, same package.
	_ = db.StatusNote()
	db.available = true
	db.digestSHA256Map["/usr/bin/signed"] = "cafe"
	db.digestSHA256Map["/usr/bin/other"] = "beef"

	// Mismatch: trojaned.
	match, expected, has := db.VerifyDigestSHA256("/usr/bin/signed", "dead")
	if has != true || match != false || expected != "cafe" {
		t.Fatalf("mismatch case = (%v, %q, %v), want (false, cafe, true)", match, expected, has)
	}

	// Match.
	if match, _, _ := db.VerifyDigestSHA256("/usr/bin/other", "BEEF"); !match {
		t.Error("case-insensitive SHA-256 match expected")
	}

	// Unowned file: no digest info -> pass.
	if match, _, has := db.VerifyDigestSHA256("/usr/bin/unknown", "dead"); has || !match {
		t.Error("unknown file must report no digest and pass")
	}

	// Merged-/usr normalization: /bin/signed resolves to /usr/bin/signed.
	if _, expected, has := db.VerifyDigestSHA256("/bin/signed", "dead"); !has || expected != "cafe" {
		t.Error("merged-/usr lookup failed for SHA-256 map")
	}
}

func TestPkgDB_RPMRealSystem(t *testing.T) {
	// Only meaningful on RPM-based hosts: detection prefers dpkg/pacman/apk,
	// so an RPM branch is only reachable when none of those exist.
	if _, err := os.Stat("/var/lib/dpkg/info"); err == nil {
		t.Skip("dpkg present: package detection resolves to dpkg before RPM")
	}
	found := false
	for _, dir := range []string{"/usr/lib/sysimage/rpm", "/var/lib/rpm"} {
		if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
			found = true
			break
		}
	}
	if !found {
		t.Skip("no RPM database on this host")
	}

	db := New("")
	if !db.IsAvailable() {
		t.Fatalf("expected real RPM db to load, note: %s", db.StatusNote())
	}
	if !strings.Contains(db.StatusNote(), "RPM database loaded") {
		t.Errorf("unexpected note: %s", db.StatusNote())
	}
}
