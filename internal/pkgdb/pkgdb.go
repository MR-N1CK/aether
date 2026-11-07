package pkgdb

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	// Register the pure-Go "sqlite" driver: go-rpmdb's sqlite backend calls
	// sql.Open("sqlite", …) but ships no driver import of its own. Without
	// this blank import every modern RPM database (rpmdb.sqlite, the
	// Fedora/RHEL 9+ default) fails with sql: unknown driver "sqlite".
	_ "modernc.org/sqlite"

	"aether/internal/safeopen"
)

// PackageDB abstracts package ownership lookups across Linux distributions.
type PackageDB interface {
	// Owner returns the package owning the given file path, if known.
	Owner(path string) (string, bool)
	// VerifyDigest verifies whether actualMD5 matches the expected package checksum.
	// Returns (match, expectedMD5, hasDigest).
	VerifyDigest(path string, actualMD5 string) (bool, string, bool)
	// VerifyDigestSHA256 verifies whether actualSHA256 matches the expected
	// package checksum for databases recording SHA-256 file digests (the
	// rpm >= 4.15 default on Fedora/RHEL 9+). Returns (match, expected, hasDigest).
	VerifyDigestSHA256(path string, actualSHA256 string) (bool, string, bool)
	// IsAvailable returns true if a supported package database was found and loaded.
	IsAvailable() bool
	// StatusNote returns informational notes about the package DB state (e.g. RPM unavailable).
	StatusNote() string
}

// DB is a thread-safe, pure Go package database reader.
type DB struct {
	rootFS          string
	once            sync.Once
	available       bool
	statusNote      string
	ownerMap        map[string]string // normalized path -> package name
	digestMap       map[string]string // normalized path -> expected md5 hash
	digestSHA256Map map[string]string // normalized path -> expected sha256 hash (RPM)
}

// New creates a new PackageDB rooted at rootFS (empty string for system root "/").
func New(rootFS string) *DB {
	return &DB{
		rootFS:          rootFS,
		ownerMap:        make(map[string]string),
		digestMap:       make(map[string]string),
		digestSHA256Map: make(map[string]string),
	}
}

// NormalizePath normalizes merged-/usr paths to /usr equivalents so lookups match
// regardless of whether paths use traditional /bin or merged /usr/bin.
func NormalizePath(p string) string {
	cleaned := filepath.Clean(p)
	if cleaned == "/" {
		return "/"
	}

	if strings.HasPrefix(cleaned, "/bin/") {
		return "/usr/bin/" + strings.TrimPrefix(cleaned, "/bin/")
	}
	if cleaned == "/bin" {
		return "/usr/bin"
	}
	if strings.HasPrefix(cleaned, "/sbin/") {
		return "/usr/sbin/" + strings.TrimPrefix(cleaned, "/sbin/")
	}
	if cleaned == "/sbin" {
		return "/usr/sbin"
	}
	if strings.HasPrefix(cleaned, "/lib/") {
		return "/usr/lib/" + strings.TrimPrefix(cleaned, "/lib/")
	}
	if cleaned == "/lib" {
		return "/usr/lib"
	}
	if strings.HasPrefix(cleaned, "/lib64/") {
		return "/usr/lib64/" + strings.TrimPrefix(cleaned, "/lib64/")
	}
	if cleaned == "/lib64" {
		return "/usr/lib64"
	}
	return cleaned
}

func isSystemBinaryPath(norm string) bool {
	return strings.HasPrefix(norm, "/usr/bin/") ||
		strings.HasPrefix(norm, "/usr/sbin/") ||
		strings.HasPrefix(norm, "/bin/") ||
		strings.HasPrefix(norm, "/sbin/") ||
		strings.HasPrefix(norm, "/usr/lib/") ||
		strings.HasPrefix(norm, "/usr/lib64/") ||
		strings.HasPrefix(norm, "/usr/libexec/") ||
		strings.HasPrefix(norm, "/lib/") ||
		strings.HasPrefix(norm, "/lib64/")
}

// resolve translates a virtual absolute path to the corresponding path under rootFS.
func (d *DB) resolve(subPath string) string {
	hostPath, _, _, err := safeopen.ResolveUnderRoot(d.rootFS, subPath)
	if err != nil {
		if d.rootFS == "" || d.rootFS == "/" {
			return "/" + strings.TrimPrefix(subPath, "/")
		}
		return filepath.Join(d.rootFS, strings.TrimPrefix(subPath, "/"))
	}
	return hostPath
}

// init loads the package database once in a thread-safe manner.
func (d *DB) init() {
	d.once.Do(func() {
		// 1. Check for Debian / Ubuntu (/var/lib/dpkg/info)
		dpkgInfoDir := d.resolve("/var/lib/dpkg/info")
		if stat, err := os.Stat(dpkgInfoDir); err == nil && stat.IsDir() {
			d.loadDpkg(dpkgInfoDir)
			return
		}

		// 2. Check for Arch Linux / Pacman (/var/lib/pacman/local)
		pacmanDir := d.resolve("/var/lib/pacman/local")
		if stat, err := os.Stat(pacmanDir); err == nil && stat.IsDir() {
			d.loadPacman(pacmanDir)
			return
		}

		// 3. Check for Alpine Linux (/lib/apk/db/installed or /var/lib/apk/db/installed)
		apkInstalled := d.resolve("/lib/apk/db/installed")
		if stat, err := os.Stat(apkInstalled); err == nil && !stat.IsDir() {
			d.loadApk(apkInstalled)
			return
		}
		apkInstalledVar := d.resolve("/var/lib/apk/db/installed")
		if stat, err := os.Stat(apkInstalledVar); err == nil && !stat.IsDir() {
			d.loadApk(apkInstalledVar)
			return
		}

		// 4. Check for RPM (RPM >= 4.18 keeps the db under /usr/lib/sysimage/rpm;
		//    older releases use /var/lib/rpm).
		for _, rpmDirVirt := range []string{"/usr/lib/sysimage/rpm", "/var/lib/rpm"} {
			rpmDir := d.resolve(rpmDirVirt)
			if stat, err := os.Stat(rpmDir); err == nil && stat.IsDir() {
				d.loadRpm(rpmDir)
				return
			}
		}

		d.available = false
		d.statusNote = "No recognized package database found"
	})
}

// loadDpkg parses Debian/Ubuntu .list files and diversions.
func (d *DB) loadDpkg(dpkgInfoDir string) {
	entries, err := os.ReadDir(dpkgInfoDir)
	if err != nil {
		d.available = false
		d.statusNote = "Failed to read dpkg info directory: " + err.Error()
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if strings.HasSuffix(entry.Name(), ".list") {
			// Extract package name: strip .list and arch qualification (e.g. libc6:amd64.list -> libc6)
			pkgName := strings.TrimSuffix(entry.Name(), ".list")
			if idx := strings.Index(pkgName, ":"); idx != -1 {
				pkgName = pkgName[:idx]
			}

			filePath := filepath.Join(dpkgInfoDir, entry.Name())
			f, oErr := safeopen.OpenReadOnly(filePath)
			if oErr != nil {
				continue
			}

			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || line == "/." {
					continue
				}
				norm := NormalizePath(line)
				d.ownerMap[norm] = pkgName
				cleaned := filepath.Clean(line)
				if cleaned != norm {
					d.ownerMap[cleaned] = pkgName
				}
			}
			f.Close()
		} else if strings.HasSuffix(entry.Name(), ".md5sums") {
			filePath := filepath.Join(dpkgInfoDir, entry.Name())
			f, oErr := safeopen.OpenReadOnly(filePath)
			if oErr != nil {
				continue
			}

			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if len(line) < 35 {
					continue
				}
				parts := strings.Fields(line)
				if len(parts) >= 2 && len(parts[0]) == 32 {
					relPath := parts[1]
					if !strings.HasPrefix(relPath, "/") {
						relPath = "/" + relPath
					}
					norm := NormalizePath(relPath)
					if isSystemBinaryPath(norm) {
						md5Hash := strings.ToLower(parts[0])
						d.digestMap[norm] = md5Hash
						cleaned := filepath.Clean(relPath)
						if cleaned != norm {
							d.digestMap[cleaned] = md5Hash
						}
					}
				}
			}
			f.Close()
		}
	}

	// Parse /var/lib/dpkg/diversions if present
	diversionsPath := d.resolve("/var/lib/dpkg/diversions")
	d.parseDpkgDiversions(diversionsPath)

	d.available = len(d.ownerMap) > 0
	if d.available {
		d.statusNote = "Debian dpkg database loaded"
	} else {
		d.statusNote = "Debian dpkg info empty"
	}
}

// parseDpkgDiversions parses Debian 3-line diversion records:
// Line 1: original file
// Line 2: diverted file
// Line 3: diverting package (or ":" for local diversion)
func (d *DB) parseDpkgDiversions(path string) {
	f, err := safeopen.OpenReadOnly(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for {
		if !scanner.Scan() {
			break
		}
		orig := strings.TrimSpace(scanner.Text())
		if orig == "" {
			continue
		}
		if !scanner.Scan() {
			break
		}
		diverted := strings.TrimSpace(scanner.Text())
		if !scanner.Scan() {
			break
		}
		pkg := strings.TrimSpace(scanner.Text())

		if pkg != "" && pkg != ":" {
			normOrig := NormalizePath(orig)
			normDiv := NormalizePath(diverted)
			d.ownerMap[normOrig] = pkg
			d.ownerMap[normDiv] = pkg
			d.ownerMap[filepath.Clean(orig)] = pkg
			d.ownerMap[filepath.Clean(diverted)] = pkg
		}
	}
}

// loadPacman parses Arch Linux /var/lib/pacman/local/<pkg-ver>/files.
func (d *DB) loadPacman(pacmanDir string) {
	entries, err := os.ReadDir(pacmanDir)
	if err != nil {
		d.available = false
		d.statusNote = "Failed to read pacman local directory: " + err.Error()
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Directory name format: <pkgname>-<pkgver>-<pkgrel>
		dirName := entry.Name()
		lastHyphen := strings.LastIndex(dirName, "-")
		if lastHyphen == -1 {
			continue
		}
		secondLastHyphen := strings.LastIndex(dirName[:lastHyphen], "-")
		if secondLastHyphen == -1 {
			continue
		}
		pkgName := dirName[:secondLastHyphen]

		filesPath := filepath.Join(pacmanDir, dirName, "files")
		f, oErr := safeopen.OpenReadOnly(filesPath)
		if oErr != nil {
			continue
		}

		d.parsePacmanFiles(f, pkgName)
		f.Close()
	}

	d.available = len(d.ownerMap) > 0
	if d.available {
		d.statusNote = "Arch pacman database loaded"
	} else {
		d.statusNote = "Arch pacman local empty"
	}
}

func (d *DB) parsePacmanFiles(r io.Reader, pkgName string) {
	scanner := bufio.NewScanner(r)
	inFilesSection := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "%FILES%" {
			inFilesSection = true
			continue
		}
		if strings.HasPrefix(line, "%") {
			inFilesSection = false
			continue
		}
		if inFilesSection && line != "" {
			absPath := "/" + strings.TrimPrefix(line, "/")
			norm := NormalizePath(absPath)
			d.ownerMap[norm] = pkgName
			cleaned := filepath.Clean(absPath)
			if cleaned != norm {
				d.ownerMap[cleaned] = pkgName
			}
		}
	}
}

// loadApk parses Alpine Linux /lib/apk/db/installed or /var/lib/apk/db/installed.
func (d *DB) loadApk(installedPath string) {
	f, err := safeopen.OpenReadOnly(installedPath)
	if err != nil {
		d.available = false
		d.statusNote = "Failed to open apk database: " + err.Error()
		return
	}
	defer f.Close()

	d.parseApkInstalled(f)

	d.available = len(d.ownerMap) > 0
	if d.available {
		d.statusNote = "Alpine apk database loaded"
	} else {
		d.statusNote = "Alpine apk database empty"
	}
}

func (d *DB) parseApkInstalled(r io.Reader) {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	var currentPkg string
	var currentDir string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			currentPkg = ""
			currentDir = ""
			continue
		}

		if strings.HasPrefix(line, "P:") {
			currentPkg = strings.TrimSpace(line[2:])
			currentDir = ""
			continue
		}

		if currentPkg == "" {
			continue
		}

		if strings.HasPrefix(line, "F:") {
			rawDir := strings.TrimSpace(line[2:])
			if rawDir == "" || rawDir == "." {
				currentDir = "/"
			} else {
				currentDir = "/" + strings.TrimPrefix(rawDir, "/")
			}
			normDir := NormalizePath(currentDir)
			d.ownerMap[normDir] = currentPkg
			cleanedDir := filepath.Clean(currentDir)
			if cleanedDir != normDir {
				d.ownerMap[cleanedDir] = currentPkg
			}
			continue
		}

		if strings.HasPrefix(line, "R:") {
			file := strings.TrimSpace(line[2:])
			if file == "" {
				continue
			}
			var absPath string
			if currentDir != "" && currentDir != "/" {
				absPath = filepath.Join(currentDir, file)
			} else {
				absPath = "/" + strings.TrimPrefix(file, "/")
			}
			norm := NormalizePath(absPath)
			d.ownerMap[norm] = currentPkg
			cleaned := filepath.Clean(absPath)
			if cleaned != norm {
				d.ownerMap[cleaned] = currentPkg
			}
		}
	}
}

// rpmDatabaseCandidates lists the on-disk rpmdb file names in preference
// order. rpmdb.Open auto-detects the SQLite3, NDB, and BerkeleyDB formats,
// so only the file name matters.
var rpmDatabaseCandidates = []string{"rpmdb.sqlite", "Packages.db", "Packages"}

// loadRpm probes an RPM database directory for a readable rpmdb file and
// loads ownership + digest maps from it. Returns true on success; every exit
// path sets available and statusNote.
func (d *DB) loadRpm(rpmDir string) bool {
	for _, candidate := range rpmDatabaseCandidates {
		hostPath := filepath.Join(rpmDir, candidate)
		if stat, err := os.Stat(hostPath); err != nil || stat.IsDir() {
			continue
		}
		if d.tryLoadRpmDB(hostPath) {
			return true
		}
		return false // first present candidate is authoritative; report its failure
	}
	d.available = false
	d.statusNote = "RPM database directory found but no readable rpmdb (tried rpmdb.sqlite, Packages.db, Packages)"
	return false
}

// tryLoadRpmDB opens one rpmdb file and populates the maps from it.
func (d *DB) tryLoadRpmDB(hostPath string) bool {
	db, err := rpmdb.Open(hostPath)
	if err != nil {
		d.available = false
		d.statusNote = "Failed to open RPM database: " + err.Error()
		return false
	}
	defer db.Close()

	pkgs, err := db.ListPackages()
	if err != nil {
		d.available = false
		d.statusNote = "Failed to list RPM packages: " + err.Error()
		return false
	}

	owner, md5s, sha256s := buildRpmMaps(convertRpmPackages(pkgs))
	d.ownerMap = owner
	d.digestMap = md5s
	d.digestSHA256Map = sha256s

	d.available = len(d.ownerMap) > 0
	if d.available {
		d.statusNote = fmt.Sprintf("RPM database loaded (%d packages)", len(pkgs))
	} else {
		d.statusNote = "RPM database empty"
	}
	return true
}

// rpmFile is the loader-internal normalized form of one installed file.
type rpmFile struct {
	path       string
	digest     string
	digestAlgo rpmdb.DigestAlgorithm
}

// rpmPkg is one installed package with its normalized file list.
type rpmPkg struct {
	name  string
	files []rpmFile
}

// convertRpmPackages adapts go-rpmdb package values into the internal form,
// pairing each installed file path with its digest and the package's digest
// algorithm. Malformed headers skip the package without failing the load.
func convertRpmPackages(pkgs []*rpmdb.PackageInfo) []rpmPkg {
	out := make([]rpmPkg, 0, len(pkgs))
	for _, p := range pkgs {
		if p == nil {
			continue
		}
		pkg := rpmPkg{name: p.Name}
		files, err := p.InstalledFiles()
		if err != nil {
			continue
		}
		for _, f := range files {
			pkg.files = append(pkg.files, rpmFile{
				path:       f.Path,
				digest:     f.Digest,
				digestAlgo: p.DigestAlgorithm,
			})
		}
		out = append(out, pkg)
	}
	return out
}

// buildRpmMaps inserts RPM file ownership (dual-key: normalized + cleaned)
// and digests. Digests are stored per algorithm — MD5 into the dpkg-shared
// digestMap, SHA-256 into digestSHA256Map — and filtered to system binary
// paths so huge packages (kernel, glibc) keep memory bounded.
func buildRpmMaps(pkgs []rpmPkg) (owner, md5s, sha256s map[string]string) {
	owner = make(map[string]string)
	md5s = make(map[string]string)
	sha256s = make(map[string]string)

	for _, pkg := range pkgs {
		for _, f := range pkg.files {
			if f.path == "" || f.path == "/" {
				continue
			}
			norm := NormalizePath(f.path)
			owner[norm] = pkg.name
			cleaned := filepath.Clean(f.path)
			if cleaned != norm {
				owner[cleaned] = pkg.name
			}
			if !isSystemBinaryPath(norm) {
				continue
			}
			digest := strings.ToLower(strings.TrimSpace(f.digest))
			if digest == "" {
				continue
			}
			switch f.digestAlgo {
			case rpmdb.PGPHASHALGO_MD5:
				md5s[norm] = digest
				if cleaned != norm {
					md5s[cleaned] = digest
				}
			case rpmdb.PGPHASHALGO_SHA256:
				sha256s[norm] = digest
				if cleaned != norm {
					sha256s[cleaned] = digest
				}
			}
		}
	}
	return owner, md5s, sha256s
}

// Owner returns the package owning path (normalizing merged-/usr).
func (d *DB) Owner(path string) (string, bool) {
	d.init()
	if !d.available {
		return "", false
	}

	// Try normalized path first
	norm := NormalizePath(path)
	if pkg, ok := d.ownerMap[norm]; ok {
		return pkg, true
	}

	// Try raw cleaned path
	cleaned := filepath.Clean(path)
	if pkg, ok := d.ownerMap[cleaned]; ok {
		return pkg, true
	}

	return "", false
}

// IsAvailable returns true if a supported package database was found.
func (d *DB) IsAvailable() bool {
	d.init()
	return d.available
}

// StatusNote returns informational status regarding package DB loading.
func (d *DB) StatusNote() string {
	d.init()
	return d.statusNote
}

// VerifyDigest checks whether actualMD5 matches the expected package checksum recorded in the package DB.
// Returns (match, expectedMD5, hasDigest).
func (d *DB) VerifyDigest(path string, actualMD5 string) (bool, string, bool) {
	d.init()
	if !d.available || len(d.digestMap) == 0 {
		return true, "", false
	}
	norm := NormalizePath(path)
	expected, ok := d.digestMap[norm]
	if !ok {
		cleaned := filepath.Clean(path)
		expected, ok = d.digestMap[cleaned]
	}
	if !ok {
		return true, "", false
	}
	return strings.EqualFold(expected, actualMD5), expected, true
}

// VerifyDigestSHA256 verifies whether actualSHA256 matches the expected
// package checksum for databases recording SHA-256 file digests (the
// rpm >= 4.15 default on Fedora/RHEL 9+). Returns (match, expected, hasDigest).
func (d *DB) VerifyDigestSHA256(path string, actualSHA256 string) (bool, string, bool) {
	d.init()
	if !d.available || len(d.digestSHA256Map) == 0 {
		return true, "", false
	}
	norm := NormalizePath(path)
	expected, ok := d.digestSHA256Map[norm]
	if !ok {
		cleaned := filepath.Clean(path)
		expected, ok = d.digestSHA256Map[cleaned]
	}
	if !ok {
		return true, "", false
	}
	return strings.EqualFold(expected, actualSHA256), expected, true
}
