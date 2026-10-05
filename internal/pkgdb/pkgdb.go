package pkgdb

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"aether/internal/safeopen"
)

// PackageDB abstracts package ownership lookups across Linux distributions.
type PackageDB interface {
	// Owner returns the package owning the given file path, if known.
	Owner(path string) (string, bool)
	// IsAvailable returns true if a supported package database was found and loaded.
	IsAvailable() bool
	// StatusNote returns informational notes about the package DB state (e.g. RPM unavailable).
	StatusNote() string
}

// DB is a thread-safe, pure Go package database reader.
type DB struct {
	rootFS     string
	once       sync.Once
	available  bool
	statusNote string
	ownerMap   map[string]string // normalized path -> package name
}

// New creates a new PackageDB rooted at rootFS (empty string for system root "/").
func New(rootFS string) *DB {
	return &DB{
		rootFS:   rootFS,
		ownerMap: make(map[string]string),
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

		// 3. Check for RPM (/var/lib/rpm)
		rpmDir := d.resolve("/var/lib/rpm")
		if stat, err := os.Stat(rpmDir); err == nil && stat.IsDir() {
			d.available = false
			d.statusNote = "RPM package database pure-Go reader unavailable; skipping package ownership scoring"
			return
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
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".list") {
			continue
		}

		// Extract package name: strip .list and arch qualification (e.g. libc6:amd64.list -> libc6)
		pkgName := strings.TrimSuffix(entry.Name(), ".list")
		if idx := strings.Index(pkgName, ":"); idx != -1 {
			pkgName = pkgName[:idx]
		}

		filePath := filepath.Join(dpkgInfoDir, entry.Name())
		f, oErr := os.Open(filePath)
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
			// Also record raw cleaned path if different from normalized
			cleaned := filepath.Clean(line)
			if cleaned != norm {
				d.ownerMap[cleaned] = pkgName
			}
		}
		f.Close()
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
	f, err := os.Open(path)
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
		f, oErr := os.Open(filesPath)
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
