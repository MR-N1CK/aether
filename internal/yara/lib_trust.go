package yara

import (
	"bufio"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// StatFunc abstracts file stat operations for testability.
type StatFunc func(path string) (os.FileInfo, error)

// EvalSymlinksFunc abstracts symlink resolution for testability.
type EvalSymlinksFunc func(path string) (string, error)

// GetenvFunc abstracts environment variable lookups for testability.
type GetenvFunc func(key string) string

// DefaultStat uses os.Stat.
func DefaultStat(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

// DefaultEvalSymlinks uses filepath.EvalSymlinks.
func DefaultEvalSymlinks(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}

// DefaultGetenv uses os.Getenv.
func DefaultGetenv(key string) string {
	return os.Getenv(key)
}

// ElfLinkage holds parsed dynamic linkage information from an ELF executable.
type ElfLinkage struct {
	NeededLibraries []string
	Runpaths        []string
}

// ElfParserFunc abstracts parsing ELF linkage from /proc/self/exe or fixture files.
type ElfParserFunc func(exePath string) (*ElfLinkage, error)

// DefaultElfParser parses dynamic section tags from the given executable path using debug/elf.
func DefaultElfParser(exePath string) (*ElfLinkage, error) {
	f, err := elf.Open(exePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var needed []string
	if libs, err := f.ImportedLibraries(); err == nil {
		needed = libs
	} else if errors.Is(err, elf.ErrNoSymbols) {
		// Statically linked executable without dynamic symbols
		return &ElfLinkage{}, nil
	} else {
		// Fallback to reading DT_NEEDED directly
		if dynNeeded, dErr := f.DynString(elf.DT_NEEDED); dErr == nil {
			needed = dynNeeded
		} else if errors.Is(dErr, elf.ErrNoSymbols) {
			return &ElfLinkage{}, nil
		} else {
			return nil, err
		}
	}

	var allRunpaths []string
	if rpaths, err := f.DynString(elf.DT_RPATH); err == nil {
		for _, rp := range rpaths {
			for _, part := range strings.Split(rp, ":") {
				part = strings.TrimSpace(part)
				if part != "" {
					allRunpaths = append(allRunpaths, part)
				}
			}
		}
	}
	if runpaths, err := f.DynString(elf.DT_RUNPATH); err == nil {
		for _, rp := range runpaths {
			for _, part := range strings.Split(rp, ":") {
				part = strings.TrimSpace(part)
				if part != "" {
					allRunpaths = append(allRunpaths, part)
				}
			}
		}
	}

	return &ElfLinkage{
		NeededLibraries: needed,
		Runpaths:        allRunpaths,
	}, nil
}

// VerifyRootOwnedPath validates that a path and all of its ancestor directories up to /
// are root-owned (UID 0) and not group- or world-writable (perm & 0022 == 0).
func VerifyRootOwnedPath(path string, statFn StatFunc, evalSymlinksFn EvalSymlinksFunc) (bool, string) {
	if statFn == nil {
		statFn = DefaultStat
	}
	if evalSymlinksFn == nil {
		evalSymlinksFn = DefaultEvalSymlinks
	}

	resolvedPath, err := evalSymlinksFn(path)
	if err != nil {
		return false, fmt.Sprintf("failed to resolve path %s: %v", path, err)
	}
	resolvedPath = filepath.Clean(resolvedPath)

	fi, err := statFn(resolvedPath)
	if err != nil {
		return false, fmt.Sprintf("failed to stat file %s: %v", resolvedPath, err)
	}

	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Sprintf("failed to retrieve POSIX stats for %s", resolvedPath)
	}
	if stat.Uid != 0 {
		return false, fmt.Sprintf("file %s owned by UID %d, expected 0 (root)", resolvedPath, stat.Uid)
	}
	if fi.Mode().Perm()&0022 != 0 {
		return false, fmt.Sprintf("file %s has insecure permissions (%04o, group/world-writable)", resolvedPath, fi.Mode().Perm())
	}

	currDir := filepath.Dir(resolvedPath)
	for {
		cleanDir := filepath.Clean(currDir)
		dfi, err := statFn(cleanDir)
		if err != nil {
			return false, fmt.Sprintf("failed to stat ancestor directory %s: %v", cleanDir, err)
		}
		dstat, ok := dfi.Sys().(*syscall.Stat_t)
		if !ok {
			return false, fmt.Sprintf("failed to retrieve POSIX stats for ancestor directory %s", cleanDir)
		}
		if dstat.Uid != 0 {
			return false, fmt.Sprintf("ancestor directory %s owned by UID %d, expected 0 (root)", cleanDir, dstat.Uid)
		}
		if dfi.Mode().Perm()&0022 != 0 {
			return false, fmt.Sprintf("ancestor directory %s has insecure permissions (%04o, group/world-writable)", cleanDir, dfi.Mode().Perm())
		}

		if cleanDir == "/" || cleanDir == "." {
			break
		}
		parent := filepath.Dir(cleanDir)
		if parent == cleanDir {
			break
		}
		currDir = parent
	}

	return true, ""
}

// EvaluateLibraryTrust validates that libyara_x_capi is loaded from a strictly trusted location.
//
// Dynamic linkage detection reads /proc/self/exe with debug/elf:
//  1. If euid == 0 and ELF cannot be parsed -> refuse YARA with "cannot verify library linkage".
//  2. If libyara_x_capi is NEEDED (match "libyara_x_capi.so" prefix or contains) -> maps check is mandatory (fail closed).
//  3. If any RUNPATH/RPATH entry is in a directory that is not root-owned and non-group/world-writable (including ancestors) -> refuse.
//  4. Statically linked builds (no NEEDED entry for libyara_x_capi) bypass the memory maps lookup.
func EvaluateLibraryTrust(
	euid uint32,
	devRpath bool,
	exePath string,
	elfParser ElfParserFunc,
	mapsContent string,
	getenv GetenvFunc,
	statFn StatFunc,
	evalSymlinksFn EvalSymlinksFunc,
) (bool, string) {
	// Non-root executions are unprivileged and operate within user boundaries
	if euid != 0 {
		return true, ""
	}

	if exePath == "" {
		exePath = "/proc/self/exe"
	}
	if elfParser == nil {
		elfParser = DefaultElfParser
	}
	if getenv == nil {
		getenv = DefaultGetenv
	}
	if statFn == nil {
		statFn = DefaultStat
	}
	if evalSymlinksFn == nil {
		evalSymlinksFn = DefaultEvalSymlinks
	}

	// 1. Dev RPATH binaries must never run YARA as root
	if devRpath {
		return false, "dev rpath build not permitted for root execution"
	}

	// 2. LD_LIBRARY_PATH and LD_PRELOAD are untrusted for root execution
	if val := getenv("LD_LIBRARY_PATH"); strings.TrimSpace(val) != "" {
		return false, "library path not trusted"
	}
	if val := getenv("LD_PRELOAD"); strings.TrimSpace(val) != "" {
		return false, "library path not trusted"
	}

	// 3. Own binary trust check: verify the executable itself and all ancestor directories
	if trusted, _ := VerifyRootOwnedPath(exePath, statFn, evalSymlinksFn); !trusted {
		return false, "executable not in a root-owned path"
	}

	// 4. Parse ELF dynamic linkage metadata
	linkage, err := elfParser(exePath)
	if err != nil {
		return false, "cannot verify linkage"
	}

	// 5. Verify all RUNPATH and RPATH entries (and their ancestors) are root-owned and not group/world-writable
	for _, rp := range linkage.Runpaths {
		if trusted, _ := VerifyRootOwnedPath(rp, statFn, evalSymlinksFn); !trusted {
			return false, "RUNPATH not trusted"
		}
	}

	// 6. Check if libyara_x_capi is NEEDED (match "libyara_x_capi.so" prefix or contains)
	hasYaraNeeded := false
	for _, lib := range linkage.NeededLibraries {
		if strings.HasPrefix(lib, "libyara_x_capi.so") || strings.Contains(lib, "libyara_x_capi") {
			hasYaraNeeded = true
			break
		}
	}

	if !hasYaraNeeded {
		// Static YARA build (libyara_x_capi.a embedded) or pure Go binary without dynamic YARA
		return true, ""
	}

	// 7. Dynamic YARA: memory maps verification is mandatory (fail closed)
	libPath := findLibInMaps(mapsContent, "libyara_x_capi")
	if libPath == "" {
		return false, "library path not trusted"
	}

	// 8. Verify the library file and its ancestor path
	if trusted, _ := VerifyRootOwnedPath(libPath, statFn, evalSymlinksFn); !trusted {
		return false, "library path not trusted"
	}
	return true, ""
}

// findLibInMaps extracts the file path for a shared library from /proc/self/maps content.
func findLibInMaps(mapsContent string, libSubstring string) string {
	scanner := bufio.NewScanner(strings.NewReader(mapsContent))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, libSubstring) {
			fields := strings.Fields(line)
			if len(fields) >= 6 {
				candidate := fields[len(fields)-1]
				if strings.HasPrefix(candidate, "/") && strings.Contains(candidate, libSubstring) {
					return candidate
				}
			}
		}
	}
	return ""
}
