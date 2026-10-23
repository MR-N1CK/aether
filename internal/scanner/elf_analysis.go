package scanner

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"aether/internal/config"
	"aether/internal/pkgdb"
	"aether/internal/report"
)

// ELF magic bytes; scanning many files makes a cheap pre-check worthwhile.
var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

// standardSystemDirs are the ELF library/binary trees a package manager owns.
// Binaries found there are attack surface for every process on the host, so a
// hostile RPATH entry inside them ranks ALERT. Outside them it still signals
// staging behaviour, but ranks WARNING.
var standardSystemDirs = []string{
	"/bin", "/sbin",
	"/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec",
	"/lib", "/lib64", "/lib32",
}

// volatileLibDirs are temporary execution/staging roots; an RPATH pointing
// into them is the classic directory-hijack bootstrap (loader resolves
// dependencies before any trust check runs).
func volatileLibDir(p string) bool {
	return p == "/tmp" || strings.HasPrefix(p, "/tmp/") ||
		p == "/var/tmp" || strings.HasPrefix(p, "/var/tmp/") ||
		p == "/dev/shm" || strings.HasPrefix(p, "/dev/shm/") ||
		strings.HasPrefix(p, "/run/user/")
}

// worldWritableDir stats a directory and reports whether it is group/world
// writable. Lookup failures return false silently: the detector fires on
// values it can verify as hostile, not on unreadable state.
func worldWritableDir(path string) bool {
	fi, err := os.Stat(path)
	if err != nil || !fi.IsDir() {
		return false
	}
	return fi.Mode().Perm()&0002 != 0
}

// CheckSuspiciousELFRPath inspects an ELF binary's DT_RPATH / DT_RUNPATH
// entries for hijack-prone search roots: volatile execution directories,
// world-writable directories, or relative entries ($ORIGIN-relative forms
// are ignored as they are the legitimate relocatable pattern).
//
// The check is deliberately narrow to stay false-positive free: it fires
// only on values that are verifiably dangerous. File reads are read-only
// (forensic-safe); the returned rule name must be registered in
// internal/report rule metadata.
func CheckSuspiciousELFRPath(path string, data []byte, mode uint32, cfg *config.Config) *HeuristicMatch {
	if len(data) < 4 || !bytes.Equal(data[:4], elfMagic) {
		return nil
	}

	// Gate on executability semantics: executables (any exec bit) or shared
	// objects get library-search treatment. Plain data files matching the ELF
	// magic are skipped.
	cleaned := filepath.Clean(path)
	isSharedObject := strings.Contains(filepath.Base(cleaned), ".so")
	if (mode&0111) == 0 && !isSharedObject {
		return nil
	}

	ef, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil
	}

	inSystemDir := false
	for _, d := range standardSystemDirs {
		if cleaned == d || strings.HasPrefix(cleaned, d+"/") {
			inSystemDir = true
			break
		}
	}

	type offending struct {
		entry string
		why   string
	}
	var offenders []offending

	inspect := func(values []string) {
		for _, raw := range values {
			for _, entry := range filepath.SplitList(raw) {
				entry = strings.TrimSpace(entry)
				if entry == "" {
					continue
				}
				if strings.HasPrefix(entry, "$ORIGIN") || strings.HasPrefix(entry, "${ORIGIN}") {
					continue
				}
				if !filepath.IsAbs(entry) {
					offenders = append(offenders, offending{entry: entry, why: "relative search path"})
					continue
				}
				if volatileLibDir(entry) {
					offenders = append(offenders, offending{entry: entry, why: "volatile execution directory"})
					continue
				}
				if worldWritableDir(entry) {
					offenders = append(offenders, offending{entry: entry, why: "world-writable directory"})
				}
			}
		}
	}

	if rpaths, err := ef.DynString(elf.DT_RPATH); err == nil {
		inspect(rpaths)
	}
	if runpaths, err := ef.DynString(elf.DT_RUNPATH); err == nil {
		inspect(runpaths)
	}

	if len(offenders) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(offenders))
	summary := make([]string, 0, len(offenders))
	for _, o := range offenders {
		key := o.entry + "|" + o.why
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		summary = append(summary, fmt.Sprintf("%s (%s)", o.entry, o.why))
	}

	reason := fmt.Sprintf("ELF DT_RPATH/DT_RUNPATH entries reference attacker-controllable library search roots: %s",
		strings.Join(summary, "; "))

	score := config.DefaultScoreELFRPATHUser
	severity := report.SeverityWarning
	if inSystemDir {
		score = config.DefaultScoreELFRPATHSystem
		severity = report.SeverityAlert
	}
	if cfg != nil {
		if cfg.Scan.ScoreELFRPATHSystem > 0 && inSystemDir {
			score = cfg.Scan.ScoreELFRPATHSystem
		}
		if cfg.Scan.ScoreELFRPATHUser > 0 && !inSystemDir {
			score = cfg.Scan.ScoreELFRPATHUser
		}
	}

	return &HeuristicMatch{
		Name:     "Persistence_ELF_RPATH_Hijack",
		Reason:   reason,
		Score:    score,
		Severity: severity,
	}
}

var reIPv4Port = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):(?:[1-9][0-9]{0,4})\b`)

// AnalyzeELFExecutable executes a comprehensive static behavioral inspection of an ELF binary:
// 1. DT_RPATH/DT_RUNPATH library search path hijacking
// 2. UPX and custom packer detection
// 3. W^X memory protection violations (RWX PT_LOAD or PT_GNU_STACK)
// 4. Per-section Shannon entropy analysis (>7.20 bits/byte in executable code sections)
// 5. Anti-analysis corrupted section headers
// 6. Capability-combination behavioral heuristics (reverse shell, C2 listener, process injection, fileless dropper)
// 7. C2 endpoint string extraction
func AnalyzeELFExecutable(path string, data []byte, mode uint32, pkgDB pkgdb.PackageDB, cfg *config.Config) []*HeuristicMatch {
	if len(data) < 4 || !bytes.Equal(data[:4], elfMagic) {
		return nil
	}

	var matches []*HeuristicMatch

	// 1. Legacy/Existing RPATH hijack check
	if rpathMatch := CheckSuspiciousELFRPath(path, data, mode, cfg); rpathMatch != nil {
		matches = append(matches, rpathMatch)
	}

	cleaned := filepath.Clean(path)
	isSharedObject := strings.Contains(filepath.Base(cleaned), ".so")
	isExecutable := (mode&0111) != 0 || isSharedObject

	var isPkgOwned bool
	if pkgDB != nil && pkgDB.IsAvailable() {
		_, isPkgOwned = pkgDB.Owner(cleaned)
	}

	// 2. UPX & Packer Signature Check (runs on raw bytes even if ELF parsing is obfuscated)
	hasUPXMagic := bytes.Contains(data, []byte("UPX!"))
	hasUPXSection := bytes.Contains(data, []byte("UPX0")) || bytes.Contains(data, []byte("UPX1")) || bytes.Contains(data, []byte("UPX2")) || bytes.Contains(data, []byte("!UPX"))
	if hasUPXMagic || hasUPXSection {
		severity := report.SeverityWarning
		score := 75
		if volatileLibDir(cleaned) || !isPkgOwned {
			severity = report.SeverityAlert
			score = 85
		}
		detail := "UPX! magic header detected"
		if hasUPXSection {
			detail = "UPX section headers (UPX0/UPX1) detected"
		}
		matches = append(matches, &HeuristicMatch{
			Name:     "ELF_Packed_UPX",
			Reason:   fmt.Sprintf("ELF binary %s is packed/obfuscated with UPX (%s), commonly used to conceal malicious payload logic and evade static signatures", cleaned, detail),
			Score:    score,
			Severity: severity,
		})
	}

	// 3. Parse ELF structure using Go standard library debug/elf
	ef, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		// If ELF magic is present but NewFile returns an error on non-trivial size,
		// test for anti-analysis corrupted section headers
		if len(data) >= 512 {
			var eShoff uint64
			var ePhnum, eShnum uint16
			if len(data) >= 64 {
				if data[4] == 2 {
					// ELF64
					eShoff = binary.LittleEndian.Uint64(data[40:48])
					ePhnum = binary.LittleEndian.Uint16(data[56:58])
					eShnum = binary.LittleEndian.Uint16(data[60:62])
				} else if data[4] == 1 && len(data) >= 52 {
					// ELF32
					eShoff = uint64(binary.LittleEndian.Uint32(data[32:36]))
					ePhnum = binary.LittleEndian.Uint16(data[44:46])
					eShnum = binary.LittleEndian.Uint16(data[48:50])
				}
				if (eShoff > uint64(len(data)) || (eShnum == 0 && eShoff > 0)) && ePhnum > 0 {
					matches = append(matches, &HeuristicMatch{
						Name:     "ELF_AntiAnalysis_Corrupted_Header",
						Reason:   fmt.Sprintf("ELF binary %s has corrupted or stripped section header table offset (e_shoff: 0x%x > size %d) with valid program headers (%d phders), an evasive anti-analysis technique designed to crash disassemblers", cleaned, eShoff, len(data), ePhnum),
						Score:    70,
						Severity: report.SeverityWarning,
					})
				}
			}
		}
		return matches
	}
	defer ef.Close()

	// 4. Segment Analysis: W^X Memory Violations (PT_LOAD with W+X, or PT_GNU_STACK with X)
	for _, prog := range ef.Progs {
		if prog.Type == elf.PT_LOAD {
			if (prog.Flags & (elf.PF_W | elf.PF_X)) == (elf.PF_W | elf.PF_X) {
				severity := report.SeverityWarning
				score := 75
				if !isPkgOwned || volatileLibDir(cleaned) {
					severity = report.SeverityAlert
					score = 85
				}
				matches = append(matches, &HeuristicMatch{
					Name:     "ELF_Section_RWX_Anomaly",
					Reason:   fmt.Sprintf("ELF binary %s contains PT_LOAD program segment with simultaneous Read/Write/Execute (RWX) permissions at Vaddr 0x%x (W^X memory protection violation typical of shellcode injectors or polymorphic crypters)", cleaned, prog.Vaddr),
					Score:    score,
					Severity: severity,
				})
				break
			}
		} else if prog.Type == 0x6474e551 { // PT_GNU_STACK
			if (prog.Flags&elf.PF_X) != 0 && (!isPkgOwned || volatileLibDir(cleaned)) {
				matches = append(matches, &HeuristicMatch{
					Name:     "ELF_Section_RWX_Anomaly",
					Reason:   fmt.Sprintf("ELF binary %s explicitly marks stack as executable (PT_GNU_STACK PF_X) outside package manager, typical of shellcode execution stagers", cleaned),
					Score:    80,
					Severity: report.SeverityWarning,
				})
				break
			}
		}
	}

	// 5. Per-Section Shannon Entropy Analysis (Executable Code Sections)
	for _, sec := range ef.Sections {
		if (sec.Flags&elf.SHF_EXECINSTR) != 0 || sec.Name == ".text" {
			if sec.Size >= 256 {
				if secData, sErr := sec.Data(); sErr == nil && len(secData) >= 256 {
					ent := ShannonEntropy(secData)
					if ent > 7.20 && (!isPkgOwned || volatileLibDir(cleaned)) {
						matches = append(matches, &HeuristicMatch{
                            Name:     "ELF_High_Entropy_Code_Section",
                            Reason:   fmt.Sprintf("Executable code section '%s' in %s has abnormally high Shannon entropy (%.2f/8.00; normal compiled code: 5.6-6.4), indicating encrypted machine code, packed stager, or embedded payload", sec.Name, cleaned, ent),
                            Score:    85,
                            Severity: report.SeverityAlert,
                        })
						break
					}
				}
			}
		}
	}

	// 6. Capability & Syscall Combination Analysis (for unmanaged binaries)
	// Package-managed system binaries (like /usr/bin/curl or /usr/bin/ssh) are exempted
	// to guarantee zero false positives on standard distribution packages.
	if !isPkgOwned && isExecutable {
		symMap := make(map[string]struct{})
		if imported, err := ef.ImportedSymbols(); err == nil {
			for _, s := range imported {
				symMap[s.Name] = struct{}{}
			}
		}
		if dynsyms, err := ef.DynamicSymbols(); err == nil {
			for _, s := range dynsyms {
				symMap[s.Name] = struct{}{}
			}
		}
		if syms, err := ef.Symbols(); err == nil {
			for _, s := range syms {
				symMap[s.Name] = struct{}{}
			}
		}

		hasAny := func(m map[string]struct{}, names ...string) bool {
			for _, name := range names {
				if _, ok := m[name]; ok {
					return true
				}
			}
			return false
		}

		hasSocket := hasAny(symMap, "socket", "socketpair")
		hasConnect := hasAny(symMap, "connect")
		hasBindListen := hasAny(symMap, "bind") && (hasAny(symMap, "listen", "accept", "accept4"))
		hasDup := hasAny(symMap, "dup2", "dup3")
		hasExec := hasAny(symMap, "execve", "execv", "execl", "execlp", "execvp", "fexecve", "execveat", "system", "popen")
		hasPtrace := hasAny(symMap, "ptrace", "process_vm_writev", "process_vm_readv")
		hasMprotect := hasAny(symMap, "mprotect", "pkey_mprotect")
		hasMemfd := hasAny(symMap, "memfd_create")

		// Helper to extract C2 endpoints from .rodata or raw data
		extractC2Endpoints := func() string {
			searchBuf := data
			if rodata := ef.Section(".rodata"); rodata != nil {
				if roBytes, rErr := rodata.Data(); rErr == nil && len(roBytes) > 0 {
					searchBuf = roBytes
				}
			}
			rawIPs := reIPv4Port.FindAll(searchBuf, 5)
			if len(rawIPs) == 0 {
				return ""
			}
			var valid []string
			seenIP := make(map[string]struct{})
			for _, b := range rawIPs {
				str := string(b)
				if strings.HasPrefix(str, "127.") || strings.HasPrefix(str, "0.0.0.0") || strings.HasPrefix(str, "255.255.255.255") {
					continue
				}
				if _, dup := seenIP[str]; !dup {
					seenIP[str] = struct{}{}
					valid = append(valid, str)
					if len(valid) >= 3 {
						break
					}
				}
			}
			if len(valid) > 0 {
				return strings.Join(valid, ", ")
			}
			return ""
		}

		// A. Reverse Shell Combination: socket + connect + dup2/dup3 + execve/execl/system
		if hasSocket && hasConnect && hasDup && hasExec {
			endpoints := extractC2Endpoints()
			reason := fmt.Sprintf("Statically detected compiled reverse shell capability: unmanaged binary %s imports socket networking (socket, connect), file descriptor redirection (dup2/dup3), and process execution (execve/system)", cleaned)
			if endpoints != "" {
				reason += fmt.Sprintf(" [Embedded C2 target: %s]", endpoints)
			}
			matches = append(matches, &HeuristicMatch{
				Name:     "ELF_Behavioral_ReverseShell_Combo",
				Reason:   reason,
				Score:    90,
				Severity: report.SeverityAlert,
			})
		}

		// B. C2 Listener / Bind Shell Combination: socket + bind + listen/accept + dup2/dup3 + execve
		if hasSocket && hasBindListen && hasDup && hasExec {
			matches = append(matches, &HeuristicMatch{
				Name:     "ELF_Behavioral_C2_Listener_Combo",
				Reason:   fmt.Sprintf("Statically detected compiled C2 listener / bind shell capability: unmanaged binary %s imports socket binding/listening (bind, listen/accept), file descriptor redirection (dup2/dup3), and command execution", cleaned),
				Score:    85,
				Severity: report.SeverityAlert,
			})
		}

		// C. Process Injection Combination: ptrace/process_vm + mprotect/mmap + waitpid/kill/fork
		if hasPtrace && (hasMprotect || hasAny(symMap, "mmap")) && hasAny(symMap, "waitpid", "kill", "fork", "clone") {
			matches = append(matches, &HeuristicMatch{
				Name:     "ELF_Behavioral_ProcessInjection_Combo",
				Reason:   fmt.Sprintf("Statically detected process memory injection capability: unmanaged binary %s imports cross-process memory access (ptrace/process_vm) combined with memory protection modifications (mprotect/mmap) and thread control", cleaned),
				Score:    90,
				Severity: report.SeverityAlert,
			})
		}

		// D. Fileless In-Memory Dropper Combination: memfd_create + fexecve/execveat
		if hasMemfd && hasAny(symMap, "fexecve", "execveat") {
			matches = append(matches, &HeuristicMatch{
				Name:     "ELF_Behavioral_FilelessDropper_Combo",
				Reason:   fmt.Sprintf("Statically detected fileless in-memory execution capability: unmanaged binary %s imports anonymous in-memory file descriptor allocation (memfd_create) combined with direct descriptor execution (fexecve/execveat)", cleaned),
				Score:    85,
				Severity: report.SeverityAlert,
			})
		}
	}

	return matches
}
