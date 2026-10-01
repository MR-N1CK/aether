package process

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

var (
	ErrProcessVanished   = errors.New("process vanished")
	ErrPermissionDenied  = errors.New("permission denied")
)

// MapEntry represents a line from /proc/<pid>/maps.
type MapEntry struct {
	StartAddr uint64
	EndAddr   uint64
	Perms     string
	Offset    int64
	Dev       string
	Inode     uint64
	Pathname  string
}

// ProcessInfo holds metadata gathered by reading /proc/<pid>/* read-only.
type ProcessInfo struct {
	PID      int
	Exe      string
	ExeStat  *unix.Stat_t
	Cwd      string
	Cmdline  []string
	Comm     string
	Uid      uint32
	Euid     uint32
	Gid      uint32
	Egid     uint32
	PPid         int
	Flags        uint32
	IsKThread    bool
	IsZombie     bool
	ExeReadable  bool
	CwdReadable  bool
	CmdReadable  bool
	MapsReadable bool
	MntNs        string
	Maps         []MapEntry
	CoverageGaps []string
}

// ReadProcessInfo gathers metadata for a PID from /proc/<pid>.
// It treats process disappearance or missing entries mid-read as non-fatal ErrProcessVanished.
func ReadProcessInfo(pid int) (*ProcessInfo, error) {
	procDir := fmt.Sprintf("/proc/%d", pid)

	// Quick check if /proc/<pid> exists
	if _, err := os.Stat(procDir); err != nil {
		if os.IsNotExist(err) || errors.Is(err, syscall.ESRCH) {
			return nil, ErrProcessVanished
		}
		if os.IsPermission(err) {
			return nil, ErrPermissionDenied
		}
		return nil, err
	}

	info := &ProcessInfo{
		PID:     pid,
		Cmdline: make([]string, 0),
		Maps:    make([]MapEntry, 0),
	}

	// 1. Read comm
	commBytes, err := os.ReadFile(filepath.Join(procDir, "comm"))
	if err == nil {
		info.Comm = strings.TrimSpace(string(commBytes))
	} else if os.IsNotExist(err) || errors.Is(err, syscall.ESRCH) {
		return nil, ErrProcessVanished
	}

	// 2. Read status for Uid/Gid/PPid
	statusBytes, err := os.ReadFile(filepath.Join(procDir, "status"))
	if err == nil {
		parseStatus(string(statusBytes), info)
	} else if os.IsNotExist(err) || errors.Is(err, syscall.ESRCH) {
		return nil, ErrProcessVanished
	}

	// 2b. Read stat for PF_KTHREAD flags
	statBytes, err := os.ReadFile(filepath.Join(procDir, "stat"))
	if err == nil {
		parseStat(string(statBytes), info)
	} else if os.IsNotExist(err) || errors.Is(err, syscall.ESRCH) {
		return nil, ErrProcessVanished
	}

	// 3. Read cmdline (separated by null bytes)
	cmdlineBytes, err := os.ReadFile(filepath.Join(procDir, "cmdline"))
	if err == nil {
		info.CmdReadable = true
		if len(cmdlineBytes) > 0 {
			rawArgs := bytes.Split(cmdlineBytes, []byte{0})
			for _, arg := range rawArgs {
				if len(arg) > 0 {
					info.Cmdline = append(info.Cmdline, string(arg))
				}
			}
		}
	} else if os.IsNotExist(err) || errors.Is(err, syscall.ESRCH) {
		return nil, ErrProcessVanished
	}

	// 4. Read exe link
	exeTarget, err := os.Readlink(filepath.Join(procDir, "exe"))
	if err == nil {
		info.ExeReadable = true
		info.Exe = exeTarget
		var st unix.Stat_t
		if sErr := unix.Stat(filepath.Join(procDir, "exe"), &st); sErr == nil {
			info.ExeStat = &st
		}
	}

	// 5. Read cwd link
	cwdTarget, err := os.Readlink(filepath.Join(procDir, "cwd"))
	if err == nil {
		info.CwdReadable = true
		info.Cwd = cwdTarget
	}

	// 6. Read mount namespace ID
	mntTarget, err := os.Readlink(filepath.Join(procDir, "ns", "mnt"))
	if err == nil {
		info.MntNs = mntTarget
	}

	// 7. Read maps (ignore error if permission denied, but parse if available)
	mapsBytes, err := os.ReadFile(filepath.Join(procDir, "maps"))
	if err == nil {
		info.MapsReadable = true
		info.Maps = ParseMaps(string(mapsBytes))
	}

	return info, nil
}

// IsFullyReadable returns true only if exe, cwd, cmdline, and maps were all readable.
func (p *ProcessInfo) IsFullyReadable() bool {
	if p == nil {
		return false
	}
	return p.ExeReadable && p.CwdReadable && p.CmdReadable && p.MapsReadable
}

// IsKernelThread determines if the process is a kernel thread.
// Detect via PF_KTHREAD (flags & 0x200000 in /proc/<pid>/stat field 9),
// fallback PPid == 2. Zombies (State: Z) are never kernel threads.
func IsKernelThread(info *ProcessInfo) bool {
	if info == nil || info.IsZombie {
		return false
	}
	if info.IsKThread {
		return true
	}
	if info.PPid == 2 && len(info.Cmdline) == 0 && info.Exe == "" {
		return true
	}
	return false
}

// parseStat parses /proc/<pid>/stat for task flags and kernel thread status.
func parseStat(content string, info *ProcessInfo) {
	lastParen := strings.LastIndex(content, ")")
	if lastParen == -1 || lastParen+2 >= len(content) {
		return
	}
	fields := strings.Fields(content[lastParen+2:])
	// fields[0]=state(3), fields[1]=ppid(4), fields[2]=pgrp(5), fields[3]=session(6),
	// fields[4]=tty_nr(7), fields[5]=tpgid(8), fields[6]=flags(9)
	if len(fields) >= 7 {
		if fl, err := strconv.ParseUint(fields[6], 10, 32); err == nil {
			info.Flags = uint32(fl)
			if (info.Flags & 0x00200000) != 0 {
				info.IsKThread = true
			}
		}
	}
	if len(fields) >= 2 && !info.IsKThread {
		if ppid, err := strconv.Atoi(fields[1]); err == nil && ppid == 2 {
			info.IsKThread = true
		}
	}
}

// ParseStatString parses /proc/<pid>/stat formatted string into ProcessInfo (exported for testing).
func ParseStatString(content string, info *ProcessInfo) {
	parseStat(content, info)
}

// ParseStatusString parses /proc/<pid>/status formatted string into ProcessInfo (exported for testing).
func ParseStatusString(content string, info *ProcessInfo) {
	parseStatus(content, info)
}

// parseStatus parses /proc/<pid>/status for Uid, Gid, PPid, and State.
func parseStatus(content string, info *ProcessInfo) {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "State:":
			if strings.HasPrefix(fields[1], "Z") {
				info.IsZombie = true
			}
		case "PPid:":
			if p, err := strconv.Atoi(fields[1]); err == nil {
				info.PPid = p
			}
		case "Uid:":
			// Uid: real effective saved fs
			if len(fields) >= 3 {
				if r, err := strconv.ParseUint(fields[1], 10, 32); err == nil {
					info.Uid = uint32(r)
				}
				if e, err := strconv.ParseUint(fields[2], 10, 32); err == nil {
					info.Euid = uint32(e)
				}
			}
		case "Gid:":
			if len(fields) >= 3 {
				if r, err := strconv.ParseUint(fields[1], 10, 32); err == nil {
					info.Gid = uint32(r)
				}
				if e, err := strconv.ParseUint(fields[2], 10, 32); err == nil {
					info.Egid = uint32(e)
				}
			}
		}
	}
}

// ParseMaps parses /proc/<pid>/maps lines into structured MapEntry items.
func ParseMaps(content string) []MapEntry {
	lines := strings.Split(content, "\n")
	entries := make([]MapEntry, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		// Field 0: address range (e.g. 55d9d7f00000-55d9d7f02000)
		addrs := strings.Split(fields[0], "-")
		if len(addrs) != 2 {
			continue
		}
		start, err1 := strconv.ParseUint(addrs[0], 16, 64)
		end, err2 := strconv.ParseUint(addrs[1], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}

		entry := MapEntry{
			StartAddr: start,
			EndAddr:   end,
			Perms:     fields[1],
			Dev:       fields[3],
		}

		if off, err := strconv.ParseInt(fields[2], 16, 64); err == nil {
			entry.Offset = off
		}
		if ino, err := strconv.ParseUint(fields[4], 10, 64); err == nil {
			entry.Inode = ino
		}

		if len(fields) >= 6 {
			// Pathname may contain spaces
			entry.Pathname = strings.Join(fields[5:], " ")
		}

		entries = append(entries, entry)
	}

	return entries
}

// ReadMappingHeader reads up to n bytes from the start of an executable memory mapping.
// Forensic & Safety Design:
//  1. Pure read-only operation: We NEVER use ptrace (PTRACE_ATTACH / PTRACE_PEEKDATA) or
//     write to target processes, preserving forensic integrity and eliminating process disruption.
//  2. /proc/<pid>/map_files/<start_hex>-<end_hex>:
//     On Linux (since kernel 3.3 with CONFIG_CHECKPOINT_RESTORE), map_files entries are directory
//     symlinks to the underlying mapped file descriptors (including memfd objects). Reading through
//     map_files accesses the file data directly in kernel space without invoking ptrace or mem access.
//  3. Exe Inode Fallback:
//     If map_files is restricted (typically requiring CAP_CHECKPOINT_RESTORE or root permissions)
//     and the mapping corresponds to the executable's inode, we safely read through /proc/<pid>/exe.
//  4. Graceful Degradation:
//     If the mapping header is unreadable due to kernel permissions or unbacked memory, we record
//     a coverage gap instead of generating a false-positive or speculative finding.
func ReadMappingHeader(pid int, startAddr, endAddr uint64, exeInode uint64, mapInode uint64) ([]byte, error) {
	// 1. Try /proc/<pid>/map_files/<start_hex>-<end_hex>
	mapFilePath := fmt.Sprintf("/proc/%d/map_files/%x-%x", pid, startAddr, endAddr)
	f, err := os.Open(mapFilePath)
	if err == nil {
		defer f.Close()
		buf := make([]byte, 4)
		n, rErr := io.ReadFull(f, buf)
		if rErr == nil && n == 4 {
			return buf, nil
		}
	}

	// 2. Fallback to /proc/<pid>/exe if map inode matches executable inode
	if exeInode != 0 && mapInode == exeInode {
		exePath := fmt.Sprintf("/proc/%d/exe", pid)
		if ef, oErr := os.Open(exePath); oErr == nil {
			defer ef.Close()
			buf := make([]byte, 4)
			n, rErr := io.ReadFull(ef, buf)
			if rErr == nil && n == 4 {
				return buf, nil
			}
		}
	}

	return nil, os.ErrPermission
}

// GetSelfMountNs returns the mount namespace of the current process.
func GetSelfMountNs() string {
	ns, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		return ""
	}
	return ns
}
