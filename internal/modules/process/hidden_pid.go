package process

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// DetectHidepid checks whether /proc is mounted with hidepid restrictions.
func DetectHidepid(mountinfoPath string) (bool, string) {
	if mountinfoPath == "" {
		mountinfoPath = "/proc/self/mountinfo"
	}

	f, err := os.Open(mountinfoPath)
	if err != nil {
		return false, ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		// Field 4 is the mount point (e.g. /proc)
		mountPoint := fields[4]
		if mountPoint != "/proc" {
			continue
		}

		// Check fields for hidepid option
		for _, field := range fields {
			if strings.Contains(field, "hidepid=1") {
				return true, "hidepid=1 (users can only access their own process directories)"
			}
			if strings.Contains(field, "hidepid=2") {
				return true, "hidepid=2 (processes not owned by the user are invisible)"
			}
			if strings.Contains(field, "hidepid=invisible") {
				return true, "hidepid=invisible (processes not owned by the user are invisible)"
			}
		}
	}
	return false, ""
}

// ReadMaxPID reads /proc/sys/kernel/pid_max, with a fallback of 32768.
func ReadMaxPID(path string) int {
	if path == "" {
		path = "/proc/sys/kernel/pid_max"
	}
	data, err := os.ReadFile(path)
	if err == nil {
		if val, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && val > 0 {
			return val
		}
	}
	return 32768
}

// ReadLastAllocatedPID reads field 5 of /proc/loadavg.
func ReadLastAllocatedPID(loadavgPath string) int {
	if loadavgPath == "" {
		loadavgPath = "/proc/loadavg"
	}
	data, err := os.ReadFile(loadavgPath)
	if err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 5 {
			if pid, err := strconv.Atoi(fields[4]); err == nil {
				return pid
			}
		}
	}
	return 0
}

// isProcessLeader inspects /proc/<pid>/status to verify if the task is a thread-group leader (process).
// In Linux, secondary threads have Tgid != Pid and are by design not listed in root /proc readdir.
func isProcessLeader(procPath string, pid int) bool {
	statusPath := filepath.Join(procPath, strconv.Itoa(pid), "status")
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Tgid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				tgid, err := strconv.Atoi(fields[1])
				if err == nil {
					return tgid == pid
				}
			}
		}
	}
	return true
}

// GetProcReaddirPIDs lists all numeric directory names currently under /proc.
func GetProcReaddirPIDs(procPath string) (map[int]bool, error) {
	entries, err := os.ReadDir(procPath)
	if err != nil {
		return nil, err
	}

	pids := make(map[int]bool, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if pid, err := strconv.Atoi(entry.Name()); err == nil && pid > 0 {
			pids[pid] = true
		}
	}
	return pids, nil
}

// ProbePIDsRange performs parallel lstat probes on 1..maxPID in procPath.
// Uses fast unix.Fstatat to avoid heap string allocations and path parsing overhead.
func ProbePIDsRange(ctx context.Context, procPath string, maxPID int) (map[int]bool, error) {
	procFd, err := unix.Open(procPath, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(procFd)

	var mu sync.Mutex
	foundPIDs := make(map[int]bool)

	numWorkers := runtime.NumCPU() * 4
	if numWorkers < 16 {
		numWorkers = 16
	}
	if numWorkers > 64 {
		numWorkers = 64
	}
	if maxPID < 1000 {
		numWorkers = 2
	}
	chunkSize := (maxPID + numWorkers - 1) / numWorkers

	var wg sync.WaitGroup
	var cancelled atomic.Bool

	for w := 0; w < numWorkers; w++ {
		low := w*chunkSize + 1
		high := (w + 1) * chunkSize
		if high > maxPID {
			high = maxPID
		}
		if low > high {
			continue
		}

		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			var stat unix.Stat_t
			buf := make([]byte, 0, 16)
			localFound := make([]int, 0, 64)

			for pid := start; pid <= end; pid++ {
				if cancelled.Load() {
					return
				}
				select {
				case <-ctx.Done():
					cancelled.Store(true)
					return
				default:
				}

				buf = strconv.AppendInt(buf[:0], int64(pid), 10)
				// AT_SYMLINK_NOFOLLOW ensures we do not follow symlinks
				err := unix.Fstatat(procFd, string(buf), &stat, unix.AT_SYMLINK_NOFOLLOW)
				if err == nil {
					localFound = append(localFound, pid)
				}
			}

			if len(localFound) > 0 {
				mu.Lock()
				for _, p := range localFound {
					foundPIDs[p] = true
				}
				mu.Unlock()
			}
		}(low, high)
	}

	wg.Wait()

	if cancelled.Load() {
		return nil, ctx.Err()
	}

	return foundPIDs, nil
}

// FilterTwoPassDiscrepancies isolates PIDs that are discrepant in BOTH passes.
// If a PID was only discrepant in pass 1 (e.g. transient race), it is filtered out.
func FilterTwoPassDiscrepancies(
	discrepantPass1 []int,
	readdirPass2 map[int]bool,
	isPIDActivePass2 func(pid int) bool,
) []int {
	confirmed := make([]int, 0)
	for _, pid := range discrepantPass1 {
		// If PID is now visible in readdir pass 2, it was just a transient newly spawned process
		if readdirPass2[pid] {
			continue
		}
		// If PID is no longer accessible via stat, it was a short-lived process that exited
		if !isPIDActivePass2(pid) {
			continue
		}
		// PID is STILL missing from readdir AND STILL active via stat -> truly hidden!
		confirmed = append(confirmed, pid)
	}
	return confirmed
}

// CheckHiddenPIDs executes the full two-pass hidden-PID detection workflow.
// CheckHiddenPIDsWithTimings executes the full two-pass hidden-PID detection workflow
// and returns per-pass timing durations.
func CheckHiddenPIDsWithTimings(ctx context.Context, procPath string, maxPID int, fullScan bool) ([]int, bool, string, time.Duration, time.Duration, error) {
	// 1. Check for hidepid
	hasHidepid, hidepidReason := DetectHidepid("")
	if hasHidepid {
		return nil, true, hidepidReason, 0, 0, nil
	}

	if procPath == "" {
		procPath = "/proc"
	}
	if maxPID <= 0 {
		maxPID = ReadMaxPID("")
	}

	pass1Start := time.Now()

	// 2. Pass 1: Readdir vs Probe
	readdir1, err := GetProcReaddirPIDs(procPath)
	if err != nil {
		return nil, false, "", 0, 0, fmt.Errorf("failed to read %s directory: %w", procPath, err)
	}

	// Determine probe limit using fast path with sane cap
	highestActivePID := 0
	for pid := range readdir1 {
		if pid > highestActivePID {
			highestActivePID = pid
		}
	}
	lastAllocated := ReadLastAllocatedPID("")
	if lastAllocated > highestActivePID {
		highestActivePID = lastAllocated
	}

	probeLimit := maxPID
	saneCap := highestActivePID + 5000
	if saneCap < 65536 {
		saneCap = 65536
	}
	if !fullScan && saneCap < maxPID {
		probeLimit = saneCap
	}

	probed1, err := ProbePIDsRange(ctx, procPath, probeLimit)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, false, "", 0, 0, err
		}
		return nil, false, "", 0, 0, fmt.Errorf("failed to probe PIDs: %w", err)
	}

	var candidates []int
	for pid := range probed1 {
		if !readdir1[pid] {
			// Must be a thread-group leader (process), not a secondary thread
			if isProcessLeader(procPath, pid) {
				candidates = append(candidates, pid)
			}
		}
	}

	pass1Dur := time.Since(pass1Start)

	// If no discrepancies in Pass 1, conclude cleanly
	if len(candidates) == 0 {
		return nil, false, "", pass1Dur, 0, nil
	}

	// 3. Short delay between passes to eliminate transient process race conditions
	select {
	case <-ctx.Done():
		return nil, false, "", pass1Dur, 0, ctx.Err()
	case <-time.After(50 * time.Millisecond):
	}

	pass2Start := time.Now()

	// 4. Pass 2: Re-read directory and verify candidate persistence
	readdir2, err := GetProcReaddirPIDs(procPath)
	if err != nil {
		return nil, false, "", pass1Dur, 0, fmt.Errorf("failed to read %s directory on second pass: %w", procPath, err)
	}

	procFd, err := unix.Open(procPath, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, false, "", pass1Dur, 0, err
	}
	defer unix.Close(procFd)

	isPIDActive := func(pid int) bool {
		var stat unix.Stat_t
		if unix.Fstatat(procFd, strconv.Itoa(pid), &stat, unix.AT_SYMLINK_NOFOLLOW) != nil {
			return false
		}
		return isProcessLeader(procPath, pid)
	}

	confirmed := FilterTwoPassDiscrepancies(candidates, readdir2, isPIDActive)
	pass2Dur := time.Since(pass2Start)
	return confirmed, false, "", pass1Dur, pass2Dur, nil
}

// CheckHiddenPIDs executes the full two-pass hidden-PID detection workflow.
// Fast path: probe up to saneCap (max active PID + headroom, minimum 65536) unless fullScan is enabled.
func CheckHiddenPIDs(ctx context.Context, procPath string, maxPID int, fullScan bool) ([]int, bool, string, error) {
	pids, hasHidepid, reason, _, _, err := CheckHiddenPIDsWithTimings(ctx, procPath, maxPID, fullScan)
	return pids, hasHidepid, reason, err
}
