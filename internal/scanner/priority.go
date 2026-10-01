package scanner

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// ApplyNice sets the CPU scheduling priority (niceness) of the current process.
// Niceness values on Linux range from -20 (highest priority) to 19 (lowest priority,
// background execution).
//
// Linux per-thread limitation note:
// In the Linux kernel, setpriority(PRIO_PROCESS, who, nice) applies to the thread group
// (TGID) when who is a PID. However, the Go runtime dynamically multiplexes goroutines
// across multiple OS threads (M) managed by the scheduler. Under some kernel configurations,
// setpriority on individual threads (TID) or runtime worker threads spawned later may exhibit
// quirks or not propagate uniformly to newly created threads.
// Applying Setpriority at early startup using unix.Getpid() before the scanner's worker pool
// and worker goroutines are launched ensures the primary thread group and all subsequently
// spawned runtime threads inherit the lower scheduling priority.
func ApplyNice(niceVal int) error {
	if niceVal < -20 || niceVal > 19 {
		return fmt.Errorf("nice value %d out of valid range (-20 to 19)", niceVal)
	}

	pid := unix.Getpid()
	if err := unix.Setpriority(unix.PRIO_PROCESS, pid, niceVal); err != nil {
		return fmt.Errorf("failed to set process priority (nice %d): %w", niceVal, err)
	}
	return nil
}
