// Package safeopen provides forensically-sound, read-only file access primitives
// for threat hunting and incident response workflows.
//
// # Forensic Invariants & Threat Boundaries
//
// 1. Immutable Read-Only Invariant:
// All persistent disk targets are opened using O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | O_NOATIME
// (with automatic fallback to omit O_NOATIME when non-root callers lack CAP_FOWNER).
// This guarantees that:
//   - Symlink traversal attacks cannot pivot target reads outside the expected boundary (ELOOP).
//   - Named pipes, FIFOs, and character devices do not hang or block the scanner (O_NONBLOCK + S_IFREG).
//   - Target file timestamps (atime/mtime/ctime) and forensic metadata remain pristine.
//
// 2. Synthetic Kernel Pseudofs Exception Boundary:
// Synthetic pseudofilesystems (/proc/*, /sys/*) are generated dynamically in-memory by Linux kernel
// subsystems. Because synthetic pseudofiles:
//   - Always report stat.Size == 0 regardless of available text content,
//   - Do not support persistent inode atime tracking (rejecting O_NOATIME),
//   - And may present dynamic entry links (/proc/[pid]/exe, /proc/[pid]/fd/*),
//
// Live triage modules inspecting kernel runtime state (/proc/modules, /proc/net/*, /proc/<pid>/*,
// /sys/module/*) interact with these dynamic pseudofs interfaces directly using bounded readers.
// Conversely, ALL persistent on-disk objects (configuration files in /etc, binaries, scripts,
// package manager databases in /var/lib/dpkg or /var/lib/pacman, YARA rulesets, and user triage
// acknowledgments) MUST strictly use safeopen primitives.
package safeopen
