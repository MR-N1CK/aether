# Data Model: Feature 003 — Runtime Threat Assessment & Static/Runtime Correlation

**Feature Branch**: `003-runtime-threat-assessment`
**Status**: Complete
**Ratification Date**: 2026-10-03

---

## 1. Entity Relationship Overview

```
+---------------------------------------------------------------------------------+
|                                CORRELATION INDEX                                |
|                                                                                 |
|  +--------------------+        +--------------------+     +------------------+  |
|  |   Static Finding   |        |   Process Entity   |     |  Socket Entity   |  |
|  | - TargetPath       | 1    N | - PID / PPID       | 1 N | - Inode          |  |
|  | - SHA-256 Hash     +--------+ - ExePath          +-----+ - Protocol       |  |
|  | - RuleName         |        | - Comm / Cmdline   |     | - Local / Remote |  |
|  | - EvidenceStrength |        | - Maps / MountNs   |     | - State (LISTEN) |  |
|  +---------+----------+        +---------+----------+     +--------+---------+  |
|            |                             |                         |            |
|            +-----------------------------+-------------------------+            |
|                                          |                                      |
|                                          v                                      |
|                          +-------------------------------+                      |
|                          |    UNIFIED EVIDENCE RECORD    |                      |
|                          | - TargetPath / Hashes         |                      |
|                          | - PID / Comm / Cmdline        |                      |
|                          | - Sockets / Endpoints         |                      |
|                          | - PackageStatus & Context     |                      |
|                          | - CorroboratingSignals []     |                      |
|                          | - EvidenceStrength            |                      |
|                          | - Final Verdict & Confidence  |                      |
|                          +-------------------------------+                      |
+---------------------------------------------------------------------------------+
```

---

## 2. Core Entities & Schema Definitions

### Entity: `ProcessInfo`
Represents an inspected Linux userland process from `/proc/<pid>`.

```go
type ProcessInfo struct {
    PID           int             // Process ID
    PPID          int             // Parent Process ID
    UID           int             // Real User ID
    EUID          int             // Effective User ID
    GID           int             // Real Group ID
    EGID          int             // Effective Group ID
    Comm          string          // Command name from /proc/<pid>/comm
    Cmdline       []string        // Command line arguments from /proc/<pid>/cmdline
    Exe           string          // Symlink target of /proc/<pid>/exe (e.g. "/tmp/bot (deleted)")
    Cwd           string          // Working directory from /proc/<pid>/cwd
    MntNs         string          // Mount namespace inode from /proc/<pid>/ns/mnt
    NetNs         string          // Network namespace inode from /proc/<pid>/ns/net
    ExeStat       *syscall.Stat_t // File stat of /proc/<pid>/exe
    Maps          []MemoryMapping // Parsed executable regions from /proc/<pid>/maps
    OpenSockets   []uint64        // Socket inodes discovered in /proc/<pid>/fd/*
    IsZombie      bool            // True if state is 'Z'
    IsKernel      bool            // True if kernel thread (PPID 2 or PF_KTHREAD)
    ReadableExe   bool            // False if EACCES/EPERM on /proc/<pid>/exe
    ReadableMaps  bool            // False if EACCES/EPERM on /proc/<pid>/maps
    ReadableFDs   bool            // False if EACCES/EPERM on /proc/<pid>/fd
    CoverageGaps  []string        // Specific permission boundary notes
}
```

---

### Entity: `SocketDescriptor`
Represents an active network socket parsed from `/proc/net/*`.

```go
type SocketDescriptor struct {
    Protocol       string              // "TCP", "TCP6", "UDP", "UDP6", "RAW", "RAW6", "PACKET"
    LocalIP        string              // Local IP address (e.g. "0.0.0.0", "127.0.0.1", "::")
    LocalPort      int                 // Local listening or source port (e.g. 22, 4444)
    RemoteIP       string              // Remote peer IP address
    RemotePort     int                 // Remote peer port
    State          string              // "LISTEN", "ESTABLISHED", "CLOSE_WAIT", "RAW"
    Inode          uint64              // Socket inode ID (matched against /proc/*/fd)
    UID            uint32              // Socket owner UID from kernel socket table
    Owner          *ProcessSocketOwner // Owning process resolved from /proc/<pid>/fd
    IsWildcard     bool                // True if bound to 0.0.0.0 or ::
    IsLoopback     bool                // True if bound to 127.0.0.1 or ::1
    IsKernelOwned  bool                // True if owned by kernel subsystem (PID 2/kthread)
    UnmappedReason string              // "non_root_limited", "ephemeral_closed", "kernel_socket"
}
```

---

### Entity: `CorrelationIndex`
In-memory cross-domain registry for finding corroboration.

```go
type CorrelationIndex struct {
    PathToFindings   map[string][]*Finding        // Normalized path -> Findings
    HashToFindings   map[string][]*Finding        // SHA256 -> Findings
    PIDToFindings    map[int][]*Finding           // PID -> Findings
    SocketToFindings map[uint64][]*Finding        // Socket Inode -> Findings
    PathToProcesses  map[string][]*ProcessInfo    // Normalized Exe -> Running processes
    HashToProcesses  map[string][]*ProcessInfo    // Exe SHA256 -> Running processes
    PIDToSockets     map[int][]*SocketDescriptor  // PID -> Owned active sockets
}
```

---

### Entity: `CorroboratingSignal`
Represents an independent operational confirmation linked to a primary finding.

```go
type CorroboratingDomain string

const (
    DomainFilesystem  CorroboratingDomain = "filesystem"
    DomainProcess     CorroboratingDomain = "process"
    DomainNetwork     CorroboratingDomain = "network"
    DomainPersistence CorroboratingDomain = "persistence"
    DomainIOC         CorroboratingDomain = "ioc"
)

type CorroboratingSignal struct {
    Domain      CorroboratingDomain `json:"domain"`
    RuleName    string              `json:"rule_name"`
    Description string              `json:"description"`
    TargetRef   string              `json:"target_ref"` // e.g. "PID: 1337", "Socket: 0.0.0.0:4444", "Cron: /etc/cron.d/bot"
    Confidence  string              `json:"confidence"`
    Timestamp   time.Time           `json:"timestamp"`
}
```

---

## 3. Evidence Strength & Verdict State Transitions

```
                                  +-----------------------+
                                  |    Raw Observation    |
                                  +-----------+-----------+
                                              |
                     +------------------------+------------------------+
                     |                                                 |
             [Permission Denied]                                [Data Readable]
                     |                                                 |
                     v                                                 v
        +-------------------------+                       +-------------------------+
        |   StrengthIncomplete    |                       |    Context Extraction   |
        | - Verdict: UNKNOWN      |                       | - Package Verification  |
        | - Severity: INFO        |                       | - Context Profile       |
        | - Confidence: LOW       |                       +------------+------------+
        +-------------------------+                                    |
                                                                       |
               +-----------------------------+-------------------------+-----------------------------+
               |                             |                                                       |
       [Direct IOC / Attack]     [Corroborated Multi-Vector]                                  [Contextual Anomaly]
               |                             |                                                       |
               v                             v                                                       v
  +-------------------------+   +-------------------------+                             +-------------------------+
  |     StrengthDirect      |   |   StrengthCorroborated  |                             |   StrengthContextual    |
  | - Reverse Shell         |   | - File + Process        |                             | - Standalone Script     |
  | - Memfd ELF Injection   |   | - Process + Socket      |                             | - Deleted Binary / Replaced
  | - Ransomware Locker     |   | - Process + Persistence |                             | - Dev Wildcard Listener |
  | - Cryptographic IOC     |   | - File + Socket + Cron  |                             +------------+------------+
  +------------+------------+   +------------+------------+                                          |
               |                             |                                                       |
               +-----------------------------+                             +-------------------------+-------------------------+
               |                                                           |                                                   |
               v                                                   [Package Owned]                                     [Unowned Artifact]
  +-------------------------+                                              |                                                   |
  |    VerdictMalicious     |                                              v                                                   v
  | - Severity: ALERT       |                                 +-------------------------+                         +-------------------------+
  | - Confidence: HIGH      |                                 |       VerdictSafe       |                         |    VerdictSuspicious    |
  +-------------------------+                                 | - Severity: NOTICE/INFO |                         | - Severity: WARNING     |
                                                              | - Confidence: LOW/MED   |                         | - Confidence: MEDIUM    |
                                                              +-------------------------+                         +-------------------------+
```

---

## 4. Multi-Vector Corroboration Rules Matrix

| Primary Finding Domain | Corroborating Domain 1 | Corroborating Domain 2 | Resulting Strength | Resulting Verdict | Resulting Severity | Resulting Confidence | Example Scenario |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **Filesystem** (Dual-Use Script) | **Process** (Running PID) | **Network** (Wildcard Listener) | `StrengthCorroborated` | `VerdictMalicious` | `ALERT` | `HIGH` | Dropped `/tmp/server.py` running and listening on `0.0.0.0:4444`. |
| **Filesystem** (Suspicious Script) | **Persistence** (Cron Job) | None | `StrengthCorroborated` | `VerdictMalicious` | `ALERT` | `HIGH` | Dropper in `/tmp` installed into `/etc/cron.d/sync`. |
| **Process** (Deleted Binary) | **Package** (Replaced on disk) | None | `StrengthContextual` | `VerdictSafe` | `NOTICE` | `LOW` | `SUSP-UPGRADE-001`: Daemon running pre-upgrade binary pending restart. |
| **Network** (Wildcard Listener) | None (Unowned script) | None | `StrengthContextual` | `VerdictSuspicious` | `WARNING` | `MEDIUM` | `SUSP-LISTEN-001`: Standalone `dev_server.py` listening on `0.0.0.0`. |
| **Network** (Wildcard Listener) | **Package** (Verified daemon) | None | `StrengthContextual` | `VerdictSafe` | `INFO` | `LOW` | `sshd` or `nginx` listening on standard port. |
| **Process** (Fileless memfd) | None | None | `StrengthDirect` | `VerdictMalicious` | `ALERT` | `HIGH` | Anonymous memfd segment containing executable ELF header (`\x7fELF`). |
| **Any** (Permission Denied) | Any | Any | `StrengthIncomplete` | `VerdictUnknown` | `INFO` | `LOW` | Non-root audit encountering protected root-owned `/proc/<pid>`. |
