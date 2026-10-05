# Contract: Systemd Scheduled Scan Service & Timer Contract

**Feature Branch**: `005-packaging-and-release`  
**Created**: 2026-10-04  
**Status**: Active

---

## 1. Overview

Aether provides an optional, opt-in systemd integration for automated background security audits. The integration comprises:
1. `aether-scan.service`: Hardened oneshot system service executing a full system scan with low CPU and I/O scheduling.
2. `aether-scan.timer`: Weekly trigger with randomized jitter to prevent resource contention.

---

## 2. Service Unit Contract: `aether-scan.service`

Location: `/usr/lib/systemd/system/aether-scan.service`  
Mode: `0644`  
Owner: `root:root`

```ini
[Unit]
Description=Aether Deep Linux Security Assessment & Threat Hunt
Documentation=man:aether(1) man:aether-scan(1)
After=network.target local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/bin/aether scan --full --no-report --json-out=/var/log/aether/audit-%%Y%%m%%d.json
WorkingDirectory=/var/log/aether

# Resource Governance & Idle Scheduling
Nice=19
IOSchedulingClass=idle
CPUSchedulingPolicy=other

# Filesystem Isolation & Sandboxing
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/log/aether
LogsDirectory=aether

# CRITICAL Threat Hunting Requirement: PrivateTmp MUST BE FALSE
# Enabling PrivateTmp isolates the unit from the host's actual /tmp, blinding Aether
# to dropped malware and temporary fileless artifacts.
PrivateTmp=false

# Privilege Hardening & Least Privilege
NoNewPrivileges=true
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE
AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE
LockPersonality=true
MemoryDenyWriteExecute=false
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
RestrictRealtime=true

# Output & Logging
StandardOutput=journal
StandardError=journal
```

---

## 3. Timer Unit Contract: `aether-scan.timer`

Location: `/usr/lib/systemd/system/aether-scan.timer`  
Mode: `0644`  
Owner: `root:root`

```ini
[Unit]
Description=Weekly Aether Deep Security Assessment Trigger
Documentation=man:aether(1)

[Timer]
OnCalendar=weekly
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
```

---

## 4. Operational Invariants

1. **Disabled by Default**: Upon initial package installation, `aether-scan.timer` MUST be inactive. The administrator must explicitly issue:
   ```bash
   systemctl enable --now aether-scan.timer
   ```
2. **Local Logging Only**: Output MUST be written strictly to local filesystem (`/var/log/aether/`) and systemd journal (`journalctl -u aether-scan`). Zero network communication.
3. **No Execution of Inspected Targets**: The scan executed by systemd operates under standard Aether read-only invariants: zero process killing, zero file modification, zero payload execution.
