# Aether Threat Hunter: Detection Engine Architecture & Build Matrix

This document provides a technical comparison of the two compilation targets available in Aether: the **Pure-Go Portable Engine** and the **Static YARA-X High-Assurance Engine**.

---

## 1. Engine Comparison Matrix

| Property | Pure-Go Portable Engine | Static YARA-X Engine |
| :--- | :--- | :--- |
| **Binary Name** | `aether` | `aether-yara-static` |
| **CGO Status** | `CGO_ENABLED=0` (Zero CGO) | `CGO_ENABLED=1` (`-tags yara`) |
| **Supported Architectures** | `linux/amd64`, `linux/arm64` | `linux/amd64` (strictly) |
| **Linkage** | 100% Statically Linked ELF | Statically Linked C++/Rust runtime, dynamic `glibc` |
| **Minimum libc Requirement** | None (Runs on scratch / Alpine musl) | `glibc` $\ge$ 2.31 (Ubuntu 20.04+, RHEL 8+, Debian 11+) |
| **Baseline Startup RSS** | $\le 25\text{MB}$ | $\le 60\text{MB}$ |
| **Peak Full-Scan RSS** | $\le 250\text{MB}$ (500k files) | $\le 250\text{MB}$ (500k files) |
| **Embedded Heuristics** | Full Native Heuristic Suite (4-Tier) | Full Native Heuristic Suite (4-Tier) |
| **Embedded YARA Signatures** | Not evaluated | Full Embedded YARA-X Signatures |
| **Custom YARA Rule Loading** | Disabled | Supported (`/etc/aether/rules/`, `aether rules`) |
| **Portability** | Maximum (Any Linux kernel $\ge$ 3.2) | Standard Modern Linux x86_64 Distributions |
| **Recommended Deployment** | Containers, ARM64 servers, embedded, alpine | x86_64 production servers, deep forensics, incident response |

---

## 2. Detection Capabilities & Behavioral Parity

Both engines implement the identical **Forensic Safety & Read-Only Invariants** mandated by the Aether Constitution:
1. **Zero Target Execution**: Scanned binaries, scripts, or malicious samples are never executed.
2. **Zero Metadata Mutation**: Files are opened with `O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | O_NOATIME` (`safeopen`).
3. **Four-Tier Verdict System**: All outputs report standardized verdicts:
   - `MALICIOUS` (Alerts, Score 85–100)
   - `SUSPICIOUS` (Warnings, Score 50–84)
   - `SAFE` (Clean Inspected Objects, Score 0–49)
   - `UNKNOWN` (Unreadable or Unsupported Formats)
4. **Offline Operation & Zero Telemetry**: Scans and checksum verifications require zero external network connectivity.

---

## 3. How to Choose an Engine

- **Choose Pure-Go (`aether`)** when:
  - Deploying to ARM64 environments (e.g., AWS Graviton, Raspberry Pi).
  - Deploying into minimal containers (Alpine, distroless, scratch).
  - You require an ultra-lightweight startup memory footprint ($\le 25\text{MB}$).
  - Performing fast, unprivileged quick-triage scans without external C library dependencies.

- **Choose Static YARA-X (`aether-yara-static`)** when:
  - Operating on modern `x86_64` Linux hosts (glibc $\ge$ 2.31).
  - You need to compile and execute complex custom YARA rules (`/etc/aether/rules/*.yar`).
  - Conducting deep incident response and static binary analysis using compiled YARA pattern matching.

---

## 4. Build Commands

```bash
# Compile pure-Go static binary
make build-pure

# Compile cross-architecture pure-Go static binaries
make build-cross

# Compile static YARA-X binary (x86_64)
make build-yara-static
```
