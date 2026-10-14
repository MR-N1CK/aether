package kernel

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"aether/internal/report"
)

// CheckEBPFProbes inspects tracefs kprobe_events/uprobe_events and pinned bpffs objects
// in /sys/fs/bpf for persistent kernel hooks and stealth interceptors.
func CheckEBPFProbes(ctx context.Context, rootFS, sysRoot string, cov *KernelCoverage, logger *slog.Logger) []report.Finding {
	var findings []report.Finding

	// 1. Tracefs kprobe_events and uprobe_events inspection
	kprobePaths := []string{
		"/sys/kernel/debug/tracing/kprobe_events",
		"/sys/kernel/tracing/kprobe_events",
	}
	uprobePaths := []string{
		"/sys/kernel/debug/tracing/uprobe_events",
		"/sys/kernel/tracing/uprobe_events",
	}

	resolvePath := func(p string) string {
		if sysRoot != "" && strings.HasPrefix(p, "/sys/") {
			return filepath.Join(sysRoot, strings.TrimPrefix(p, "/sys/"))
		}
		if rootFS != "" {
			return filepath.Join(rootFS, strings.TrimPrefix(p, "/"))
		}
		return p
	}

	sensitiveHooks := []string{
		"commit_creds",
		"prepare_kernel_cred",
		"sys_bpf",
		"__x64_sys_bpf",
		"filldir64",
		"security_file_open",
		"security_bprm_check",
		"tcp_v4_rcv",
		"packet_rcv",
		"sys_kill",
		"__x64_sys_kill",
		"sys_execve",
		"__x64_sys_execve",
		"diamorphine",
		"reptile",
		"rootkit",
		"bpfdoor",
	}

	checkTraceFile := func(candidates []string, probeType string) {
		for _, cand := range candidates {
			hostPath := resolvePath(cand)
			data, err := os.ReadFile(hostPath)
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(bytes.NewReader(data))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				lower := strings.ToLower(line)
				isSuspicious := false
				matchedTarget := ""
				for _, sh := range sensitiveHooks {
					if strings.Contains(lower, sh) {
						isSuspicious = true
						matchedTarget = sh
						break
					}
				}

				if isSuspicious {
					f := report.NewFinding(
						"kernel",
						report.SeverityWarning,
						cand,
						fmt.Sprintf("Active dynamic %s hook targeting sensitive kernel function (%s): %s", probeType, matchedTarget, line),
						"Kernel_eBPF_Persistent_Probe",
					)
					f.Metadata["probe_type"] = probeType
					f.Metadata["probe_line"] = line
					f.Metadata["target_symbol"] = matchedTarget
					findings = append(findings, f)
				}
			}
			break // only inspect the first accessible tracefs candidate
		}
	}

	checkTraceFile(kprobePaths, "kprobe")
	checkTraceFile(uprobePaths, "uprobe")

	// 2. BPF filesystem pinned objects (/sys/fs/bpf)
	bpfDir := resolvePath("/sys/fs/bpf")
	if stat, err := os.Stat(bpfDir); err == nil && stat.IsDir() {
		_ = filepath.WalkDir(bpfDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || path == bpfDir {
				return nil
			}
			rel, _ := filepath.Rel(bpfDir, path)
			if rel == "." || rel == "" {
				return nil
			}

			// Legitimate standard system directories in bpffs
			if d.IsDir() {
				switch d.Name() {
				case "xdp", "ip", "tc", "systemd", "snap":
					return filepath.SkipDir
				}
				if strings.HasPrefix(d.Name(), ".") {
					// Hidden directory in bpffs is anomalous
					f := report.NewFinding(
						"kernel",
						report.SeverityWarning,
						path,
						fmt.Sprintf("Hidden directory in eBPF filesystem (/sys/fs/bpf/%s)", rel),
						"Kernel_eBPF_Persistent_Probe",
					)
					f.Metadata["bpf_path"] = path
					findings = append(findings, f)
				}
				return nil
			}

			// Pinned file check
			nameLower := strings.ToLower(d.Name())
			if strings.HasPrefix(d.Name(), ".") ||
				strings.Contains(nameLower, "bpfdoor") ||
				strings.Contains(nameLower, "rootkit") ||
				strings.Contains(nameLower, "stealth") ||
				strings.Contains(nameLower, "hook") ||
				strings.Contains(nameLower, "backdoor") {

				f := report.NewFinding(
					"kernel",
					report.SeverityWarning,
					path,
					fmt.Sprintf("Suspicious pinned eBPF object in bpffs: %s", rel),
					"Kernel_eBPF_Persistent_Probe",
				)
				f.Metadata["bpf_object"] = rel
				findings = append(findings, f)
			}
			return nil
		})
	}

	return findings
}
