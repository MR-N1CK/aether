package process

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/hasher"
	"aether/internal/ioc"
	"aether/internal/report"
)

// ProcessCoverage tracks metrics for process inspection.
type ProcessCoverage struct {
	Inspected            int64
	Limited              int64
	SkippedPermission    int64
	SkippedVanished      int64
	KernelThreadsSkipped int64
	ZombiesSkipped       int64
	NonRootLimited       bool
	HiddenPIDRange       string
	NotHashed            int64
	DurationBreakdown    *events.ProcessDurationBreakdown
}

// Module implements the specialized Linux process threat hunting module.
type Module struct {
	rootFS    string
	procRoot  string
	iocEngine ioc.Engine
	bus       *events.EventBus
	logger    *slog.Logger
	selfMntNs string
	coverage  ProcessCoverage
}

// NewModule creates an initialized process inspection module.
func NewModule(iocEng ioc.Engine, bus *events.EventBus, logger *slog.Logger) *Module {
	return NewModuleWithRoots("", "", iocEng, bus, logger)
}

// NewModuleWithRoots creates an initialized process inspection module with custom rootFS and procRoot for testing.
func NewModuleWithRoots(rootFS, procRoot string, iocEng ioc.Engine, bus *events.EventBus, logger *slog.Logger) *Module {
	if logger == nil {
		logger = slog.Default()
	}
	return &Module{
		rootFS:    rootFS,
		procRoot:  procRoot,
		iocEngine: iocEng,
		bus:       bus,
		logger:    logger,
		selfMntNs: GetSelfMountNs(),
	}
}

func (m *Module) Name() string { return "process" }

func (m *Module) Description() string {
	return "Inspects running processes for anomalies, memory executions, and unlinked binaries"
}

// Coverage returns the statistics from the last process run.
func (m *Module) Coverage() ProcessCoverage {
	return m.coverage
}

type devInoKey struct {
	dev uint64
	ino uint64
}

type processGroupKey struct {
	ruleName string
	exePath  string
	mntNs    string
}

type groupedProcessFinding struct {
	finding    report.Finding
	pids       []int
	baseReason string
}

func formatPIDs(pids []int, maxCount int) string {
	if len(pids) <= maxCount {
		var b strings.Builder
		for i, p := range pids {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(strconv.Itoa(p))
		}
		return b.String()
	}
	var b strings.Builder
	for i := 0; i < maxCount; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(strconv.Itoa(pids[i]))
	}
	b.WriteString(fmt.Sprintf(" (+%d more)", len(pids)-maxCount))
	return b.String()
}

// Run executes the process hunting sweep across all accessible processes in /proc.
func (m *Module) Run(ctx context.Context, cfg *config.Config, rep report.Reporter) error {
	m.logger.Debug("starting process threat hunting module")

	var inspected atomic.Int64
	var limited atomic.Int64
	var skippedPerm atomic.Int64
	var skippedVanished atomic.Int64
	var kernelThreads atomic.Int64
	var zombies atomic.Int64
	var notHashed atomic.Int64

	isNonRoot := os.Geteuid() != 0
	if isNonRoot {
		m.logger.Info("running process hunter as non-root: inspection of other users' processes will be limited",
			slog.Int("euid", os.Geteuid()),
		)
	}

	baseProc := "/proc"
	if m.procRoot != "" {
		baseProc = m.procRoot
	}

	entries, err := os.ReadDir(baseProc)
	if err != nil {
		return fmt.Errorf("failed to enumerate %s: %w", baseProc, err)
	}

	pids := make([]int, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if pid, err := strconv.Atoi(entry.Name()); err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}

	startTime := time.Now()
	procfsStart := time.Now()
	var hashingDur time.Duration
	hashCache := make(map[devInoKey]*hasher.HashStreamResult)

	groups := make(map[processGroupKey]*groupedProcessFinding)
	var groupKeys []processGroupKey

	lastProgress := time.Now()

	selfPID := os.Getpid()
	for i, pid := range pids {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if pid == selfPID && m.procRoot == "" {
			continue
		}

		info, err := ReadProcessInfoWithRoot(m.procRoot, pid)
		if err != nil {
			if err == ErrProcessVanished {
				skippedVanished.Add(1)
				continue
			}
			if err == ErrPermissionDenied {
				skippedPerm.Add(1)
				continue
			}
			skippedPerm.Add(1)
			continue
		}

		// Skip kernel threads quietly
		if IsKernelThread(info) {
			kernelThreads.Add(1)
			continue
		}

		// Zombies are counted separately, never as kernel threads or inspected
		if info.IsZombie {
			zombies.Add(1)
			continue
		}

		// Count as inspected only if exe, cwd, cmdline, and maps were all readable
		if info.IsFullyReadable() {
			inspected.Add(1)
		} else {
			limited.Add(1)
		}

		// Run detection checks
		var signals []*ProcessSignal
		if s := CheckDeletedExe(info, cfg); s != nil {
			signals = append(signals, s)
		}
		if s := CheckExeOrCwdInTemp(info, cfg); s != nil {
			signals = append(signals, s)
		}
		if sigs := CheckFilelessExecution(info, cfg); len(sigs) > 0 {
			signals = append(signals, sigs...)
		}
		if s := CheckAnonymousRWXInjection(info, cfg); s != nil {
			signals = append(signals, s)
		}
		if s := CheckMasquerading(info, cfg); s != nil {
			signals = append(signals, s)
		}
		if s := CheckRootWritableExe(info, cfg); s != nil {
			signals = append(signals, s)
		}
		if s := CheckProcessReverseShell(info, cfg); s != nil {
			signals = append(signals, s)
		}
		if s := CheckContainerCapabilities(info, m.selfMntNs, cfg); s != nil {
			signals = append(signals, s)
		}
		if envSignals := CheckProcessEnviron(info, cfg); len(envSignals) > 0 {
			signals = append(signals, envSignals...)
		}

		// Container namespace score adjustment
		isContainer := ApplyContainerScoreAdjustment(signals, info, m.selfMntNs, cfg.Scan.ContainerScoreReduction)

		// Executable hashing and IOC evaluation:
		// Only hash when the process finding has Severity >= report.SeverityWarning.
		// Respect --max-filesize. Hash at most once per unique (dev, inode).
		var procHashes *hasher.HashStreamResult
		var hashMatch *ioc.MatchResult

		if len(signals) > 0 {
			// Determine initial heuristic severity
			initialSeverity := report.SeverityNotice
			strongCount := 0
			totalScore := 0
			for _, s := range signals {
				totalScore += s.Score
				if s.IsStrong {
					strongCount++
				}
			}
			if strongCount >= 2 && totalScore >= 80 {
				initialSeverity = report.SeverityAlert
			} else if totalScore >= 50 {
				initialSeverity = report.SeverityWarning
			}

			if initialSeverity >= report.SeverityWarning {
				maxSize := cfg.Scan.MaxFileSize
				if maxSize <= 0 {
					maxSize = config.DefaultMaxFileSize
				}

				if info.ExeStat != nil && int64(info.ExeStat.Size) <= maxSize {
					key := devInoKey{dev: uint64(info.ExeStat.Dev), ino: uint64(info.ExeStat.Ino)}
					if cached, ok := hashCache[key]; ok {
						procHashes = cached
					} else {
						hashStart := time.Now()
						procExePath := filepath.Join(baseProc, strconv.Itoa(pid), "exe")
						f, oErr := os.Open(procExePath)
						if oErr == nil {
							hRes, hErr := hasher.StreamHashAndHeader(f)
							f.Close()
							hashingDur += time.Since(hashStart)
							if hErr == nil && hRes != nil {
								procHashes = hRes
								hashCache[key] = hRes
							}
						}
					}
				}
			}

			if procHashes != nil {
				// 1. Allowlist check: suppresses heuristic findings
				if m.iocEngine != nil {
					if isAllowlisted, _ := m.iocEngine.IsAllowlisted(procHashes.Hashes.SHA256); isAllowlisted {
						signals = nil // Clear heuristic signals on allowlist match
					} else {
						// 2. Hash IOC checks
						if match := m.iocEngine.CheckHash(procHashes.Hashes.SHA256); match != nil {
							hashMatch = match
						} else if match := m.iocEngine.CheckHash(procHashes.Hashes.SHA1); match != nil {
							hashMatch = match
						} else if match := m.iocEngine.CheckHash(procHashes.Hashes.MD5); match != nil {
							hashMatch = match
						}

						if hashMatch != nil {
							signals = append(signals, &ProcessSignal{
								RuleName:   hashMatch.RuleName,
								Reason:     hashMatch.Reason,
								Score:      hashMatch.Score,
								Severity:   hashMatch.Severity,
								IsIOCMatch: true,
							})
						}
					}
				}
			}
		}

		if procHashes == nil {
			notHashed.Add(1)
		}

		// Benign-pattern suppression for temporary execution directories
		// Matching files/processes skip temp directory heuristics (unless SUID/SGID, hidden and exec, or hash IOC matched)
		if len(signals) > 0 && hashMatch == nil && m.iocEngine != nil {
			cleanExe := filepath.Clean(strings.TrimSuffix(info.Exe, " (deleted)"))
			cleanCwd := filepath.Clean(info.Cwd)

			var mode uint32
			if st, err := os.Stat(filepath.Join(baseProc, strconv.Itoa(pid), "exe")); err == nil {
				mode = uint32(st.Mode())
			}
			base := filepath.Base(cleanExe)
			isSUIDorSGID := (mode & 06000) != 0
			isHiddenAndExec := strings.HasPrefix(base, ".") && (mode&0111 != 0)

			if !isSUIDorSGID && !isHiddenAndExec {
				isExeBenign, _ := m.iocEngine.IsKnownBenign(cleanExe, uint32(info.Euid))
				isCwdBenign, _ := m.iocEngine.IsKnownBenign(cleanCwd, uint32(info.Euid))

				if isExeBenign || isCwdBenign {
					var remaining []*ProcessSignal
					for _, s := range signals {
						if s.RuleName == "Process_Exe_Or_Cwd_In_Temp" {
							continue
						}
						if s.RuleName == "Process_Deleted_Binary_Suspicious_Location" && isExeBenign {
							continue
						}
						remaining = append(remaining, s)
					}
					signals = remaining
				}
			}
		}

		// If anomalies were detected, consolidate and buffer into groups
		if len(signals) > 0 {
			finding := ConsolidateProcessSignals(signals, info, isContainer)
			if finding != nil {
				if procHashes != nil {
					finding.Hashes["MD5"] = procHashes.Hashes.MD5
					finding.Hashes["SHA1"] = procHashes.Hashes.SHA1
					finding.Hashes["SHA256"] = procHashes.Hashes.SHA256
				}
				cleanExe := filepath.Clean(strings.TrimSuffix(info.Exe, " (deleted)"))
				if cleanExe == "" || cleanExe == "." {
					cleanExe = fmt.Sprintf("[%s]", info.Comm)
				}
				gKey := processGroupKey{
					ruleName: finding.RuleName,
					exePath:  cleanExe,
					mntNs:    info.MntNs,
				}
				if g, ok := groups[gKey]; ok {
					g.pids = append(g.pids, info.PID)
					curScore, _ := g.finding.Metadata["score"].(int)
					newScore, _ := finding.Metadata["score"].(int)
					if newScore > curScore {
						g.finding.Metadata["score"] = newScore
					}
					if finding.Severity == report.SeverityAlert {
						g.finding.Severity = report.SeverityAlert
					}
				} else {
					g := &groupedProcessFinding{
						finding:    *finding,
						pids:       []int{info.PID},
						baseReason: finding.Reason,
					}
					groups[gKey] = g
					groupKeys = append(groupKeys, gKey)
				}
			}
		}

		// Emit Progress event periodically
		if m.bus != nil && (i%20 == 0 || time.Since(lastProgress) > 200*time.Millisecond) {
			lastProgress = time.Now()
			elapsed := time.Since(startTime)
			rate := 0.0
			if elapsed.Seconds() > 0 {
				rate = float64(inspected.Load()) / elapsed.Seconds()
			}
			m.bus.Publish(events.Progress{
				Time:          time.Now(),
				CurrentFiles:  inspected.Load(),
				FilesPerSec:   rate,
				Elapsed:       elapsed,
				ActiveModules: []string{"process"},
			})
		}
	}

	procfsDur := time.Since(procfsStart) - hashingDur
	if procfsDur < 0 {
		procfsDur = 0
	}

	// Emit grouped process findings
	for _, k := range groupKeys {
		g := groups[k]
		pids := g.pids
		f := g.finding
		f.Metadata["count"] = len(pids)
		f.Metadata["pids"] = pids
		f.Metadata["pid"] = pids[0]
		if len(pids) > 1 {
			pidsStr := formatPIDs(pids, 10)
			f.Reason = fmt.Sprintf("%s (count: %d, PIDs: %s)", g.baseReason, len(pids), pidsStr)
		}
		if rep != nil {
			rep.Report(f)
		}
	}

	// Hidden-PID check
	fullScan := false
	if cfg != nil {
		fullScan = cfg.Scan.Full
	}
	hiddenPIDs, hasHidepid, hidepidReason, pass1Dur, pass2Dur, hErr := CheckHiddenPIDsWithTimings(ctx, baseProc, 0, fullScan)
	if hErr != nil {
		m.logger.Warn("hidden PID probe encountered error", slog.Any("error", hErr))
	} else if hasHidepid {
		m.logger.Info("hidden-PID check skipped due to mount option hidepid", slog.String("reason", hidepidReason))
	} else if len(hiddenPIDs) > 0 {
		for _, hpid := range hiddenPIDs {
			f := report.NewFinding(
				"process",
				report.SeverityAlert,
				fmt.Sprintf("/proc/%d", hpid),
				fmt.Sprintf("Process %d is hidden from /proc directory listing but accessible via direct stat (rootkit evasion indicator)", hpid),
				"Process_Hidden_PID",
			)
			f.Metadata["pid"] = hpid
			f.Metadata["score"] = cfg.Scan.ScoreProcHiddenPID
			if f.Metadata["score"] == 0 {
				f.Metadata["score"] = config.DefaultScoreProcHiddenPID
			}
			if rep != nil {
				rep.Report(f)
			}
		}
	}

	hiddenPIDRange := "fast"
	if fullScan {
		hiddenPIDRange = "full"
	}

	totalDur := time.Since(startTime)

	m.coverage = ProcessCoverage{
		Inspected:            inspected.Load(),
		Limited:              limited.Load(),
		SkippedPermission:    skippedPerm.Load(),
		SkippedVanished:      skippedVanished.Load(),
		KernelThreadsSkipped: kernelThreads.Load(),
		ZombiesSkipped:       zombies.Load(),
		NonRootLimited:       isNonRoot,
		HiddenPIDRange:       hiddenPIDRange,
		NotHashed:            notHashed.Load(),
		DurationBreakdown: &events.ProcessDurationBreakdown{
			Procfs:      procfsDur,
			Hashing:     hashingDur,
			HiddenPass1: pass1Dur,
			HiddenPass2: pass2Dur,
			Total:       totalDur,
		},
	}

	m.logger.Debug("process inspection finished",
		slog.Int64("inspected", m.coverage.Inspected),
		slog.Int64("limited", m.coverage.Limited),
		slog.Int64("permission_denied", m.coverage.SkippedPermission),
		slog.Int64("vanished", m.coverage.SkippedVanished),
		slog.Int64("kernel_threads", m.coverage.KernelThreadsSkipped),
		slog.Int64("zombies", m.coverage.ZombiesSkipped),
		slog.Int64("not_hashed", m.coverage.NotHashed),
	)

	return nil
}
