package network

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/ioc"
	"aether/internal/pkgdb"
	"aether/internal/report"
)

// NetworkCoverage captures metrics and scope notes from network inspection.
type NetworkCoverage struct {
	SocketsInspected       int64
	TCPListeners           int64
	UDPListeners           int64
	EstablishedConnections int64
	RawPacketSockets       int64
	KernelOwnedSockets     int64
	UnmappedSocketsNonRoot int64
	NonRootLimited         bool
	NamespaceNote          string
}

// Module implements threat hunting inspection for Linux sockets, network listeners, and C2 connections.
type Module struct {
	rootFS    string
	procRoot  string
	iocEngine ioc.Engine
	bus       *events.EventBus
	logger    *slog.Logger
	pkgDB     pkgdb.PackageDB
	coverage  NetworkCoverage
}

// NewModule creates an initialized network module targeting the host system.
func NewModule(iocEng ioc.Engine, bus *events.EventBus, logger *slog.Logger) *Module {
	return NewModuleWithRoots("", "", iocEng, bus, logger)
}

// NewModuleWithRoots creates an initialized network module with injectable rootFS and procRoot for testing.
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
		pkgDB:     pkgdb.New(rootFS),
	}
}

func (m *Module) Name() string { return "network" }

func (m *Module) Description() string {
	return "Inspects network sockets (/proc/net/tcp, udp, raw, packet), listeners, and established connections for C2 indicators"
}

// Coverage returns the statistics from the last network module execution.
func (m *Module) Coverage() NetworkCoverage {
	return m.coverage
}

// Run executes the complete network inspection sweep.
func (m *Module) Run(ctx context.Context, cfg *config.Config, rep report.Reporter) error {
	m.logger.Debug("starting network threat hunting module", slog.String("proc_root", m.procRoot))

	isRoot := os.Geteuid() == 0 || m.procRoot != ""
	isNonRoot := !isRoot

	cov := NetworkCoverage{
		NonRootLimited: isNonRoot,
		NamespaceNote:  "Snapshot of current network namespace (container network namespaces are not inspected)",
	}

	// 1. Build socket inode -> process map from /proc/<pid>/fd
	socketToProc := BuildSocketProcessMap(m.procRoot, m.logger)

	// 2. Parse all socket tables from /proc/net/*
	sockets, pErr := ParseAllSockets(m.procRoot, socketToProc, m.logger)
	if pErr != nil {
		m.logger.Warn("error parsing network socket tables", slog.Any("error", pErr))
	}

	// 3. Evaluate detections
	findings := EvaluateNetworkDetections(ctx, sockets, isRoot, cfg, m.iocEngine, &cov, m.logger)

	// Report findings
	for _, f := range findings {
		if rep != nil {
			rep.Report(f)
		}
	}

	m.coverage = cov
	return nil
}

// ProcessSocketOwner holds metadata for a process owning a network socket.
type ProcessSocketOwner struct {
	PID      int
	Comm     string
	ExePath  string
	Cmdline  string
	UID      uint32
	IsKernel bool
}

// BuildSocketProcessMap maps socket inode IDs to owning processes by inspecting /proc/<pid>/fd.
func BuildSocketProcessMap(procRoot string, logger *slog.Logger) map[uint64]*ProcessSocketOwner {
	socketMap := make(map[uint64]*ProcessSocketOwner)

	baseProc := "/proc"
	if procRoot != "" {
		baseProc = procRoot
	}

	entries, err := os.ReadDir(baseProc)
	if err != nil {
		return socketMap
	}

	myPID := os.Getpid()

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}

		// Self-exclusion: skip our own process
		if pid == myPID && procRoot == "" {
			continue
		}

		pidDir := filepath.Join(baseProc, entry.Name())
		fdDir := filepath.Join(pidDir, "fd")

		// Read comm
		commBytes, _ := os.ReadFile(filepath.Join(pidDir, "comm"))
		comm := strings.TrimSpace(string(commBytes))

		// Read cmdline
		cmdBytes, _ := os.ReadFile(filepath.Join(pidDir, "cmdline"))
		cmdline := strings.ReplaceAll(string(cmdBytes), "\x00", " ")

		// Read exe
		exePath, _ := os.Readlink(filepath.Join(pidDir, "exe"))

		// Check if kernel thread (pid 2 or ppid 2 / PF_KTHREAD in stat)
		isKernel := pid == 2
		if statBytes, err := os.ReadFile(filepath.Join(pidDir, "stat")); err == nil {
			statStr := string(statBytes)
			if lastParen := strings.LastIndex(statStr, ")"); lastParen != -1 && len(statStr) > lastParen+2 {
				rest := strings.Fields(statStr[lastParen+2:])
				if len(rest) >= 7 {
					ppid, _ := strconv.Atoi(rest[1])
					flags, _ := strconv.ParseUint(rest[6], 10, 64)
					if ppid == 2 || (flags&0x200000) != 0 {
						isKernel = true
					}
				}
			}
		}

		owner := &ProcessSocketOwner{
			PID:      pid,
			Comm:     comm,
			ExePath:  exePath,
			Cmdline:  cmdline,
			IsKernel: isKernel,
		}

		fdEntries, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fdEntries {
			linkTarget, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}

			// socket:[12345] or [0000]:12345
			if strings.HasPrefix(linkTarget, "socket:[") && strings.HasSuffix(linkTarget, "]") {
				inodeStr := linkTarget[8 : len(linkTarget)-1]
				if inode, err := strconv.ParseUint(inodeStr, 10, 64); err == nil {
					socketMap[inode] = owner
				}
			}
		}
	}

	return socketMap
}
