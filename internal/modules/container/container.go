package container

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/ioc"
	"aether/internal/pkgdb"
	"aether/internal/report"
)

// ContainerCoverage captures metrics from container inspection.
type ContainerCoverage struct {
	SocketsInspected int64
	InsideContainer  bool
	RuntimeDetected  string
	NonRootLimited   bool
}

// Module implements threat hunting inspection for container escapes and socket permissions.
type Module struct {
	rootFS    string
	procRoot  string
	iocEngine ioc.Engine
	bus       *events.EventBus
	logger    *slog.Logger
	pkgDB     pkgdb.PackageDB
	coverage  ContainerCoverage
}

// NewModule creates an initialized container module targeting the host system.
func NewModule(iocEng ioc.Engine, bus *events.EventBus, logger *slog.Logger) *Module {
	return NewModuleWithRoots("", "", iocEng, bus, logger)
}

// NewModuleWithRoots creates an initialized container module with injectable roots for testing.
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

func (m *Module) Name() string { return "container" }

func (m *Module) Description() string {
	return "Inspects container runtime control sockets (Docker, Containerd, Podman) and detects container breakout/escape vectors"
}

// Coverage returns the inspection statistics from the last container module run.
func (m *Module) Coverage() ContainerCoverage {
	return m.coverage
}

func (m *Module) resolve(subPath string) string {
	if m.rootFS == "" || m.rootFS == "/" {
		return "/" + strings.TrimPrefix(subPath, "/")
	}
	return filepath.Join(m.rootFS, strings.TrimPrefix(subPath, "/"))
}

func (m *Module) resolveProc(subPath string) string {
	if m.procRoot != "" {
		return filepath.Join(m.procRoot, strings.TrimPrefix(subPath, "/"))
	}
	return m.resolve(subPath)
}

// detectContainerEnvironment checks whether the target root is inside a container.
func (m *Module) detectContainerEnvironment() (bool, string) {
	// 1. Check for standard container indicator files
	if _, err := os.Stat(m.resolve("/.dockerenv")); err == nil {
		return true, "docker"
	}
	if _, err := os.Stat(m.resolve("/run/.containerenv")); err == nil {
		return true, "podman"
	}

	// 2. Check /proc/1/cgroup
	cgroupPath := m.resolveProc("/proc/1/cgroup")
	f, err := os.Open(cgroupPath)
	if err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.ToLower(scanner.Text())
			if strings.Contains(line, "docker") {
				return true, "docker"
			}
			if strings.Contains(line, "containerd") {
				return true, "containerd"
			}
			if strings.Contains(line, "kubepods") {
				return true, "kubernetes"
			}
			if strings.Contains(line, "lxc") {
				return true, "lxc"
			}
			if strings.Contains(line, "libpod") {
				return true, "podman"
			}
		}
	}

	return false, ""
}

// Run executes container threat hunting checks.
func (m *Module) Run(ctx context.Context, cfg *config.Config, rep report.Reporter) error {
	m.logger.Debug("starting container threat hunting module",
		slog.String("root_fs", m.rootFS),
		slog.String("proc_root", m.procRoot),
	)

	cov := ContainerCoverage{
		NonRootLimited: os.Geteuid() != 0 && m.rootFS == "",
	}

	isInside, runtimeName := m.detectContainerEnvironment()
	cov.InsideContainer = isInside
	cov.RuntimeDetected = runtimeName

	var findings []report.Finding

	socketCandidates := []string{
		"/var/run/docker.sock",
		"/run/docker.sock",
		"/run/containerd/containerd.sock",
		"/var/run/containerd/containerd.sock",
		"/run/podman/podman.sock",
		"/var/run/podman/podman.sock",
	}

	for _, sockPath := range socketCandidates {
		target := m.resolve(sockPath)
		stat, err := os.Stat(target)
		if err != nil {
			continue
		}
		cov.SocketsInspected++

		// Check 1: World-writable socket on host or inside container (ALERT 85)
		if stat.Mode()&0002 != 0 {
			f := report.NewFinding(
				"container",
				report.SeverityAlert,
				sockPath,
				fmt.Sprintf("Container runtime control socket %s is world-writable (mode %04o)", sockPath, stat.Mode().Perm()),
				"Container_Socket_World_Writable",
			)
			f.Metadata["score"] = 85
			f.Metadata["permissions"] = fmt.Sprintf("%04o", stat.Mode().Perm())
			findings = append(findings, f)
		}

		// Check 2: Docker/Containerd socket mounted inside a running container (escape path, ALERT 90)
		if isInside {
			f := report.NewFinding(
				"container",
				report.SeverityAlert,
				sockPath,
				fmt.Sprintf("Host container control socket %s is mounted inside running container (%s runtime) - critical breakout vector", sockPath, runtimeName),
				"Container_Escape_Mounted_Docker_Socket",
			)
			f.Metadata["score"] = 90
			f.Metadata["runtime"] = runtimeName
			f.Metadata["escape_vector"] = true
			findings = append(findings, f)
		}
	}

	for _, f := range findings {
		if rep != nil {
			rep.Report(f)
		}
	}

	m.coverage = cov
	return nil
}
