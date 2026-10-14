package scanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/ioc"
	"aether/internal/modules"
	"aether/internal/modules/container"
	"aether/internal/modules/kernel"
	"aether/internal/modules/network"
	"aether/internal/modules/persistence"
	"aether/internal/modules/process"
	"aether/internal/modules/users"
)

// buildDefaultModules instantiates hunting modules based on scan configuration and target root.
func buildDefaultModules(cfg *config.Config, rootFS string, iocEng ioc.Engine, bus *events.EventBus, logger *slog.Logger) []modules.Module {
	procMod := process.NewModule(iocEng, bus, logger)
	persistMod := persistence.NewModuleWithRoot(rootFS, iocEng, bus, logger)
	usersMod := users.NewModuleWithRoot(rootFS, iocEng, bus, logger)
	netMod := network.NewModule(iocEng, bus, logger)
	kernelMod := kernel.NewModuleWithRoots(rootFS, "", "", iocEng, bus, logger)
	containerMod := container.NewModuleWithRoots(rootFS, "", iocEng, bus, logger)

	isCustom := cfg.Scan.ExplicitPaths || (len(cfg.Scan.Paths) > 0 && !slicesEqual(cfg.Scan.Paths, config.DefaultScanPaths()))
	if cfg.Scan.Quick || cfg.Scan.Full {
		isCustom = false
	}

	var defaultMods []modules.Module
	if len(cfg.Scan.Modules) > 0 {
		for _, mName := range cfg.Scan.Modules {
			switch mName {
			case "process":
				defaultMods = append(defaultMods, procMod)
			case "persistence":
				defaultMods = append(defaultMods, persistMod)
			case "users":
				defaultMods = append(defaultMods, usersMod)
			case "network":
				defaultMods = append(defaultMods, netMod)
			case "kernel":
				defaultMods = append(defaultMods, kernelMod)
			case "container":
				defaultMods = append(defaultMods, containerMod)
			}
		}
	} else if isCustom {
		// With --path (custom mode), run only the filesystem module by default.
		defaultMods = []modules.Module{}
	} else {
		defaultMods = []modules.Module{procMod, persistMod, usersMod, netMod, kernelMod, containerMod}
	}
	return defaultMods
}

// runModules executes all configured hunting modules and collects their execution events.
func (s *Scanner) runModules(ctx context.Context, moduleRep *busReporter, isOffline bool, modulesNotRun *[]string, modulesFinishedList *[]events.ModuleFinished) error {
	for _, mod := range s.modules {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if isOffline && (mod.Name() == "process" || mod.Name() == "network") {
				status := "NOT APPLICABLE (offline mode)"
				*modulesNotRun = append(*modulesNotRun, fmt.Sprintf("%s (not applicable in offline mode)", mod.Name()))
				mf := events.ModuleFinished{
					Time:           time.Now(),
					ModuleName:     mod.Name(),
					Duration:       0,
					FindingsCount:  0,
					InspectedCount: 0,
					Status:         status,
				}
				*modulesFinishedList = append(*modulesFinishedList, mf)
				s.bus.Publish(mf)
				continue
			}

			modStart := time.Now()
			s.logger.Debug("running hunting module", slog.String("module", mod.Name()))
			s.bus.Publish(events.ModuleStarted{
				Time:        modStart,
				ModuleName:  mod.Name(),
				Description: mod.Description(),
			})

			findingsBefore := moduleRep.count.Load()
			err := mod.Run(ctx, s.cfg, moduleRep)
			findingsCount := int(moduleRep.count.Load() - findingsBefore)

			status := "OK"
			if errors.Is(err, modules.ErrNotImplemented) {
				status = "NOT IMPLEMENTED"
				*modulesNotRun = append(*modulesNotRun, fmt.Sprintf("%s (not implemented)", mod.Name()))
			} else if errors.Is(err, modules.ErrNotApplicable) {
				status = "NOT APPLICABLE (offline mode)"
				*modulesNotRun = append(*modulesNotRun, fmt.Sprintf("%s (not applicable in offline mode)", mod.Name()))
			} else if err != nil {
				status = "FAILED"
				*modulesNotRun = append(*modulesNotRun, fmt.Sprintf("%s (failed)", mod.Name()))
				s.logger.Warn("module execution returned error",
					slog.String("module", mod.Name()),
					slog.Any("error", err),
				)
			}

			var inspectedCount int64
			if pMod, ok := mod.(*process.Module); ok {
				inspectedCount = pMod.Coverage().Inspected
			} else if permMod, ok := mod.(*persistence.Module); ok {
				inspectedCount = permMod.Coverage().TotalInspected
			} else if uMod, ok := mod.(*users.Module); ok {
				inspectedCount = uMod.Coverage().AccountsInspected
			} else if nMod, ok := mod.(*network.Module); ok {
				inspectedCount = nMod.Coverage().SocketsInspected
			} else if kMod, ok := mod.(*kernel.Module); ok {
				inspectedCount = kMod.Coverage().LoadedModulesInspected
			}

			mf := events.ModuleFinished{
				Time:           time.Now(),
				ModuleName:     mod.Name(),
				Duration:       time.Since(modStart),
				FindingsCount:  findingsCount,
				InspectedCount: inspectedCount,
				Err:            err,
				Status:         status,
			}
			*modulesFinishedList = append(*modulesFinishedList, mf)
			s.bus.Publish(mf)
		}
	}
	return nil
}

// collectModuleCoverage gathers coverage statistics from each module after execution.
func (s *Scanner) collectModuleCoverage(isOffline bool) (*events.ProcessCoverageStats, *events.PersistenceCoverageStats, *events.UsersCoverageStats, *events.NetworkCoverageStats, *events.KernelCoverageStats) {
	var procCov *events.ProcessCoverageStats
	var persistCov *events.PersistenceCoverageStats
	var usersCov *events.UsersCoverageStats
	var netCov *events.NetworkCoverageStats
	var kernelCov *events.KernelCoverageStats

	for _, mod := range s.modules {
		if isOffline && (mod.Name() == "process" || mod.Name() == "network") {
			continue
		}
		if pMod, ok := mod.(*process.Module); ok {
			c := pMod.Coverage()
			if c.Inspected > 0 || !isOffline {
				procCov = &events.ProcessCoverageStats{
					Inspected:         c.Inspected,
					Limited:           c.Limited,
					SkippedPermission: c.SkippedPermission,
					SkippedVanished:   c.SkippedVanished,
					KernelThreads:     c.KernelThreadsSkipped,
					Zombies:           c.ZombiesSkipped,
					NonRootLimited:    c.NonRootLimited,
					HiddenPIDRange:    c.HiddenPIDRange,
					NotHashed:         c.NotHashed,
					DurationBreakdown: c.DurationBreakdown,
				}
			}
		} else if permMod, ok := mod.(*persistence.Module); ok {
			c := permMod.Coverage()
			persistCov = &events.PersistenceCoverageStats{
				TotalInspected:  c.TotalInspected,
				TotalUnreadable: c.TotalUnreadable,
				NotPresent:      c.NotPresent,
				TotalMissing:    c.TotalMissing,
				TotalMasked:     c.TotalMasked,
				MaskedPaths:     c.MaskedPaths,
				NonRootLimited:  c.NonRootLimited,
				PkgDBAvailable:  c.PkgDBAvailable,
				PkgDBNote:       c.PkgDBNote,
				UnreadablePaths: c.UnreadablePaths,
			}
		} else if uMod, ok := mod.(*users.Module); ok {
			c := uMod.Coverage()
			usersCov = &events.UsersCoverageStats{
				AccountsInspected:      c.AccountsInspected,
				SystemAccounts:         c.SystemAccounts,
				ShadowReadable:         c.ShadowReadable,
				ShadowGapNonRoot:       c.ShadowGapNonRoot,
				DuplicateUIDs:          c.DuplicateUIDs,
				PrivilegedGroupMembers: c.PrivilegedGroupMembers,
				DockerLXDMembers:       c.DockerLXDMembers,
				NonRootLimited:         c.NonRootLimited,
			}
		} else if nMod, ok := mod.(*network.Module); ok {
			c := nMod.Coverage()
			if c.SocketsInspected > 0 || !isOffline {
				netCov = &events.NetworkCoverageStats{
					SocketsInspected:       c.SocketsInspected,
					TCPListeners:           c.TCPListeners,
					UDPListeners:           c.UDPListeners,
					EstablishedConnections: c.EstablishedConnections,
					RawPacketSockets:       c.RawPacketSockets,
					KernelOwnedSockets:     c.KernelOwnedSockets,
					UnmappedSocketsNonRoot: c.UnmappedSocketsNonRoot,
					NonRootLimited:         c.NonRootLimited,
					NamespaceNote:          c.NamespaceNote,
				}
			}
		} else if kMod, ok := mod.(*kernel.Module); ok {
			c := kMod.Coverage()
			if c.LoadedModulesInspected > 0 || c.ModprobeFilesInspected > 0 || !isOffline {
				kernelCov = &events.KernelCoverageStats{
					LoadedModulesInspected: c.LoadedModulesInspected,
					SysfsLoadableEntries:   c.SysfsLoadableEntries,
					TaintValue:             c.TaintValue,
					TaintFlags:             c.TaintFlags,
					TaintSeverity:          c.TaintSeverity,
					ModprobeFilesInspected: c.ModprobeFilesInspected,
					GapsNote:               c.GapsNote,
				}
			}
		}
	}
	return procCov, persistCov, usersCov, netCov, kernelCov
}
