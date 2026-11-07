package realworld_test

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/ioc"
	"aether/internal/modules"
	"aether/internal/modules/kernel"
	"aether/internal/modules/network"
	"aether/internal/modules/persistence"
	"aether/internal/modules/process"
	"aether/internal/modules/users"
	"aether/internal/pkgdb"
	"aether/internal/realworld"
	"aether/internal/report"
	"aether/internal/scanner"
)

func TestPrivilegeBoundaryParity_Snapshot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping DAC privilege-boundary assertions as root: root reads through file permissions, so the boundary under test does not exist (containers run as root)")
	}
	profilesDir := findTestProfilesDir(t)
	profileDir := filepath.Join(profilesDir, realworld.ProfilePrivilegeRestricted)

	loader := realworld.NewProfileLoader()
	snapshot, err := loader.LoadSnapshot(profileDir)
	if err != nil {
		t.Fatalf("LoadSnapshot failed for %s: %v", profileDir, err)
	}

	shadowFile := filepath.Join(snapshot.RootFS, "etc/shadow")
	mapsFile := filepath.Join(snapshot.ProcRoot, "1001/maps")
	_ = os.Chmod(shadowFile, 0000)
	_ = os.Chmod(mapsFile, 0000)
	t.Cleanup(func() {
		_ = os.Chmod(shadowFile, 0644)
		_ = os.Chmod(mapsFile, 0644)
	})

	cfg := config.NewDefaultConfig()
	cfg.Scan.DemoRules = true
	cfg.Scan.Root = "/"
	cfg.Scan.Paths = []string{snapshot.RootFS}
	cfg.Scan.ExplicitPaths = true
	cfg.Scan.Threads = 2
	cfg.Scan.Nice = 0
	cfg.Scan.MaxFileSize = 10 * 1024 * 1024

	bus := events.NewEventBus()
	defer bus.Close()
	rep, err := report.NewConcurrentReporter("")
	if err != nil {
		t.Fatalf("NewConcurrentReporter: %v", err)
	}
	defer rep.Close()
	bus.AttachReporter(rep)

	logger := slog.Default()
	iocEng, _ := ioc.NewEngine(cfg, logger)
	pkgDB := pkgdb.New(snapshot.RootFS)

	procMod := process.NewModuleWithRoots(snapshot.RootFS, snapshot.ProcRoot, iocEng, bus, logger)
	netMod := network.NewModuleWithRoots(snapshot.RootFS, snapshot.ProcRoot, iocEng, bus, logger)
	persistMod := persistence.NewModuleWithRoot(snapshot.RootFS, iocEng, bus, logger)
	usersMod := users.NewModuleWithRoot(snapshot.RootFS, iocEng, bus, logger)
	kernelMod := kernel.NewModuleWithRoots(snapshot.RootFS, snapshot.ProcRoot, snapshot.SysRoot, iocEng, bus, logger)

	mods := []modules.Module{procMod, netMod, persistMod, usersMod, kernelMod}

	sc := scanner.NewScanner(cfg, bus, rep, logger,
		scanner.WithPackageDB(pkgDB),
		scanner.WithModules(mods),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := sc.Run(ctx); err != nil {
		t.Fatalf("Scanner.Run failed: %v", err)
	}

	findings := rep.Findings()

	// Verify coverage gaps exist
	procCov := procMod.Coverage()
	usersCov := usersMod.Coverage()

	if usersCov.ShadowReadable {
		t.Errorf("expected ShadowReadable == false in privilege-restricted environment")
	}
	if !usersCov.ShadowGapNonRoot {
		t.Errorf("expected ShadowGapNonRoot == true in privilege-restricted environment")
	}

	gaps := realworld.CollectCoverageGaps(
		nil,
		&events.ProcessCoverageStats{
			Inspected:         procCov.Inspected,
			Limited:           procCov.Limited,
			SkippedPermission: procCov.SkippedPermission,
			NonRootLimited:    procCov.NonRootLimited,
		},
		&events.UsersCoverageStats{
			AccountsInspected: usersCov.AccountsInspected,
			ShadowReadable:    usersCov.ShadowReadable,
			ShadowGapNonRoot:  usersCov.ShadowGapNonRoot,
			NonRootLimited:    usersCov.NonRootLimited,
		},
		nil,
		nil,
		nil,
	)

	if len(gaps) == 0 {
		t.Fatalf("expected coverage gaps to be recorded for unprivileged scan, got 0")
	}

	synth := realworld.NewAssessmentSynthesizer()
	assessment := synth.Synthesize(findings, gaps)

	t.Logf("Synthesized Posture: %s (Rationale: %s)", assessment.Posture, assessment.SummaryRationale)
	t.Logf("Visibility Gaps Recorded: %d", len(assessment.VisibilityGaps))

	// Invariant 1: Posture must be LIMITED_VISIBILITY, never falsely SAFE or panic to HIGH_RISK
	if assessment.Posture != realworld.PostureLimitedVisibility {
		t.Errorf("expected posture %s, got %s", realworld.PostureLimitedVisibility, assessment.Posture)
	}

	// Invariant 2: Zero false ALERTs
	if assessment.AlertsCount != 0 {
		t.Errorf("expected 0 alerts, got %d", assessment.AlertsCount)
	}

	// Invariant 3: Recommended action must instruct root re-run
	hasRootRemediation := false
	for _, action := range assessment.NextActions {
		if action.Command == "sudo aether scan --full" {
			hasRootRemediation = true
			break
		}
	}
	if !hasRootRemediation {
		t.Errorf("expected action recommending 'sudo aether scan --full', none found")
	}

	// Invariant 4: Manifest compliance must pass 100%
	evaluator := realworld.NewComplianceEvaluator()
	compliance := evaluator.Evaluate(&snapshot.Manifest, findings, assessment.Posture)
	if !compliance.Compliant {
		t.Fatalf("manifest compliance failed: %v", compliance.Violations)
	}
}

func TestPrivilegeBoundaryParity_UnprivilegedVsElevated(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping unprivileged-vs-elevated parity as root: the unprivileged mode under test is indistinguishable from elevated mode when uid == 0 (containers run as root)")
	}
	tempDir := t.TempDir()
	rootFS := filepath.Join(tempDir, "rootfs")
	procDir := filepath.Join(tempDir, "proc")

	_ = os.MkdirAll(filepath.Join(rootFS, "etc"), 0755)
	_ = os.MkdirAll(procDir, 0755)

	_ = os.WriteFile(filepath.Join(rootFS, "etc/passwd"), []byte("root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:user:/home/user:/bin/bash\n"), 0644)
	shadowPath := filepath.Join(rootFS, "etc/shadow")
	_ = os.WriteFile(shadowPath, []byte("root:$6$dummy:19000:0:99999:7:::\nuser:*:19000:0:99999:7:::\n"), 0600)

	// Subtest 1: Unprivileged simulation (shadow made unreadable mode 0000)
	t.Run("Unprivileged_Mode", func(t *testing.T) {
		_ = os.Chmod(shadowPath, 0000)
		defer os.Chmod(shadowPath, 0644)

		logger := slog.Default()
		cfg := config.NewDefaultConfig()
		bus := events.NewEventBus()
		defer bus.Close()
		rep, _ := report.NewConcurrentReporter("")
		defer rep.Close()
		iocEng, _ := ioc.NewEngine(cfg, logger)

		usersMod := users.NewModuleWithRoot(rootFS, iocEng, bus, logger)
		_ = usersMod.Run(context.Background(), cfg, rep)

		uCov := usersMod.Coverage()
		gaps := realworld.CollectCoverageGaps(nil, nil, &events.UsersCoverageStats{
			ShadowReadable:   uCov.ShadowReadable,
			ShadowGapNonRoot: uCov.ShadowGapNonRoot,
		}, nil, nil, nil)

		synth := realworld.NewAssessmentSynthesizer()
		ass := synth.Synthesize(rep.Findings(), gaps)

		if ass.Posture != realworld.PostureLimitedVisibility {
			t.Errorf("unprivileged run expected %s, got %s", realworld.PostureLimitedVisibility, ass.Posture)
		}
		if len(ass.VisibilityGaps) == 0 {
			t.Errorf("unprivileged run must record visibility gaps")
		}
	})

	// Subtest 2: Elevated simulation (shadow readable mode 0600, not world-readable)
	t.Run("Elevated_Mode", func(t *testing.T) {
		_ = os.Chmod(shadowPath, 0600)

		logger := slog.Default()
		cfg := config.NewDefaultConfig()
		bus := events.NewEventBus()
		defer bus.Close()
		rep, _ := report.NewConcurrentReporter("")
		defer rep.Close()
		iocEng, _ := ioc.NewEngine(cfg, logger)

		usersMod := users.NewModuleWithRoot(rootFS, iocEng, bus, logger)
		_ = usersMod.Run(context.Background(), cfg, rep)

		uCov := usersMod.Coverage()
		gaps := realworld.CollectCoverageGaps(nil, nil, &events.UsersCoverageStats{
			ShadowReadable:   uCov.ShadowReadable,
			ShadowGapNonRoot: uCov.ShadowGapNonRoot,
		}, nil, nil, nil)

		synth := realworld.NewAssessmentSynthesizer()
		ass := synth.Synthesize(rep.Findings(), gaps)

		if ass.Posture != realworld.PostureSafe {
			t.Errorf("elevated clean run expected %s, got %s", realworld.PostureSafe, ass.Posture)
		}
		if len(ass.VisibilityGaps) != 0 {
			t.Errorf("elevated clean run must have 0 visibility gaps, got %d", len(ass.VisibilityGaps))
		}
	})
}
