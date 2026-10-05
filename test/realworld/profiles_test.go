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

func findTestProfilesDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	for i := 0; i < 5; i++ {
		candidate := filepath.Join(dir, "testdata", "realworld_corpus", "profiles")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not find testdata/realworld_corpus/profiles")
	return ""
}

func runProfileAudit(t *testing.T, profileDir string) (*realworld.EnvironmentSnapshot, []report.Finding, realworld.ComprehensiveSystemAssessment, *realworld.ComplianceResult) {
	t.Helper()

	loader := realworld.NewProfileLoader()
	snapshot, err := loader.LoadSnapshot(profileDir)
	if err != nil {
		t.Fatalf("LoadSnapshot failed for %s: %v", profileDir, err)
	}

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
		t.Fatalf("Scanner.Run failed for profile %s: %v", snapshot.ProfileID, err)
	}

	findings := rep.Findings()

	var gaps []realworld.CoverageGap
	if snapshot.ProfileID == realworld.ProfilePrivilegeRestricted {
		procCov := procMod.Coverage()
		usersCov := usersMod.Coverage()
		gaps = realworld.CollectCoverageGaps(
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
	}

	synth := realworld.NewAssessmentSynthesizer()
	assessment := synth.Synthesize(findings, gaps)

	evaluator := realworld.NewComplianceEvaluator()
	compliance := evaluator.Evaluate(&snapshot.Manifest, findings, assessment.Posture)

	return snapshot, findings, assessment, compliance
}

func TestRealWorldEnvironmentProfiles(t *testing.T) {
	profilesDir := findTestProfilesDir(t)

	profiles := []struct {
		id             string
		expectedStatus realworld.SystemPosture
		maxAlerts      int
	}{
		{realworld.ProfileDesktopStandard, realworld.PostureSafe, 0},
		{realworld.ProfileServerWeb, realworld.PostureSafe, 0},
		{realworld.ProfileServerMinimal, realworld.PostureSafe, 0},
		{realworld.ProfileUpgradedPending, realworld.PostureAttentionRequired, 0},
		{realworld.ProfileWorkstationPentest, realworld.PostureSafe, 0},
		{realworld.ProfileWorkstationDev, realworld.PostureSafe, 0},
		{realworld.ProfileContainerHost, realworld.PostureSafe, 0},
		{realworld.ProfilePackageMixed, realworld.PostureSafe, 0},
		{realworld.ProfilePrivilegeRestricted, realworld.PostureLimitedVisibility, 0},
	}

	for _, tc := range profiles {
		tc := tc
		t.Run(tc.id, func(t *testing.T) {
			profileDir := filepath.Join(profilesDir, tc.id)
			snapshot, findings, assessment, compliance := runProfileAudit(t, profileDir)

			t.Logf("[%s] Scanned %d findings; Posture: %s; Compliant: %v",
				tc.id, len(findings), assessment.Posture, compliance.Compliant)

			for _, f := range findings {
				t.Logf("  finding: rule=%s sev=%s verdict=%s path=%s reason=%s",
					f.RuleName, f.Severity, f.Verdict, f.Path, f.Reason)
			}

			if !compliance.Compliant {
				t.Errorf("[%s] Manifest compliance failed with violations: %v", tc.id, compliance.Violations)
			}

			if assessment.AlertsCount > tc.maxAlerts {
				t.Errorf("[%s] Expected at most %d alerts, got %d", tc.id, tc.maxAlerts, assessment.AlertsCount)
			}

			if assessment.Posture != tc.expectedStatus {
				t.Errorf("[%s] Expected posture %s, got %s (rationale: %s)",
					tc.id, tc.expectedStatus, assessment.Posture, assessment.SummaryRationale)
			}

			if snapshot.ProfileID != tc.id {
				t.Errorf("Mismatched profile ID: expected %s, got %s", tc.id, snapshot.ProfileID)
			}
		})
	}
}
