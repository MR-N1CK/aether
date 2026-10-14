package realworld

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aether/internal/pkgdb"
)

// EnvironmentSnapshot represents an instantiated hermetic environment fixture.
type EnvironmentSnapshot struct {
	ProfileID string
	Manifest  ProfileManifest
	RootDir   string // Physical root of the profile fixture
	RootFS    string // Virtual root filesystem
	ProcRoot  string // Virtual /proc filesystem
	SysRoot   string // Virtual /sys filesystem
	PackageDB pkgdb.PackageDB
}

// ProfileLoader loads and validates real-world environment profiles and manifests.
type ProfileLoader struct{}

// NewProfileLoader creates a new ProfileLoader instance.
func NewProfileLoader() *ProfileLoader {
	return &ProfileLoader{}
}

// LoadManifest reads, parses, and validates a ProfileManifest JSON file.
func (l *ProfileLoader) LoadManifest(manifestPath string) (*ProfileManifest, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read manifest file %s: %w", manifestPath, err)
	}

	var manifest ProfileManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse manifest %s: %w", manifestPath, err)
	}

	if err := l.ValidateManifest(&manifest); err != nil {
		return nil, fmt.Errorf("validate manifest %s: %w", manifestPath, err)
	}

	return &manifest, nil
}

// ValidateManifest verifies that the manifest adheres to schema invariants.
func (l *ProfileLoader) ValidateManifest(m *ProfileManifest) error {
	if m == nil {
		return fmt.Errorf("manifest cannot be nil")
	}

	if m.ProfileID == "" {
		return fmt.Errorf("missing profile_id")
	}

	validProfiles := map[string]bool{
		ProfileDesktopStandard:     true,
		ProfileWorkstationDev:      true,
		ProfileWorkstationPentest:  true,
		ProfileServerWeb:           true,
		ProfileServerMinimal:       true,
		ProfileContainerHost:       true,
		ProfilePackageMixed:        true,
		ProfileUpgradedPending:     true,
		ProfilePrivilegeRestricted: true,
	}
	if !validProfiles[m.ProfileID] {
		return fmt.Errorf("unknown profile_id: %q", m.ProfileID)
	}

	if m.Version == "" {
		return fmt.Errorf("missing version")
	}

	switch m.ExpectedStatus {
	case PostureSafe, PostureAttentionRequired, PostureHighRisk, PostureLimitedVisibility:
		// Valid
	default:
		return fmt.Errorf("invalid expected_status: %q", m.ExpectedStatus)
	}

	if m.MaxAcceptableAlerts < 0 {
		return fmt.Errorf("max_acceptable_alerts cannot be negative")
	}
	if m.MaxAcceptableWarnings < 0 {
		return fmt.Errorf("max_acceptable_warnings cannot be negative")
	}

	for i, f := range m.AcceptableFindings {
		if f.RuleName == "" {
			return fmt.Errorf("acceptable_finding[%d]: missing rule_name", i)
		}
		if f.ExpectedSeverity == "" {
			return fmt.Errorf("acceptable_finding[%d]: missing expected_severity", i)
		}
		if f.ExpectedVerdict == "" {
			return fmt.Errorf("acceptable_finding[%d]: missing expected_verdict", i)
		}
	}

	for i, f := range m.ForbiddenFindings {
		if f.RulePattern == "" {
			return fmt.Errorf("forbidden_finding[%d]: missing rule_pattern", i)
		}
		if f.Reason == "" {
			return fmt.Errorf("forbidden_finding[%d]: missing reason", i)
		}
	}

	for i, d := range m.DualUseSoftware {
		if d.ToolName == "" {
			return fmt.Errorf("dual_use_software[%d]: missing tool_name", i)
		}
		if d.PrimaryBinary == "" {
			return fmt.Errorf("dual_use_software[%d]: missing primary_binary", i)
		}
		if d.ExpectedPassiveVerdict == "" {
			return fmt.Errorf("dual_use_software[%d]: missing expected_passive_verdict", i)
		}
	}

	return nil
}

// LoadSnapshot inspects a profile directory, loads its profile_manifest.json, and normalizes paths.
func (l *ProfileLoader) LoadSnapshot(profileDir string) (*EnvironmentSnapshot, error) {
	absDir, err := filepath.Abs(profileDir)
	if err != nil {
		return nil, fmt.Errorf("resolve profileDir %s: %w", profileDir, err)
	}

	manifestPath := filepath.Join(absDir, "profile_manifest.json")
	manifest, err := l.LoadManifest(manifestPath)
	if err != nil {
		return nil, err
	}

	rootFS := absDir
	if subRoot := filepath.Join(absDir, "rootfs"); isDir(subRoot) {
		rootFS = subRoot
	}

	procRoot := ""
	if subProc := filepath.Join(absDir, "proc"); isDir(subProc) {
		procRoot = subProc
	} else if subProc := filepath.Join(rootFS, "proc"); isDir(subProc) {
		procRoot = subProc
	}

	sysRoot := ""
	if subSys := filepath.Join(absDir, "sys"); isDir(subSys) {
		sysRoot = subSys
	} else if subSys := filepath.Join(rootFS, "sys"); isDir(subSys) {
		sysRoot = subSys
	}

	return &EnvironmentSnapshot{
		ProfileID: manifest.ProfileID,
		Manifest:  *manifest,
		RootDir:   absDir,
		RootFS:    rootFS,
		ProcRoot:  procRoot,
		SysRoot:   sysRoot,
		PackageDB: pkgdb.New(rootFS),
	}, nil
}

// NormalizeRelativePath strips the physical snapshot root prefix and returns the canonical target path.
func (s *EnvironmentSnapshot) NormalizeRelativePath(physPath string) string {
	if s.RootFS != "" && strings.HasPrefix(physPath, s.RootFS) {
		rel := strings.TrimPrefix(physPath, s.RootFS)
		if !strings.HasPrefix(rel, "/") {
			rel = "/" + rel
		}
		return rel
	}
	if strings.HasPrefix(physPath, s.RootDir) {
		rel := strings.TrimPrefix(physPath, s.RootDir)
		if !strings.HasPrefix(rel, "/") {
			rel = "/" + rel
		}
		return rel
	}
	return physPath
}

func isDir(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}
