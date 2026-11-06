package benchmark

import (
	"path/filepath"
	"strings"
	"sync"
)

// MockPackageDB provides a hermetic, in-memory implementation of pkgdb.PackageDB.
type MockPackageDB struct {
	mu         sync.RWMutex
	available  bool
	statusNote string
	ownerMap   map[string]string
}

// NewMockPackageDB creates a new in-memory MockPackageDB.
func NewMockPackageDB() *MockPackageDB {
	return &MockPackageDB{
		available:  true,
		statusNote: "Hermetic In-Memory Benchmark PackageDB",
		ownerMap:   make(map[string]string),
	}
}

// SetOwner registers a package ownership mapping for a path.
func (m *MockPackageDB) SetOwner(path, pkgName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	norm := filepath.ToSlash(filepath.Clean(strings.TrimSuffix(path, " (deleted)")))
	m.ownerMap[norm] = pkgName
	base := filepath.Base(norm)
	m.ownerMap[base] = pkgName
	baseNoExt := strings.TrimSuffix(base, filepath.Ext(base))
	if baseNoExt != "" {
		m.ownerMap[baseNoExt] = pkgName
	}
}

// Owner returns the package owning the path if registered.
func (m *MockPackageDB) Owner(path string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	norm := filepath.ToSlash(filepath.Clean(strings.TrimSuffix(path, " (deleted)")))
	if pkg, ok := m.ownerMap[norm]; ok {
		return pkg, true
	}

	base := filepath.Base(norm)
	if pkg, ok := m.ownerMap[base]; ok {
		return pkg, true
	}

	baseNoExt := strings.TrimSuffix(base, filepath.Ext(base))
	if pkg, ok := m.ownerMap[baseNoExt]; ok {
		return pkg, true
	}

	for k, pkg := range m.ownerMap {
		if strings.HasSuffix(norm, k) || strings.HasSuffix(k, norm) {
			return pkg, true
		}
	}

	return "", false
}

// IsAvailable returns true if mock DB is enabled.
func (m *MockPackageDB) IsAvailable() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.available
}

// VerifyDigest verifies whether actualMD5 matches expected digest in mock.
func (m *MockPackageDB) VerifyDigest(path string, actualMD5 string) (bool, string, bool) {
	return true, "", false
}

func (m *MockPackageDB) VerifyDigestSHA256(path string, actualSHA256 string) (bool, string, bool) {
	return true, "", false
}

// SetAvailable configures whether the mock database reports as available.
func (m *MockPackageDB) SetAvailable(available bool, note string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.available = available
	m.statusNote = note
}

// StatusNote returns the current status note.
func (m *MockPackageDB) StatusNote() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.statusNote
}

// DistroProfile represents an OS package management ecosystem profile for simulation.
type DistroProfile string

const (
	DistroDebian    DistroProfile = "DEBIAN_DPKG"
	DistroArch      DistroProfile = "ARCH_PACMAN"
	DistroRPM       DistroProfile = "REDHAT_RPM"
	DistroUnmanaged DistroProfile = "UNMANAGED_NO_PKGDB"
)

// CreateMockPackageDBForCase builds a hermetic MockPackageDB configured for a specific benchmark case.
func CreateMockPackageDBForCase(c BenchmarkCorpusCase) *MockPackageDB {
	return CreateMockPackageDBForEnvironment(c, DistroDebian)
}

// CreateMockPackageDBForEnvironment builds a hermetic MockPackageDB for a specified distribution environment.
func CreateMockPackageDBForEnvironment(c BenchmarkCorpusCase, distro DistroProfile) *MockPackageDB {
	db := NewMockPackageDB()
	if distro == DistroUnmanaged {
		db.SetAvailable(false, "Unmanaged system (no package manager available)")
		return db
	}

	db.statusNote = string(distro) + " Package Database Simulation"
	if c.IsPackageOwned && c.PackageName != "" {
		db.SetOwner(c.TargetPath, c.PackageName)
	}
	return db
}
