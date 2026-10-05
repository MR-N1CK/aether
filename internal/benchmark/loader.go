package benchmark

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// CorpusLoader manages discovery, parsing, and normalization of benchmark corpus cases.
type CorpusLoader struct {
	CorpusRoot string
}

// NewCorpusLoader creates a loader rooted at the specified directory.
func NewCorpusLoader(corpusRoot string) *CorpusLoader {
	absRoot, err := filepath.Abs(corpusRoot)
	if err != nil {
		absRoot = corpusRoot
	}
	return &CorpusLoader{
		CorpusRoot: filepath.Clean(absRoot),
	}
}

// LoadAll discovers and loads all valid benchmark cases in the corpus directory.
func (l *CorpusLoader) LoadAll() ([]BenchmarkCorpusCase, error) {
	if _, err := os.Stat(l.CorpusRoot); os.IsNotExist(err) {
		return nil, fmt.Errorf("benchmark corpus directory does not exist: %s", l.CorpusRoot)
	}

	var cases []BenchmarkCorpusCase
	seenIDs := make(map[string]string)

	err := filepath.Walk(l.CorpusRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Look for manifest/contract JSON files
		name := info.Name()
		if strings.HasSuffix(name, ".contract.json") || strings.HasSuffix(name, ".manifest.json") || name == "manifest.json" {
			caseObj, err := l.LoadCase(path)
			if err != nil {
				return fmt.Errorf("failed to parse manifest at %s: %w", path, err)
			}

			if existing, exists := seenIDs[caseObj.ID]; exists {
				return fmt.Errorf("duplicate corpus case ID %q found at %s and %s", caseObj.ID, existing, path)
			}
			seenIDs[caseObj.ID] = path
			cases = append(cases, caseObj)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Sort cases deterministically by ID
	sort.Slice(cases, func(i, j int) bool {
		return cases[i].ID < cases[j].ID
	})

	return cases, nil
}

// LoadCase loads a single benchmark case manifest and normalizes paths relative to CorpusRoot.
func (l *CorpusLoader) LoadCase(manifestPath string) (BenchmarkCorpusCase, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return BenchmarkCorpusCase{}, fmt.Errorf("failed to read manifest %s: %w", manifestPath, err)
	}

	var c BenchmarkCorpusCase
	if err := json.Unmarshal(data, &c); err != nil {
		return BenchmarkCorpusCase{}, fmt.Errorf("malformed JSON in manifest %s: %w", manifestPath, err)
	}

	manifestDir := filepath.Dir(manifestPath)
	c.CorpusRelativeDir, _ = filepath.Rel(l.CorpusRoot, manifestDir)
	c.CorpusRelativeDir = filepath.ToSlash(c.CorpusRelativeDir)

	// Resolve the fixture file on disk:
	var fixtureFilePath string

	// 1. Check if TargetPath exists relative to manifestDir
	if c.TargetPath != "" && !filepath.IsAbs(c.TargetPath) {
		relToManifest := filepath.Join(manifestDir, c.TargetPath)
		if _, err := os.Stat(relToManifest); err == nil {
			fixtureFilePath = relToManifest
		} else {
			relToRoot := filepath.Join(l.CorpusRoot, c.TargetPath)
			if _, err := os.Stat(relToRoot); err == nil {
				fixtureFilePath = relToRoot
			}
		}
	}

	// 2. Check for companion file in manifestDir with same base name or non-contract file
	if fixtureFilePath == "" {
		baseName := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(manifestPath), ".contract.json"), ".manifest.json")
		entries, err := os.ReadDir(manifestDir)
		if err == nil {
			// First look for companion matching baseName
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				name := e.Name()
				if (strings.HasPrefix(name, baseName+".") || strings.HasPrefix(name, baseName)) && !strings.HasSuffix(name, ".json") {
					fixtureFilePath = filepath.Join(manifestDir, name)
					break
				}
			}
			// If not found, any non-json file in manifestDir
			if fixtureFilePath == "" {
				for _, e := range entries {
					if e.IsDir() {
						continue
					}
					name := e.Name()
					if !strings.HasSuffix(name, ".json") {
						fixtureFilePath = filepath.Join(manifestDir, name)
						break
					}
				}
			}
		}
	}

	// Read fixture content if found
	if fixtureFilePath != "" {
		if content, err := os.ReadFile(fixtureFilePath); err == nil {
			c.FixtureContent = content
		}
	}

	// Normalize TargetPath relative to CorpusRoot if it is inside CorpusRoot
	if c.TargetPath != "" {
		if !filepath.IsAbs(c.TargetPath) {
			fullTarget := filepath.Join(manifestDir, c.TargetPath)
			if relPath, err := filepath.Rel(l.CorpusRoot, fullTarget); err == nil && !strings.HasPrefix(relPath, "..") {
				c.TargetPath = filepath.ToSlash(relPath)
			}
		}
	} else if fixtureFilePath != "" {
		if relPath, err := filepath.Rel(l.CorpusRoot, fixtureFilePath); err == nil && !strings.HasPrefix(relPath, "..") {
			c.TargetPath = filepath.ToSlash(relPath)
		}
	}

	// Check for companion mock_proc directory
	mockProcPath := filepath.Join(manifestDir, "mock_proc")
	if stat, err := os.Stat(mockProcPath); err == nil && stat.IsDir() {
		c.MockProcDir = mockProcPath
	}

	return c, nil
}
