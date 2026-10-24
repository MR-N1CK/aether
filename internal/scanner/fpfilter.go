package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// False-positive filters are the professional tuner's escape hatch, modeled
// on the filter files shipped with Loki/THOR-class scanners: a known-benign
// signature hit (rule + path, optionally description substring) is
// downgraded to an informational, visibly-marked finding instead of polling
// the alert counters. Suppression is never silent — the finding keeps its
// rule name and carries the filter's note so an auditor can review every
// suppression.

// FPFilter is one suppression rule.
type FPFilter struct {
	Rule                string `yaml:"rule"`                           // exact rule name to suppress
	Path                string `yaml:"path"`                           // glob or directory prefix ("/dir" or "/dir/**")
	DescriptionContains string `yaml:"description_contains,omitempty"` // optional substring in the finding reason
	Note                string `yaml:"note"`                           // human-readable justification, shown in output
}

type fpFilterFile struct {
	Version int        `yaml:"version"`
	Filters []FPFilter `yaml:"filters"`
}

// FPFilterSet is the compiled set of loaded false-positive filters.
type FPFilterSet struct {
	filters []FPFilter
	sources []string
}

// LoadFPFilters reads one or more false-positive filter YAML files. Missing
// files are skipped silently (filters are optional tuning); malformed files
// are hard errors so a broken filter never fails open.
func LoadFPFilters(paths []string) (*FPFilterSet, error) {
	set := &FPFilterSet{}
	for _, p := range paths {
		raw, err := os.ReadFile(p) //nolint:gosec // filter files are operator-provided configuration
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("fp-filter file %s: %w", p, err)
		}
		var f fpFilterFile
		if err := yaml.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("fp-filter file %s: %w", p, err)
		}
		for _, flt := range f.Filters {
			if flt.Rule == "" || flt.Path == "" {
				return nil, fmt.Errorf("fp-filter file %s: every filter needs rule and path", p)
			}
			if flt.Note == "" {
				return nil, fmt.Errorf("fp-filter file %s: filter for %s missing note (suppressions must be auditable)", p, flt.Rule)
			}
			set.filters = append(set.filters, flt)
		}
		set.sources = append(set.sources, p)
	}
	return set, nil
}

// fpPathMatch reports whether a finding path matches a filter's path
// expression: "/dir" matches the directory and everything under it,
// "/dir/**" matches only the subtree, and any other value is a standard
// filepath.Match glob.
func fpPathMatch(pattern, path string) bool {
	clean := filepath.ToSlash(filepath.Clean(path))
	subtreeOnly := strings.HasSuffix(pattern, "/**")
	base := strings.TrimSuffix(strings.TrimSuffix(pattern, "**"), "/")

	if subtreeOnly {
		return strings.HasPrefix(clean, base+"/")
	}
	if !strings.ContainsAny(pattern, "*?[") {
		// Bare directory: the directory itself and everything beneath it.
		return clean == base || strings.HasPrefix(clean, base+"/")
	}
	ok, _ := filepath.Match(pattern, clean)
	return ok
}

// Match returns the first filter that suppresses this finding, if any.
func (s *FPFilterSet) Match(rule, path, description string) *FPFilter {
	if s == nil {
		return nil
	}
	for i := range s.filters {
		f := &s.filters[i]
		if f.Rule != rule {
			continue
		}
		if !fpPathMatch(f.Path, path) {
			continue
		}
		if f.DescriptionContains != "" &&
			!strings.Contains(strings.ToLower(description), strings.ToLower(f.DescriptionContains)) {
			continue
		}
		return f
	}
	return nil
}

// Count reports the number of loaded filters (for telemetry).
func (s *FPFilterSet) Count() int {
	if s == nil {
		return 0
	}
	return len(s.filters)
}

// Sources lists the loaded filter file paths (for telemetry).
func (s *FPFilterSet) Sources() []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.sources...)
}
