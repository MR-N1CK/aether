package report_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"aether/internal/report"
)

var (
	reRuleNameField = regexp.MustCompile(`RuleName:\s*"([A-Za-z0-9_]+)"`)
	reRuleField     = regexp.MustCompile(`Rule:\s*"([A-Za-z0-9_]+)"`)
	reNameField     = regexp.MustCompile(`Name:\s*"([A-Za-z0-9_]+)"`)
	reNewFinding    = regexp.MustCompile(`NewFinding\([^,]+,[^,]+,[^,]+,[^,]+,\s*"([A-Za-z0-9_]+)"\)`)
	reYaraRule      = regexp.MustCompile(`(?m)^rule\s+([A-Za-z0-9_]+)\s*\{`)
	reVarRuleAssign = regexp.MustCompile(`\b(?:rule|primaryRule|ruleName)\s*(?::=|=)\s*"([A-Za-z0-9_]+)"`)
)

// allowlistedRulePrefixes covers dynamically generated rules (such as cryptographic IOC hashes),
// generic informational metadata, or known synthetic test rules.
func isAllowlistedRule(rule string) bool {
	if strings.HasPrefix(rule, "IOC_Hash_") ||
		strings.HasPrefix(rule, "IOC_Path_") ||
		strings.HasPrefix(rule, "IOC_Network_") ||
		strings.HasPrefix(rule, "RULE_") ||
		strings.HasPrefix(rule, "Test_") ||
		strings.HasPrefix(rule, "Fake_") ||
		strings.HasPrefix(rule, "Mock_") ||
		rule == "YARA_Skipped_Oversize" ||
		rule == "YARA_Rule_File" ||
		rule == "Generic_Threat" ||
		rule == "Generic_Warn" ||
		rule == "Generic_Notice" ||
		rule == "Unregistered_Custom_Rule_XYZ" {
		return true
	}
	return false
}

func findRepoRoot(t *testing.T) string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to get caller info for registry coverage test")
	}
	dir := filepath.Dir(filename)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not find repo root with go.mod")
	return ""
}

func TestEmittedRules_AllResolveInRegistry(t *testing.T) {
	repoRoot := findRepoRoot(t)
	emitted := make(map[string][]string) // rule -> source locations

	scanDirs := []string{
		"internal/scanner",
		"internal/yara",
		"internal/modules",
		"cmd/aether",
	}

	for _, relDir := range scanDirs {
		dir := filepath.Join(repoRoot, relDir)
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "portfolio" || d.Name() == "vendor" || d.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			// Skip test files, mock fixtures, and registry definitions themselves
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}
			if strings.HasSuffix(path, "rule_metadata.go") || strings.HasSuffix(path, "rule_metadata_modules.go") {
				return nil
			}
			if !strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, ".yar") {
				return nil
			}

			contentBytes, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			content := string(contentBytes)
			relPath, _ := filepath.Rel(repoRoot, path)

			for _, match := range reRuleNameField.FindAllStringSubmatch(content, -1) {
				emitted[match[1]] = append(emitted[match[1]], relPath)
			}
			for _, match := range reRuleField.FindAllStringSubmatch(content, -1) {
				emitted[match[1]] = append(emitted[match[1]], relPath)
			}
			for _, match := range reNewFinding.FindAllStringSubmatch(content, -1) {
				emitted[match[1]] = append(emitted[match[1]], relPath)
			}
			for _, match := range reYaraRule.FindAllStringSubmatch(content, -1) {
				emitted[match[1]] = append(emitted[match[1]], relPath)
			}
			for _, match := range reVarRuleAssign.FindAllStringSubmatch(content, -1) {
				emitted[match[1]] = append(emitted[match[1]], relPath)
			}
			for _, match := range reNameField.FindAllStringSubmatch(content, -1) {
				name := match[1]
				if strings.HasPrefix(name, "Heuristic_") ||
					strings.HasPrefix(name, "Script_") ||
					strings.HasPrefix(name, "Webshell_") ||
					strings.HasPrefix(name, "File_") ||
					strings.HasPrefix(name, "Trojaned_") ||
					strings.HasPrefix(name, "High_Entropy_") ||
					strings.HasPrefix(name, "Persistence_") {
					emitted[name] = append(emitted[name], relPath)
				}
			}

			return nil
		})
		if err != nil {
			t.Fatalf("error walking directory %s: %v", relDir, err)
		}
	}

	var allRules []string
	for r := range emitted {
		allRules = append(allRules, r)
	}
	sort.Strings(allRules)

	t.Logf("Total extracted emitted rules: %d", len(allRules))
	t.Logf("Total registered rules in registry: %d", report.RegisteredRuleCount())

	var missing []string
	for _, r := range allRules {
		if isAllowlistedRule(r) {
			continue
		}

		meta, ok := report.LookupRuleMeta(r)
		if !ok {
			missing = append(missing, r)
			t.Errorf("Rule %q emitted in %v is not registered in report.RegisterRuleMeta", r, emitted[r])
			continue
		}

		if meta.Title == "" {
			t.Errorf("Rule %q has empty Title in registry", r)
		}
		if meta.Why == "" {
			t.Errorf("Rule %q has empty Why in registry", r)
		}
		if len(meta.Remediation) == 0 {
			t.Errorf("Rule %q has no Remediation steps in registry", r)
		}
		if meta.EvidenceStrength == "" {
			t.Errorf("Rule %q has empty EvidenceStrength in registry", r)
		}
	}

	if len(missing) > 0 {
		t.Fatalf("%d emitted rules are missing from the metadata registry", len(missing))
	}
}
