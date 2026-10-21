package report

import (
	"sync"
)

// RuleMeta is the enrichment knowledge base for a detector rule: human-readable
// title, plain-English rationale, MITRE ATT&CK mapping, and remediation steps.
type RuleMeta struct {
	Title            string
	Why              string
	MITRE            []MITREMapping
	Remediation      []string
	Confidence       Confidence
	EvidenceStrength EvidenceStrength
}

var (
	ruleRegistryMu sync.RWMutex
	ruleRegistry   = make(map[string]RuleMeta)
)

// RegisterRuleMeta registers enrichment metadata for a rule name. It panics on
// duplicate registration or incomplete metadata so that a rule can never ship
// without enrichment (fail-fast at process start).
func RegisterRuleMeta(name string, meta RuleMeta) {
	if name == "" {
		panic("report: RegisterRuleMeta called with empty rule name")
	}
	if meta.Title == "" {
		panic("rule " + name + ": Title must not be empty")
	}
	if meta.Why == "" {
		panic("rule " + name + ": Why explanation is required")
	}
	if len(meta.Remediation) == 0 {
		panic("rule " + name + ": at least one Remediation step is required")
	}
	if meta.Confidence == "" {
		meta.Confidence = ConfidenceMedium
	}
	ruleRegistryMu.Lock()
	defer ruleRegistryMu.Unlock()
	if _, dup := ruleRegistry[name]; dup {
		panic("rule " + name + ": duplicate metadata registration")
	}
	ruleRegistry[name] = meta
}

// LookupRuleMeta returns registered enrichment metadata for a rule name.
func LookupRuleMeta(name string) (RuleMeta, bool) {
	ruleRegistryMu.RLock()
	defer ruleRegistryMu.RUnlock()
	m, ok := ruleRegistry[name]
	return m, ok
}

// RegisteredRuleCount returns the number of rules with registered metadata.
// Used by tests to enforce registration coverage.
func RegisteredRuleCount() int {
	ruleRegistryMu.RLock()
	defer ruleRegistryMu.RUnlock()
	return len(ruleRegistry)
}

// RegisteredRuleNames returns all registered rule names (sorted by map range
// order is not guaranteed; callers should sort if deterministic output matters).
func RegisteredRuleNames() []string {
	ruleRegistryMu.RLock()
	defer ruleRegistryMu.RUnlock()
	names := make([]string, 0, len(ruleRegistry))
	for name := range ruleRegistry {
		names = append(names, name)
	}
	return names
}

// mustRegister is the package-internal registration helper used by init().
func mustRegister(name, title, why string, mitre []MITREMapping, remediation []string, conf Confidence) {
	RegisterRuleMeta(name, RuleMeta{
		Title:       title,
		Why:         why,
		MITRE:       mitre,
		Remediation: remediation,
		Confidence:  confidenceValue(conf),
	})
}

func confidenceValue(c Confidence) Confidence {
	if c == "" {
		return ConfidenceMedium
	}
	return c
}
