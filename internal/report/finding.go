package report

import "time"

// Severity represents the alert level of a threat hunting finding.
type Severity string

const (
	SeverityInfo    Severity = "INFO"
	SeverityNotice  Severity = "NOTICE"
	SeverityWarning Severity = "WARNING"
	SeverityAlert   Severity = "ALERT"
)

func (s Severity) String() string {
	return string(s)
}

// RuleSummary provides an aggregated count and severity for a specific rule.
type RuleSummary struct {
	RuleName     string   `json:"rule_name"`
	Severity     Severity `json:"severity"`
	Count        int      `json:"count"`
	Acknowledged bool     `json:"acknowledged,omitempty"`
}

// Finding represents a single security observation or compromise indicator
// discovered during a hunt scan.
type Finding struct {
	Timestamp time.Time              `json:"timestamp"`
	Module    string                 `json:"module"`
	Severity  Severity               `json:"severity"`
	Path      string                 `json:"path,omitempty"`
	Reason    string                 `json:"reason"`
	RuleName  string                 `json:"rule_name,omitempty"`
	Count     int                    `json:"count,omitempty"`
	Paths     []string               `json:"paths,omitempty"`
	Hashes    map[string]string      `json:"hashes,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// NewFinding creates a populated Finding with the current local timestamp (with timezone offset).
func NewFinding(module string, severity Severity, path, reason, ruleName string) Finding {
	return Finding{
		Timestamp: time.Now(),
		Module:    module,
		Severity:  severity,
		Path:      path,
		Reason:    reason,
		RuleName:  ruleName,
		Count:     1,
		Paths:     []string{path},
		Hashes:    make(map[string]string),
		Metadata:  make(map[string]interface{}),
	}
}

