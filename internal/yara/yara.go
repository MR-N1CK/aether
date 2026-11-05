package yara

import (
	"context"
	"strconv"
	"strings"

	"aether/internal/events"
	"aether/internal/report"
)

// ValidationResult contains the compile validation summary of a rules directory.
type ValidationResult struct {
	TotalFilesFound          int
	FilesCompiled            int
	FilesFailed              int
	TotalRulesLoaded         int
	RulesWithExplicitScore   int
	RulesWithExplicitSev     int
	RulesWithAlertOrCritical int
	RulesWithDefaultMetadata int
	Failures                 []RuleFailure
}

// RuleFailure contains the path and error message for a failed rule file.
type RuleFailure struct {
	Path  string
	Error string
}

// RuleMatch represents a signature hit from a YARA scan.
type RuleMatch struct {
	RuleName       string                 `json:"rule_name"`
	Namespace      string                 `json:"namespace,omitempty"`
	Tags           []string               `json:"tags,omitempty"`
	MatchedStrings []string               `json:"matched_strings,omitempty"` // String identifiers only (never matched content), max 20
	FirstOffset    int                    `json:"first_offset"`              // Earliest pattern match byte offset in the scanned buffer; -1 = unavailable
	Score          int                    `json:"score"`
	Severity       report.Severity        `json:"severity"`
	IsStrong       bool                   `json:"is_strong"`
	Confidence     string                 `json:"confidence,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// ScanTarget contains the file buffer and associated metadata passed to YARA for evaluation.
type ScanTarget struct {
	Path      string
	Filename  string
	Extension string
	FileType  string
	Owner     string
	Data      []byte
}

// Scanner defines the worker-isolated scanner interface for goroutine safety.
type Scanner interface {
	Scan(target ScanTarget) ([]RuleMatch, error)
	Destroy()
}

// Engine defines the YARA rule compiler and scanning contract.
type Engine interface {
	// LoadRules compiles and caches YARA rule files from disk or embedded sources.
	LoadRules(rulePaths []string) error
	// NewScanner creates a thread-isolated worker scanner instance.
	NewScanner() Scanner
	// Coverage returns YARA compilation and scan statistics.
	Coverage() events.YARACoverageStats
	// Enabled returns true if YARA is compiled in, rules were successfully loaded, and no fatal trust errors occurred.
	Enabled() bool
	// StatusString returns a human-readable description of engine status (e.g., active rules count or disabled reason).
	StatusString() string
	// Close releases any allocated resources.
	Close() error
}

// ScoreFromMeta parses score, severity, and confidence from rule metadata according to Aether rules.
// Severity mapping:
//   - score < warningThreshold (<40 by default): NOTICE
//   - warningThreshold <= score < strongThreshold (40-74 by default): WARNING (weak)
//   - strongThreshold <= score < alertThreshold (75-89 by default): WARNING (strong)
//   - score >= alertThreshold (>=90 by default): ALERT
//
// All scores are clamped to [0, 100].
func ScoreFromMeta(metadata map[string]interface{}, defaultScore, warningThreshold, strongThreshold, alertThreshold int) (int, report.Severity, bool, string) {
	if defaultScore <= 0 {
		defaultScore = 50
	}
	if warningThreshold <= 0 {
		warningThreshold = 40
	}
	if strongThreshold <= 0 {
		strongThreshold = 75
	}
	if alertThreshold <= 0 {
		alertThreshold = 90
	}

	score := -1
	scoreFound := false
	var rawSeverity string
	var confidence string

	for k, v := range metadata {
		kLower := strings.ToLower(k)
		switch kLower {
		case "score":
			switch val := v.(type) {
			case int:
				score = val
				scoreFound = true
			case int64:
				score = int(val)
				scoreFound = true
			case float64:
				score = int(val)
				scoreFound = true
			case string:
				if n, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
					score = n
					scoreFound = true
				}
			}
		case "severity":
			if s, ok := v.(string); ok {
				rawSeverity = strings.ToUpper(strings.TrimSpace(s))
			}
		case "confidence":
			if s, ok := v.(string); ok {
				confidence = strings.ToLower(strings.TrimSpace(s))
			}
		}
	}

	// If score was not explicitly found, derive from severity string if present, or defaultScore
	if !scoreFound {
		switch rawSeverity {
		case "CRITICAL", "ALERT":
			score = 90
		case "HIGH", "WARNING":
			score = 70
		case "MEDIUM":
			score = 50
		case "LOW", "NOTICE":
			score = 25
		case "INFO", "INFORMATIONAL":
			score = 10
		default:
			score = defaultScore
		}
	}

	// Clamp score to [0, 100]
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	// Determine severity from score
	var sev report.Severity
	if score >= alertThreshold {
		sev = report.SeverityAlert
	} else if score >= warningThreshold {
		sev = report.SeverityWarning
	} else {
		sev = report.SeverityNotice
	}

	isStrong := score >= strongThreshold
	return score, sev, isStrong, confidence
}

// NoopEngine is a zero-CGO, pure Go placeholder implementation of the Engine interface.
// This allows Aether to compile statically with CGO_ENABLED=0 out of the box.
type NoopEngine struct{}

// NewNoopEngine returns a ready-to-use no-op YARA engine.
func NewNoopEngine() Engine {
	return &NoopEngine{}
}

func (e *NoopEngine) LoadRules(rulePaths []string) error {
	return nil
}

func (e *NoopEngine) NewScanner() Scanner {
	return &noopScanner{}
}

func (e *NoopEngine) Coverage() events.YARACoverageStats {
	return events.YARACoverageStats{
		CompiledIn:   false,
		NotRunReason: "YARA not compiled in",
	}
}

func (e *NoopEngine) Enabled() bool {
	return false
}

func (e *NoopEngine) StatusString() string {
	return "DISABLED (native heuristics only)"
}

func (e *NoopEngine) Close() error {
	return nil
}

type noopScanner struct{}

func (s *noopScanner) Scan(target ScanTarget) ([]RuleMatch, error) {
	return nil, nil
}

func (s *noopScanner) Destroy() {}

// ScanContextKey for context propagation if needed
type scanContextKey struct{}

func WithScanContext(ctx context.Context, target ScanTarget) context.Context {
	return context.WithValue(ctx, scanContextKey{}, target)
}
