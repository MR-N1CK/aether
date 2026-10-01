package ioc

import (
	"fmt"
	"log/slog"
	"regexp"

	"gopkg.in/yaml.v3"

	"aether/internal/report"
)

// PatternEntry represents a raw YAML entry for filename/path IOC matching.
type PatternEntry struct {
	Pattern string `yaml:"pattern"`
	Score   int    `yaml:"score"`
	Reason  string `yaml:"reason"`
	OSHint  string `yaml:"os_hint"`
}

// PatternRule represents a compiled regex path/filename rule.
type PatternRule struct {
	Pattern   string
	Regex     *regexp.Regexp
	Score     int
	Reason    string
	OSHint    string
	Severity  report.Severity
	RuleName  string
}

// ScoreToSeverity translates a numerical score to a Finding Severity.
func ScoreToSeverity(score int) report.Severity {
	if score >= 80 {
		return report.SeverityAlert
	}
	if score >= 50 {
		return report.SeverityWarning
	}
	if score >= 20 {
		return report.SeverityNotice
	}
	return report.SeverityInfo
}

// ParsePatternFile parses a YAML file of regex path IOC entries.
// Invalid patterns are logged as warnings and skipped without crashing.
func ParsePatternFile(data []byte, filename string, logger *slog.Logger) ([]PatternRule, error) {
	if logger == nil {
		logger = slog.Default()
	}

	var entries []PatternEntry
	if err := yaml.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse yaml patterns in %s: %w", filename, err)
	}

	var rules []PatternRule
	for i, entry := range entries {
		if entry.Pattern == "" {
			continue
		}

		re, err := regexp.Compile(entry.Pattern)
		if err != nil {
			logger.Warn("skipping invalid regex pattern in IOC file",
				slog.String("file", filename),
				slog.Int("index", i),
				slog.String("pattern", entry.Pattern),
				slog.Any("error", err),
			)
			continue
		}

		score := entry.Score
		if score <= 0 {
			score = 50 // default score
		}

		ruleName := fmt.Sprintf("Path_Rule_%d", i+1)
		rules = append(rules, PatternRule{
			Pattern:  entry.Pattern,
			Regex:    re,
			Score:    score,
			Reason:   entry.Reason,
			OSHint:   entry.OSHint,
			Severity: ScoreToSeverity(score),
			RuleName: ruleName,
		})
	}

	return rules, nil
}
