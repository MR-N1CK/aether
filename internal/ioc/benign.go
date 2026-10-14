package ioc

import (
	"fmt"
	"log/slog"
	"regexp"

	"gopkg.in/yaml.v3"
)

// BenignEntry represents a raw YAML entry for known benign path suppression.
type BenignEntry struct {
	PathRegex           string `yaml:"path_regex"`
	Reason              string `yaml:"reason"`
	OwnerMatchesNameUID bool   `yaml:"owner_matches_name_uid"`
}

// BenignRule represents a compiled regex path suppression rule.
type BenignRule struct {
	Pattern             string
	Regex               *regexp.Regexp
	Reason              string
	OwnerMatchesNameUID bool
}

// ParseBenignFile parses a YAML file containing known benign path suppression patterns.
func ParseBenignFile(data []byte, filename string, logger *slog.Logger) ([]BenignRule, error) {
	if logger == nil {
		logger = slog.Default()
	}

	var entries []BenignEntry
	if err := yaml.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse known_benign yaml in %s: %w", filename, err)
	}

	var rules []BenignRule
	for i, entry := range entries {
		if entry.PathRegex == "" {
			continue
		}

		re, err := regexp.Compile(entry.PathRegex)
		if err != nil {
			logger.Warn("skipping invalid regex in known_benign file",
				slog.String("file", filename),
				slog.Int("index", i),
				slog.String("regex", entry.PathRegex),
				slog.Any("error", err),
			)
			continue
		}

		rules = append(rules, BenignRule{
			Pattern:             entry.PathRegex,
			Regex:               re,
			Reason:              entry.Reason,
			OwnerMatchesNameUID: entry.OwnerMatchesNameUID,
		})
	}

	return rules, nil
}
