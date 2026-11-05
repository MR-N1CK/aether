package yara

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/report"
)

// FallbackVersion identifies the pure-Go signature engine used in default
// (CGO_ENABLED=0) builds.
const FallbackVersion = "pure-go signature fallback 1.0"

// maxMatchedStringIDs mirrors the YARA-X engine contract: matched string
// identifiers only (never matched content), capped at 20 per rule.
const maxMatchedStringIDs = 20

// FallbackEngine implements Engine by interpreting the embedded YARA-subset
// rule source with pure Go primitives (bytes.Contains + RE2). It exists so
// default builds without libyara_x_capi retain 100% of the embedded
// signature coverage. Rules are compiled once at construction and are
// immutable afterwards; worker scanners are stateless per Scan call.
type FallbackEngine struct {
	cfg    *config.Config
	logger *slog.Logger

	rules       []fallbackRule
	fingerprint string
	rulesFailed int
	failedFiles []string
	demoRules   bool

	filesScanned    atomic.Int64
	skippedOversize atomic.Int64
}

// NewFallbackEngine compiles the embedded core rules (and optionally the demo
// rules) into the pure-Go fallback engine.
func NewFallbackEngine(cfg *config.Config, logger *slog.Logger) *FallbackEngine {
	e := &FallbackEngine{cfg: cfg, logger: logger}
	if cfg != nil {
		e.demoRules = cfg.Scan.DemoRules
	}
	e.loadSource("embedded:core_linux_rules.yar", EmbeddedCoreLinuxRules)
	if e.demoRules {
		e.loadSource("embedded:demo_rules.yar", DemoRuleEICAR+"\n"+DemoRuleMarker)
	}
	return e
}

// loadSource parses one rule source and merges it into the engine state.
func (e *FallbackEngine) loadSource(origin, src string) {
	sum := sha256.Sum256([]byte(src))
	fp := hex.EncodeToString(sum[:])[:16]
	if e.fingerprint == "" {
		e.fingerprint = fp
	} else {
		e.fingerprint += "," + fp
	}
	rules, err := parseYARASubset(src)
	if err != nil {
		// The embedded source ships with the binary; failing to parse it is a
		// development-time bug, not a runtime condition. Degrade loudly.
		if e.logger != nil {
			e.logger.Error("fallback engine: rule source failed to parse",
				slog.String("origin", origin), slog.Any("error", err))
		}
		e.rulesFailed++
		e.failedFiles = append(e.failedFiles, origin+": "+err.Error())
		return
	}
	e.rules = append(e.rules, rules...)
}

// LoadRules parses operator-provided rule files written in the supported
// YARA subset. Files using syntax outside the subset are counted as failures
// and skipped; the scan continues with the remaining rules.
func (e *FallbackEngine) LoadRules(rulePaths []string) error {
	for _, path := range rulePaths {
		data, err := os.ReadFile(path)
		if err != nil {
			e.rulesFailed++
			e.failedFiles = append(e.failedFiles, path+": "+err.Error())
			continue
		}
		before := len(e.rules)
		e.loadSource(path, string(data))
		if e.logger != nil && len(e.rules) > before {
			e.logger.Info("fallback engine: loaded external rules",
				slog.String("path", path), slog.Int("rules", len(e.rules)-before))
		}
	}
	return nil
}

func (e *FallbackEngine) NewScanner() Scanner {
	return &fallbackScanner{e: e}
}

func (e *FallbackEngine) Coverage() events.YARACoverageStats {
	return events.YARACoverageStats{
		CompiledIn:         false, // YARA-X itself is not linked in this build
		Version:            fmt.Sprintf("%s (%d rules)", FallbackVersion, len(e.rules)),
		RulesLoaded:        len(e.rules),
		RulesetFingerprint: e.fingerprint,
		RulesFailed:        e.rulesFailed,
		FailedFiles:        e.failedFiles,
		FilesScanned:       e.filesScanned.Load(),
		SkippedOversize:    e.skippedOversize.Load(),
		DemoRulesOnly:      false,
		NotRunReason:       e.notRunReason(),
	}
}

func (e *FallbackEngine) notRunReason() string {
	if len(e.rules) > 0 {
		return ""
	}
	return "no rules compiled"
}

func (e *FallbackEngine) Enabled() bool { return len(e.rules) > 0 }

func (e *FallbackEngine) StatusString() string {
	if !e.Enabled() {
		return "DISABLED (no signature rules compiled)"
	}
	origin := "embedded"
	if e.demoRules {
		origin = "embedded + demo"
	}
	return fmt.Sprintf("ACTIVE (%s pure-Go fallback: %d rules)", origin, len(e.rules))
}

func (e *FallbackEngine) Close() error { return nil }

type fallbackScanner struct {
	e *FallbackEngine
}

func (s *fallbackScanner) Scan(target ScanTarget) ([]RuleMatch, error) {
	return s.e.scan(target)
}

func (s *fallbackScanner) Destroy() {}

// scan evaluates every size-eligible rule against the target buffer.
func (e *FallbackEngine) scan(target ScanTarget) ([]RuleMatch, error) {
	if len(e.rules) == 0 {
		return nil, nil
	}
	data := target.Data

	// One lowercased view shared by all nocase literal patterns of
	// size-eligible rules; regexes handle case via (?i) instead.
	var low []byte
	needLow := false
	for i := range e.rules {
		r := &e.rules[i]
		if int64(len(data)) >= r.MaxSize {
			continue
		}
		if !needLow {
			for _, p := range r.Patterns {
				if !p.IsRegex && p.NoCase {
					needLow = true
					break
				}
			}
		}
	}
	if needLow {
		low = bytes.ToLower(data)
	}

	var matches []RuleMatch
	for i := range e.rules {
		r := &e.rules[i]
		if int64(len(data)) >= r.MaxSize {
			e.skippedOversize.Add(1)
			continue
		}
		if e.ruleDisabled(r) {
			continue
		}

		ctx := &condCtx{data: data, matched: make(map[string]bool, len(r.Patterns))}
		firstOffset := -1
		for _, p := range r.Patterns {
			ctx.allIDs = append(ctx.allIDs, p.ID)
			ok, off := fallbackPatternMatches(p, data, low)
			ctx.matched[p.ID] = ok
			if ok && off >= 0 && (firstOffset == -1 || off < firstOffset) {
				firstOffset = off
			}
		}
		if !r.Cond.eval(ctx) {
			continue
		}

		matches = append(matches, RuleMatch{
			RuleName:       r.Name,
			Namespace:      "fallback",
			MatchedStrings: matchedIDs(ctx, r.Patterns),
			FirstOffset:    firstOffset,
			Metadata:       r.Meta,
		})
		m := &matches[len(matches)-1]
		m.Score, m.Severity, m.IsStrong, m.Confidence = e.scoreFromRuleMeta(r.Meta)
	}

	e.filesScanned.Add(1)
	return matches, nil
}

// fallbackPatternMatches reports whether a pattern occurs in the buffer and
// returns the byte offset of its first occurrence (-1 when absent). Regex
// offsets come from FindIndex on the raw buffer; nocase literals from the
// shared lowercased view, which shares byte offsets with the original.
func fallbackPatternMatches(p fallbackPattern, data, low []byte) (bool, int) {
	if p.IsRegex {
		loc := p.Regex.FindIndex(data)
		if loc == nil {
			return false, -1
		}
		return true, loc[0]
	}
	if p.NoCase {
		idx := bytes.Index(low, p.LitLow)
		return idx >= 0, idx
	}
	idx := bytes.Index(data, p.Literal)
	return idx >= 0, idx
}

// matchedIDs returns the identifiers of patterns that matched, capped at
// maxMatchedStringIDs, mirroring the YARA-X privacy contract (identifiers
// only, never matched content).
func matchedIDs(ctx *condCtx, patterns []fallbackPattern) []string {
	var out []string
	for _, p := range patterns {
		if ctx.matched[p.ID] {
			out = append(out, p.ID)
			if len(out) >= maxMatchedStringIDs {
				break
			}
		}
	}
	return out
}

func (e *FallbackEngine) ruleDisabled(r *fallbackRule) bool {
	if e.cfg == nil {
		return false
	}
	for _, d := range e.cfg.Scan.DisabledRules {
		if d == r.Name {
			return true
		}
	}
	// The embedded rule set defines no tags; tags arrive only from external
	// rule files, which the subset parser does not attach yet.
	return false
}

// scoreFromRuleMeta applies the same threshold logic as the YARA-X scanner so
// verdicts are identical across engines.
func (e *FallbackEngine) scoreFromRuleMeta(meta map[string]interface{}) (int, report.Severity, bool, string) {
	warningScore := config.DefaultScoreYaraWarning
	strongScore := config.DefaultScoreYaraStrong
	alertScore := config.DefaultScoreYaraAlert
	if e.cfg != nil {
		if e.cfg.Scan.YaraWarningScore > 0 {
			warningScore = e.cfg.Scan.YaraWarningScore
		}
		if e.cfg.Scan.YaraStrongScore > 0 {
			strongScore = e.cfg.Scan.YaraStrongScore
		}
		if e.cfg.Scan.YaraAlertScore > 0 {
			alertScore = e.cfg.Scan.YaraAlertScore
		}
	}
	return ScoreFromMeta(meta, 50, warningScore, strongScore, alertScore)
}

// FallbackRuleNames returns the names of all compiled fallback rules (used by
// tests and diagnostics).
func (e *FallbackEngine) FallbackRuleNames() []string {
	names := make([]string, 0, len(e.rules))
	for i := range e.rules {
		names = append(names, e.rules[i].Name)
	}
	return names
}

// Fingerprint returns the ruleset fingerprint of the fallback engine.
func (e *FallbackEngine) Fingerprint() string { return e.fingerprint }
