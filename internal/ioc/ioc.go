package ioc

import (
	"bytes"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"aether/internal/config"
	"aether/internal/report"
)

// IOCType indicates the category of indicator of compromise.
type IOCType string

const (
	TypeMD5       IOCType = "MD5"
	TypeSHA1      IOCType = "SHA1"
	TypeSHA256    IOCType = "SHA256"
	TypeFilePath  IOCType = "FILE_PATH"
	TypeIPAddress IOCType = "IP_ADDRESS"
	TypeDomain    IOCType = "DOMAIN"
)

// MatchResult represents an indicator hit against a file.
type MatchResult struct {
	RuleName    string
	Reason      string
	Score       int
	Severity    report.Severity
	IsHashMatch bool
}

// SourceInfo describes an individual IOC feed source and its indicator contribution.
type SourceInfo struct {
	Source   string `json:"source"`
	Count    int    `json:"count"`
	Type     string `json:"type"`     // "Hash", "IP", "Pattern", "Benign"
	Category string `json:"category"` // "builtin", "imported", "standard_dir", "custom"
}

// Engine defines the lookup and match contract for IOC indicators.
type Engine interface {
	LoadDirectory(dir string) error
	LoadFile(path string) error
	LoadBuiltin() error
	LoadAllowlist(path string) error
	CheckHash(hashVal string) *MatchResult
	CheckPath(path string) *MatchResult
	CheckIP(ip net.IP) *IPMatchResult
	IsAllowlisted(sha256Hash string) (bool, string)
	IsKnownBenign(path string, ownerUID uint32) (bool, string)
	HashRuleCount() int
	PatternRuleCount() int
	BenignRuleCount() int
	IPRuleCount() int
	SourceSummary() []SourceInfo
}

// RealEngine implements high-performance O(1) hash matching and compiled regex path matching.
type RealEngine struct {
	mu           sync.RWMutex
	hashRules    map[string]HashRule // lowercase hash -> rule
	patternRules []PatternRule
	ipRules      []IPRule
	benignRules  []BenignRule
	sources      []SourceInfo
	allowlist    *Allowlist
	logger       *slog.Logger
}

// NewEngine initializes an IOC engine and loads built-in demo rules, discovered IOC dirs,
// and configured allowlists.
func NewEngine(cfg *config.Config, logger *slog.Logger) (*RealEngine, error) {
	if logger == nil {
		logger = slog.Default()
	}

	eng := &RealEngine{
		hashRules:    make(map[string]HashRule),
		patternRules: make([]PatternRule, 0),
		benignRules:  make([]BenignRule, 0),
		sources:      make([]SourceInfo, 0),
		allowlist:    NewAllowlist(),
		logger:       logger,
	}

	// 1. Load built-in benign demo rules and suppression rules
	if err := eng.LoadBuiltin(); err != nil {
		logger.Warn("failed to load built-in demo IOCs", slog.Any("error", err))
	}

	// 2. Discover and load IOCs from standard directories
	for _, dir := range config.DefaultIOCDirs() {
		if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
			if err := eng.LoadDirectory(dir); err != nil {
				logger.Warn("error loading standard IOC dir", slog.String("dir", dir), slog.Any("error", err))
			}
		}
	}

	// 3. Load known_benign.yaml from standard configuration paths if present
	for _, p := range []string{
		"configs/known_benign.yaml",
		filepath.Join(os.Getenv("HOME"), ".config", config.ToolName, "known_benign.yaml"),
		filepath.Join("/etc", config.ToolName, "known_benign.yaml"),
	} {
		if data, err := os.ReadFile(p); err == nil {
			if bRules, bErr := ParseBenignFile(data, p, logger); bErr == nil {
				eng.mu.Lock()
				eng.benignRules = append(eng.benignRules, bRules...)
				eng.mu.Unlock()
				logger.Debug("loaded known benign patterns", slog.String("file", p), slog.Int("count", len(bRules)))
			}
		}
	}

	// 4. Load custom IOC directory if specified
	if cfg != nil && cfg.Scan.IOCDir != "" {
		if err := eng.LoadDirectory(cfg.Scan.IOCDir); err != nil {
			return nil, fmt.Errorf("failed to load custom IOC directory %q: %w", cfg.Scan.IOCDir, err)
		}
	}

	// 4b. Load custom single IOC file if specified
	if cfg != nil && cfg.Scan.IOCFile != "" {
		if err := eng.LoadFile(cfg.Scan.IOCFile); err != nil {
			return nil, fmt.Errorf("failed to load custom IOC file %q: %w", cfg.Scan.IOCFile, err)
		}
	}

	// 5. Load allowlist if configured
	if cfg != nil && cfg.Scan.AllowlistPath != "" {
		if err := eng.LoadAllowlist(cfg.Scan.AllowlistPath); err != nil {
			return nil, fmt.Errorf("failed to load allowlist %q: %w", cfg.Scan.AllowlistPath, err)
		}
	}

	return eng, nil
}

// LoadBuiltin parses embedded benign rules and curated threat intelligence feeds.
func (e *RealEngine) LoadBuiltin() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	hashRules, err := ParseHashFile(strings.NewReader(builtinDemoHashes), "builtin_hashes.txt")
	if err != nil {
		return err
	}
	for _, hr := range hashRules {
		e.hashRules[hr.Hash] = hr
	}
	e.addSourceLocked("builtin:demo_hashes", len(hashRules), "Hash", "builtin")

	// Load embedded curated threat intelligence feeds
	entries, err := embeddedIntelFS.ReadDir("intel")
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt") {
				continue
			}
			data, readErr := embeddedIntelFS.ReadFile("intel/" + entry.Name())
			if readErr != nil {
				continue
			}
			intelRules, parseErr := ParseHashFile(bytes.NewReader(data), entry.Name())
			if parseErr == nil && len(intelRules) > 0 {
				for _, hr := range intelRules {
					e.hashRules[hr.Hash] = hr
				}
				e.addSourceLocked("builtin:intel/"+entry.Name(), len(intelRules), "Hash", "builtin")
				if e.logger != nil {
					e.logger.Debug("loaded embedded threat intelligence hashes", slog.String("file", entry.Name()), slog.Int("count", len(intelRules)))
				}
			}
		}
	}

	patRules, err := ParsePatternFile([]byte(builtinDemoPatterns), "builtin_patterns.yaml", e.logger)
	if err != nil {
		return err
	}
	e.patternRules = append(e.patternRules, patRules...)
	e.addSourceLocked("builtin:demo_patterns", len(patRules), "Pattern", "builtin")

	benignRules, err := ParseBenignFile([]byte(builtinKnownBenignPatterns), "builtin_known_benign.yaml", e.logger)
	if err != nil {
		return err
	}
	e.benignRules = append(e.benignRules, benignRules...)
	e.addSourceLocked("builtin:known_benign", len(benignRules), "Benign", "builtin")
	return nil
}

// LoadFile parses a single IOC file (.txt, .hashes, .ips, .yaml, .ioc) directly into the engine.
func (e *RealEngine) LoadFile(path string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.loadFileLocked(path)
}

func (e *RealEngine) loadFileLocked(path string) error {
	base := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(path))

	// Check for known_benign.yaml / known_benign.yml
	if (ext == ".yaml" || ext == ".yml") && strings.Contains(base, "known_benign") {
		data, err := os.ReadFile(path)
		if err != nil {
			e.logger.Warn("cannot read known_benign file", slog.String("path", path), slog.Any("error", err))
			return err
		}
		bRules, err := ParseBenignFile(data, filepath.Base(path), e.logger)
		if err != nil {
			e.logger.Warn("error parsing known_benign file", slog.String("path", path), slog.Any("error", err))
			return err
		}
		e.benignRules = append(e.benignRules, bRules...)
		e.addSourceLocked(path, len(bRules), "Benign", "config")
		e.logger.Debug("loaded known benign patterns", slog.String("file", path), slog.Int("count", len(bRules)))
		return nil
	}

	switch ext {
	case ".ips":
		f, err := os.Open(path)
		if err != nil {
			e.logger.Warn("cannot read IP IOC file", slog.String("path", path), slog.Any("error", err))
			return err
		}
		defer f.Close()

		ipRules, err := ParseIPFile(f, filepath.Base(path))
		if err != nil {
			e.logger.Warn("error parsing IP file", slog.String("path", path), slog.Any("error", err))
			return err
		}
		e.ipRules = append(e.ipRules, ipRules...)
		e.addSourceLocked(path, len(ipRules), "IP", "imported")
		e.logger.Debug("loaded IP IOCs", slog.String("file", path), slog.Int("count", len(ipRules)))
		return nil

	case ".yaml", ".yml":
		data, err := os.ReadFile(path)
		if err != nil {
			e.logger.Warn("cannot read pattern IOC file", slog.String("path", path), slog.Any("error", err))
			return err
		}

		rules, err := ParsePatternFile(data, filepath.Base(path), e.logger)
		if err != nil {
			e.logger.Warn("error parsing pattern file", slog.String("path", path), slog.Any("error", err))
			return err
		}
		e.patternRules = append(e.patternRules, rules...)
		e.addSourceLocked(path, len(rules), "Pattern", "imported")
		e.logger.Debug("loaded path IOCs", slog.String("file", path), slog.Int("count", len(rules)))
		return nil

	default: // .txt, .hashes, .ioc, or other line-delimited indicators
		f, err := os.Open(path)
		if err != nil {
			e.logger.Warn("cannot read hash/IP IOC file", slog.String("path", path), slog.Any("error", err))
			return err
		}
		defer f.Close()

		rules, _ := ParseHashFile(f, filepath.Base(path))
		for _, r := range rules {
			e.hashRules[r.Hash] = r
		}
		if len(rules) > 0 {
			e.addSourceLocked(path, len(rules), "Hash", "imported")
			e.logger.Debug("loaded hash IOCs", slog.String("file", path), slog.Int("count", len(rules)))
		}

		// Also attempt to parse IP rules from .txt / .ioc if not all lines were hashes
		_, _ = f.Seek(0, 0)
		ipRules, _ := ParseIPFile(f, filepath.Base(path))
		if len(ipRules) > 0 {
			e.ipRules = append(e.ipRules, ipRules...)
			e.addSourceLocked(path, len(ipRules), "IP", "imported")
			e.logger.Debug("loaded IP IOCs", slog.String("file", path), slog.Int("count", len(ipRules)))
		}
		return nil
	}
}

// LoadDirectory walks a directory and compiles all .txt/.hashes/.yaml IOC files.
func (e *RealEngine) LoadDirectory(dir string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		_ = e.loadFileLocked(path)
		return nil
	})
}

// LoadAllowlist loads a known-good SHA256 allowlist file.
func (e *RealEngine) LoadAllowlist(path string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.allowlist.LoadFile(path)
}

// CheckHash evaluates a single hash (MD5, SHA1, or SHA256) in O(1) time.
func (e *RealEngine) CheckHash(hashVal string) *MatchResult {
	if hashVal == "" {
		return nil
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	key := strings.ToLower(strings.TrimSpace(hashVal))
	if rule, found := e.hashRules[key]; found {
		return &MatchResult{
			RuleName:    rule.ThreatName,
			Reason:      fmt.Sprintf("Matched %s hash indicator: %s (%s)", rule.Type, rule.Hash, rule.Description),
			Score:       rule.Score,
			Severity:    rule.Severity,
			IsHashMatch: true,
		}
	}
	return nil
}

// CheckPath evaluates path and filename against compiled regex rules.
func (e *RealEngine) CheckPath(path string) *MatchResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rule := range e.patternRules {
		if rule.Regex.MatchString(path) {
			return &MatchResult{
				RuleName:    rule.RuleName,
				Reason:      fmt.Sprintf("Matched path pattern %q: %s", rule.Pattern, rule.Reason),
				Score:       rule.Score,
				Severity:    rule.Severity,
				IsHashMatch: false,
			}
		}
	}
	return nil
}

// IsAllowlisted checks if the SHA256 hash is in the known-good allowlist.
func (e *RealEngine) IsAllowlisted(sha256Hash string) (bool, string) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.allowlist.Contains(sha256Hash)
}

// IsKnownBenign checks if the path matches known-benign patterns (e.g. tool caches).
// If the matching rule specifies OwnerMatchesNameUID, the UID is extracted from a
// regex capture group and verified against ownerUID.
func (e *RealEngine) IsKnownBenign(path string, ownerUID uint32) (bool, string) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rule := range e.benignRules {
		matches := rule.Regex.FindStringSubmatch(path)
		if len(matches) == 0 {
			matches = rule.Regex.FindStringSubmatch(filepath.Base(path))
			if len(matches) == 0 {
				continue
			}
		}

		if rule.OwnerMatchesNameUID {
			if len(matches) < 2 {
				// Regex requires owner UID match but did not have a capture group
				continue
			}
			parsedUID, err := strconv.ParseUint(matches[1], 10, 32)
			if err != nil || uint32(parsedUID) != ownerUID {
				// UID in filename does not match the actual file owner UID!
				continue
			}
		}

		return true, rule.Reason
	}
	return false, ""
}

// CheckIP evaluates an IP against registered IP/CIDR IOC indicators.
func (e *RealEngine) CheckIP(ip net.IP) *IPMatchResult {
	if ip == nil {
		return nil
	}

	isSpecial := IsSpecialIP(ip)

	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rule := range e.ipRules {
		// If connection IP is special (loopback, RFC1918, etc.), only match if the rule explicitly targeted it
		if isSpecial && !rule.IsExplicitSpecial {
			continue
		}

		matched := false
		if rule.IP != nil && rule.IP.Equal(ip) {
			matched = true
		} else if rule.IPNet != nil && rule.IPNet.Contains(ip) {
			matched = true
		}

		if matched {
			score := 75 // STRONG
			sev := report.SeverityWarning
			isHigh := false
			if rule.Confidence == "high" {
				score = 90
				sev = report.SeverityAlert
				isHigh = true
			}
			ruleName := "Network_IOC_IP_Connection"
			if rule.Comment != "" && !strings.Contains(rule.Comment, " ") && len(rule.Comment) < 32 {
				ruleName = rule.Comment
			}
			return &IPMatchResult{
				RuleName:   ruleName,
				Reason:     fmt.Sprintf("Connection to known malicious IP indicator: %s (%s)", ip.String(), rule.Comment),
				Score:      score,
				Severity:   sev,
				IsHighConf: isHigh,
				Comment:    rule.Comment,
			}
		}
	}
	return nil
}

// HashRuleCount returns total registered hash signatures.
func (e *RealEngine) HashRuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.hashRules)
}

// PatternRuleCount returns total registered regex path rules.
func (e *RealEngine) PatternRuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.patternRules)
}

// BenignRuleCount returns total registered known-benign suppression rules.
func (e *RealEngine) BenignRuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.benignRules)
}

// IPRuleCount returns total registered IP/CIDR rules.
func (e *RealEngine) IPRuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.ipRules)
}

func (e *RealEngine) addSourceLocked(src string, count int, typ, cat string) {
	e.sources = append(e.sources, SourceInfo{
		Source:   src,
		Count:    count,
		Type:     typ,
		Category: cat,
	})
}

// SourceSummary returns metadata for all loaded IOC files and embedded feeds.
func (e *RealEngine) SourceSummary() []SourceInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()
	res := make([]SourceInfo, len(e.sources))
	copy(res, e.sources)
	return res
}

// StubEngine fallback for minimal testing.
type StubEngine struct{}

func NewStubEngine() Engine                                                     { return &StubEngine{} }
func (s *StubEngine) LoadDirectory(dir string) error                            { return nil }
func (s *StubEngine) LoadFile(path string) error                                { return nil }
func (s *StubEngine) LoadBuiltin() error                                        { return nil }
func (s *StubEngine) LoadAllowlist(path string) error                           { return nil }
func (s *StubEngine) CheckHash(hashVal string) *MatchResult                     { return nil }
func (s *StubEngine) CheckPath(path string) *MatchResult                        { return nil }
func (s *StubEngine) CheckIP(ip net.IP) *IPMatchResult                          { return nil }
func (s *StubEngine) IsAllowlisted(sha256Hash string) (bool, string)            { return false, "" }
func (s *StubEngine) IsKnownBenign(path string, ownerUID uint32) (bool, string) { return false, "" }
func (s *StubEngine) HashRuleCount() int                                        { return 0 }
func (s *StubEngine) PatternRuleCount() int                                     { return 0 }
func (s *StubEngine) BenignRuleCount() int                                      { return 0 }
func (s *StubEngine) IPRuleCount() int                                          { return 0 }
func (s *StubEngine) SourceSummary() []SourceInfo                               { return nil }
