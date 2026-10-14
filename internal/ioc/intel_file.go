package ioc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"aether/internal/config"
	"aether/internal/report"
	"aether/internal/safeopen"
)

var (
	// reSTIXHash extracts hash values from STIX 2.x indicator comparison patterns:
	// e.g. [file:hashes.'SHA-256' = '34301d0a514757c91d4e861219b16be9cbff01e4a6e35cb31682855f9630c5e7']
	reSTIXHash = regexp.MustCompile(`(?i)file:hashes\.(?:'|")?(?:SHA-?256|MD5|SHA-?1)(?:'|")?\s*=\s*(?:'|")([a-fA-F0-9]{32,64})(?:'|")`)
	// reHexOnly validates purely hexadecimal strings
	reHexOnly = regexp.MustCompile(`^[a-fA-F0-9]+$`)
)

// ImportSummary records the result of an intelligence package import operation.
type ImportSummary struct {
	SourceFile        string `json:"source_file"`
	DestFile          string `json:"dest_file"`
	TotalParsed       int    `json:"total_parsed"`
	NewImported       int    `json:"new_imported"`
	DuplicatesSkipped int    `json:"duplicates_skipped"`
}

// LoadIntelPackage parses a threat intelligence feed from an io.Reader.
// It automatically detects and supports:
// 1. Line-delimited hash lists (<hash> # <desc>, <hash> <desc>, <hash>, CSV <hash>,<desc>)
// 2. STIX 2.x JSON bundles and STIX-lite indicator objects
// 3. Generic JSON indicator lists
func LoadIntelPackage(r io.Reader, sourceName string) ([]HashRule, error) {
	// Limit read buffer to 50MB to adhere to safety budget
	lr := io.LimitReader(r, int64(config.DefaultMaxFileSize))
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("failed to read threat intelligence package: %w", err)
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, nil
	}

	// 1. Try parsing as JSON (STIX bundle, indicator list, or generic IOC JSON)
	if bytes.HasPrefix(trimmed, []byte("{")) || bytes.HasPrefix(trimmed, []byte("[")) {
		rules, jsonErr := parseJSONIntel(trimmed, sourceName)
		if jsonErr == nil && len(rules) > 0 {
			return rules, nil
		}
	}

	// 2. Fall back to flexible line-delimited parsing
	return parseLineIntel(trimmed, sourceName)
}

func parseJSONIntel(data []byte, sourceName string) ([]HashRule, error) {
	// Check if this is a STIX bundle or generic object
	var generic map[string]interface{}
	if err := json.Unmarshal(data, &generic); err == nil {
		var rules []HashRule
		seen := make(map[string]struct{})

		// Case A: STIX bundle with "objects" array
		if objs, ok := generic["objects"].([]interface{}); ok {
			for _, objRaw := range objs {
				obj, isMap := objRaw.(map[string]interface{})
				if !isMap {
					continue
				}
				typ, _ := obj["type"].(string)
				if typ != "indicator" {
					continue
				}
				name, _ := obj["name"].(string)
				desc, _ := obj["description"].(string)
				pattern, _ := obj["pattern"].(string)

				if name == "" {
					name = desc
				}
				if name == "" {
					name = sourceName
				}

				// Extract hashes from pattern
				matches := reSTIXHash.FindAllStringSubmatch(pattern, -1)
				for _, m := range matches {
					if len(m) > 1 {
						h := strings.ToLower(m[1])
						if _, exists := seen[h]; !exists {
							seen[h] = struct{}{}
							if rule := createHashRule(h, name, desc); rule != nil {
								rules = append(rules, *rule)
							}
						}
					}
				}
			}
		}

		// Case B: Single STIX indicator object
		if typ, ok := generic["type"].(string); ok && typ == "indicator" {
			name, _ := generic["name"].(string)
			desc, _ := generic["description"].(string)
			pattern, _ := generic["pattern"].(string)
			matches := reSTIXHash.FindAllStringSubmatch(pattern, -1)
			for _, m := range matches {
				if len(m) > 1 {
					h := strings.ToLower(m[1])
					if _, exists := seen[h]; !exists {
						seen[h] = struct{}{}
						if rule := createHashRule(h, name, desc); rule != nil {
							rules = append(rules, *rule)
						}
					}
				}
			}
		}

		// Case C: Generic "indicators" or "hashes" array
		for _, key := range []string{"indicators", "hashes", "iocs"} {
			if items, ok := generic[key].([]interface{}); ok {
				for _, item := range items {
					if itemMap, ok := item.(map[string]interface{}); ok {
						h, hDesc := extractHashAndDesc(itemMap)
						if _, exists := seen[h]; !exists && isValidHashLen(len(h)) {
							seen[h] = struct{}{}
							if rule := createHashRule(h, hDesc, hDesc); rule != nil {
								rules = append(rules, *rule)
							}
						}
					}
				}
			}
		}

		if len(rules) > 0 {
			return rules, nil
		}
	}

	// Try JSON array of indicators: [ {"hash": "..."}, ... ]
	var arr []map[string]interface{}
	if err := json.Unmarshal(data, &arr); err == nil {
		var rules []HashRule
		seen := make(map[string]struct{})
		for _, item := range arr {
			h, hDesc := extractHashAndDesc(item)
			if _, exists := seen[h]; !exists && isValidHashLen(len(h)) {
				seen[h] = struct{}{}
				if rule := createHashRule(h, hDesc, hDesc); rule != nil {
					rules = append(rules, *rule)
				}
			}
		}
		if len(rules) > 0 {
			return rules, nil
		}
	}

	return nil, fmt.Errorf("no valid indicators found in JSON structure")
}

func parseLineIntel(data []byte, sourceName string) ([]HashRule, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var rules []HashRule
	seen := make(map[string]struct{})

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		var rawHash, desc string

		// Format 1: <hash> # <description>
		if idx := strings.Index(line, "#"); idx != -1 {
			rawHash = strings.TrimSpace(line[:idx])
			desc = strings.TrimSpace(line[idx+1:])
		} else if strings.Contains(line, ",") {
			// Format 2: CSV <hash>,<description>
			parts := strings.SplitN(line, ",", 2)
			rawHash = strings.TrimSpace(parts[0])
			if len(parts) > 1 {
				desc = strings.TrimSpace(parts[1])
			}
		} else {
			// Format 3: Space/tab separated <hash> <description> or just <hash>
			fields := strings.Fields(line)
			if len(fields) > 0 {
				rawHash = fields[0]
				if len(fields) > 1 {
					desc = strings.Join(fields[1:], " ")
				}
			}
		}

		// Clean up surrounding quotes
		rawHash = strings.Trim(rawHash, `"'`)
		h := strings.ToLower(rawHash)

		if !isValidHashLen(len(h)) || !reHexOnly.MatchString(h) {
			continue
		}

		if _, exists := seen[h]; exists {
			continue
		}
		seen[h] = struct{}{}

		if desc == "" {
			desc = fmt.Sprintf("Imported indicator from %s", sourceName)
		}

		if rule := createHashRule(h, desc, desc); rule != nil {
			rules = append(rules, *rule)
		}
	}

	return rules, scanner.Err()
}

func isValidHashLen(l int) bool {
	return l == 32 || l == 40 || l == 64
}

func extractHashAndDesc(m map[string]interface{}) (string, string) {
	var hStr, hDesc string
	for _, k := range []string{"hash", "sha256", "sha1", "md5", "value", "indicator"} {
		if val, ok := m[k].(string); ok && val != "" {
			hStr = val
			break
		}
	}
	for _, k := range []string{"description", "name", "desc", "title", "threat"} {
		if val, ok := m[k].(string); ok && val != "" {
			hDesc = val
			break
		}
	}
	return strings.ToLower(strings.TrimSpace(hStr)), hDesc
}

func createHashRule(hash string, name, desc string) *HashRule {
	var iocType IOCType
	switch len(hash) {
	case 32:
		iocType = TypeMD5
	case 40:
		iocType = TypeSHA1
	case 64:
		iocType = TypeSHA256
	default:
		return nil
	}

	threatName := name
	if threatName == "" || strings.Contains(threatName, " ") || len(threatName) > 40 {
		threatName = "IOC_Hash_" + string(iocType)
	}

	if desc == "" {
		desc = "Threat intelligence hash indicator match"
	}

	return &HashRule{
		Hash:        hash,
		Type:        iocType,
		ThreatName:  threatName,
		Description: desc,
		Score:       100, // Hash IOC matches are confirmed ALERTs
		Severity:    report.SeverityAlert,
	}
}

// DefaultImportDir returns the canonical destination directory for imported threat intelligence:
// 1. /etc/aether/iocs (if invoked as root / UID 0)
// 2. ~/.config/aether/iocs (for regular user accounts)
func DefaultImportDir() string {
	if os.Geteuid() == 0 {
		return filepath.Join("/etc", config.ToolName, "iocs")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".config", config.ToolName, "iocs")
	}
	return filepath.Join("/etc", config.ToolName, "iocs")
}

// ImportIntelFile validates a source intelligence file, extracts unique indicators,
// deduplicates against existing engine and destination entries, and safely persists
// the new threat signatures into destDir.
func ImportIntelFile(srcPath string, destDir string, overwrite bool) (*ImportSummary, error) {
	// 1. Forensic safety verification: open read-only regular file without following symlinks
	cleanSrc := filepath.Clean(srcPath)
	f, err := safeopen.OpenRegularReadOnly(cleanSrc, int64(config.DefaultMaxFileSize))
	if err != nil {
		return nil, fmt.Errorf("cannot safely read source threat intelligence file %q: %w", cleanSrc, err)
	}
	defer f.Close()

	// 2. Parse intelligence feed
	rules, err := LoadIntelPackage(f, filepath.Base(cleanSrc))
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no valid hash indicators discovered in %q", filepath.Base(cleanSrc))
	}

	// 3. Resolve destination directory
	if destDir == "" {
		destDir = DefaultImportDir()
	}
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return nil, fmt.Errorf("cannot create IOC destination directory %q: %w", destDir, err)
	}

	destFile := filepath.Join(destDir, "imported_hashes.txt")

	// 4. Read existing destination file for deduplication
	existingHashes := make(map[string]struct{})
	if !overwrite {
		if destF, err := os.Open(destFile); err == nil {
			if existingRules, err := ParseHashFile(destF, filepath.Base(destFile)); err == nil {
				for _, r := range existingRules {
					existingHashes[r.Hash] = struct{}{}
				}
			}
			destF.Close()
		}
	}

	// 5. Filter out duplicates
	var newRules []HashRule
	var dupesCount int
	for _, r := range rules {
		if _, exists := existingHashes[r.Hash]; exists {
			dupesCount++
			continue
		}
		existingHashes[r.Hash] = struct{}{}
		newRules = append(newRules, r)
	}

	// 6. Write or append to target file
	openFlags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if overwrite {
		openFlags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}

	outF, err := os.OpenFile(destFile, openFlags, 0644)
	if err != nil {
		return nil, fmt.Errorf("cannot open destination IOC file %q: %w", destFile, err)
	}
	defer outF.Close()

	destStat, _ := outF.Stat()
	if overwrite || (destStat != nil && destStat.Size() == 0) {
		_, _ = outF.WriteString("# Aether Imported Threat Intelligence Indicators\n")
		_, _ = outF.WriteString("# Format: <hash> # <description>\n\n")
	}

	for _, r := range newRules {
		line := fmt.Sprintf("%s # %s\n", r.Hash, r.Description)
		if _, err := outF.WriteString(line); err != nil {
			return nil, fmt.Errorf("failed writing imported indicators: %w", err)
		}
	}

	return &ImportSummary{
		SourceFile:        cleanSrc,
		DestFile:          destFile,
		TotalParsed:       len(rules),
		NewImported:       len(newRules),
		DuplicatesSkipped: dupesCount,
	}, nil
}
