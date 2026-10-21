package tui

import (
	"strings"
	"unicode"
)

// fuzzyScore reports whether query is a fuzzy (case-insensitive) subsequence
// of text and, if so, a heuristic match score. Higher scores are better.
//
// Scoring favors what a human usually means when typing an abbreviation:
//   - every matched rune contributes
//   - consecutive matches (no gaps) are strongly preferred
//   - matches at a token boundary (start of text or after a separator) are
//     strongly preferred
//
// A plain substring hit naturally maximizes both bonuses, so it outranks
// scattered subsequence hits of the same query. Non-matches return (0, false).
func fuzzyScore(text, query string) (int, bool) {
	if query == "" {
		return 0, true
	}

	lt := []rune(strings.ToLower(text))
	lq := []rune(strings.ToLower(query))

	score := 0
	consecutive := false
	qi := 0
	for ti := 0; ti < len(lt) && qi < len(lq); ti++ {
		if lt[ti] != lq[qi] {
			consecutive = false
			continue
		}
		score += 10
		if consecutive {
			score += 8
		}
		if ti == 0 || !alnumRune(lt[ti-1]) {
			score += 6
		}
		consecutive = true
		qi++
	}
	if qi < len(lq) {
		return 0, false
	}
	return score, true
}

// fuzzyHaystack concatenates the searchable fields of a finding into a single
// lowercased string for fuzzy matching. Fields are joined with a unit
// separator so that acronym-style queries crossing fields earn token-boundary
// credit (the separator is a non-alphanumeric rune) instead of looking like a
// mid-word typo.
func fuzzyHaystack(path, reason, module, severity, rule string) string {
	return strings.ToLower(strings.Join([]string{path, reason, module, severity, rule}, "\x1f"))
}

func alnumRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

// QueryFilter defines parsed structured search filters combined with free-text query.
// Supports:
//   sev:<val>  / severity:<val>  (alert, warning, notice, info)
//   mod:<val>  / module:<val>    (persistence, process, network, users, kernel, filesystem, etc.)
//   path:<val>                   (substring match on target path)
//   rule:<val>                   (substring match on detection rule name)
//   <terms>                      (fuzzy subsequence matching across finding haystack)
type QueryFilter struct {
	Severity string
	Module   string
	Path     string
	Rule     string
	FreeText string
}

// IsEmpty reports whether the filter query contains no constraints.
func (qf QueryFilter) IsEmpty() bool {
	return qf.Severity == "" && qf.Module == "" && qf.Path == "" && qf.Rule == "" && qf.FreeText == ""
}

// ParseQueryFilter extracts key:value directives and free-text search from a query string.
func ParseQueryFilter(q string) QueryFilter {
	tokens := strings.Fields(strings.TrimSpace(q))
	var qf QueryFilter
	var freeTokens []string

	for _, tok := range tokens {
		lower := strings.ToLower(tok)
		switch {
		case strings.HasPrefix(lower, "sev:"):
			qf.Severity = strings.ToLower(tok[4:])
		case strings.HasPrefix(lower, "severity:"):
			qf.Severity = strings.ToLower(tok[9:])
		case strings.HasPrefix(lower, "mod:"):
			qf.Module = strings.ToLower(tok[4:])
		case strings.HasPrefix(lower, "module:"):
			qf.Module = strings.ToLower(tok[7:])
		case strings.HasPrefix(lower, "path:"):
			qf.Path = strings.ToLower(tok[5:])
		case strings.HasPrefix(lower, "rule:"):
			qf.Rule = strings.ToLower(tok[5:])
		default:
			freeTokens = append(freeTokens, tok)
		}
	}

	qf.FreeText = strings.Join(freeTokens, " ")
	return qf
}

// Matches evaluates whether finding metadata satisfies all structured filters and free text.
func (qf QueryFilter) Matches(path, reason, module, severity, rule string) bool {
	if qf.Severity != "" {
		sevStr := strings.ToLower(severity)
		switch qf.Severity {
		case "alert", "crit", "critical":
			if sevStr != "alert" && sevStr != "critical" {
				return false
			}
		case "warn", "warning", "high", "med", "medium":
			if sevStr != "warning" && sevStr != "high" && sevStr != "medium" {
				return false
			}
		case "notice", "low":
			if sevStr != "notice" && sevStr != "low" {
				return false
			}
		case "info":
			if sevStr != "info" {
				return false
			}
		default:
			if !strings.Contains(sevStr, qf.Severity) {
				return false
			}
		}
	}

	if qf.Module != "" {
		if !strings.Contains(strings.ToLower(module), qf.Module) {
			return false
		}
	}

	if qf.Path != "" {
		if !strings.Contains(strings.ToLower(path), qf.Path) {
			return false
		}
	}

	if qf.Rule != "" {
		if !strings.Contains(strings.ToLower(rule), qf.Rule) {
			return false
		}
	}

	if qf.FreeText != "" {
		if _, ok := fuzzyScore(fuzzyHaystack(path, reason, module, severity, rule), qf.FreeText); !ok {
			return false
		}
	}

	return true
}
