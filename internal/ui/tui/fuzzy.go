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
