package report

import (
	"bytes"
	"strings"
)

const (
	// SnippetMaxLineLen bounds each rendered snippet line so a minified
	// one-line payload cannot blow up the dossier modal or report width.
	SnippetMaxLineLen = 240
	// SnippetContextLines is the number of context lines shown above and
	// below the matched line.
	SnippetContextLines = 2
)

// CaptureSnippet extracts the matched line plus SnippetContextLines context
// lines from the in-memory scan buffer at detection time. matchOffset is a
// 0-based byte offset into data. It never re-opens the inspected file; when
// the offset is out of range or data is empty it returns nil.
func CaptureSnippet(data []byte, matchOffset int) *SnippetContext {
	if len(data) == 0 || matchOffset < 0 || matchOffset >= len(data) {
		return nil
	}

	lineStart := matchOffset
	for lineStart > 0 && data[lineStart-1] != '\n' {
		lineStart--
	}
	lineEnd := matchOffset
	for lineEnd < len(data) && data[lineEnd] != '\n' {
		lineEnd++
	}

	// Walk back SnippetContextLines full lines to the first context line.
	firstStart := lineStart
	for walked := 0; walked < SnippetContextLines && firstStart > 0; walked++ {
		firstStart-- // the '\n' terminating the previous line
		for firstStart > 0 && data[firstStart-1] != '\n' {
			firstStart--
		}
	}

	// Walk forward SnippetContextLines full lines to the last context line.
	lastEnd := lineEnd
	for walked := 0; walked < SnippetContextLines && lastEnd < len(data); walked++ {
		lastEnd++ // skip the '\n' terminating the current line
		for lastEnd < len(data) && data[lastEnd] != '\n' {
			lastEnd++
		}
	}

	firstLineNo := 1 + bytes.Count(data[:firstStart], []byte{'\n'})
	segments := strings.Split(string(data[firstStart:lastEnd]), "\n")
	matchIndex := bytes.Count(data[firstStart:lineStart], []byte{'\n'})

	lines := make([]SnippetLine, 0, len(segments))
	for i, seg := range segments {
		seg = strings.TrimSuffix(seg, "\r")
		lines = append(lines, SnippetLine{
			Number:  firstLineNo + i,
			Text:    truncateRunes(seg, SnippetMaxLineLen),
			IsMatch: i == matchIndex,
		})
	}

	return &SnippetContext{
		Lines:      lines,
		MatchIndex: matchIndex,
		MatchCol:   runeLen(data[lineStart:matchOffset]),
	}
}

// MatchedLine returns the matched snippet line content and 1-based source line
// number, or empty values when no snippet was captured.
func (s *SnippetContext) MatchedLine() (string, int) {
	if s == nil || s.MatchIndex < 0 || s.MatchIndex >= len(s.Lines) {
		return "", 0
	}
	line := s.Lines[s.MatchIndex]
	return line.Text, line.Number
}

func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "…"
}

func runeLen(b []byte) int {
	return len([]rune(string(b)))
}
