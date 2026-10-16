package plain

import (
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/x/term"
)

const (
	// MinUsableWidth is the narrowest terminal width considered usable for card layout.
	MinUsableWidth = 40
	// DefaultContentWidth is the fallback content width for non-TTY writers (CI logs).
	DefaultContentWidth = 92
	// MaxCardWidth caps ASCII box width so wide terminals keep a readable silhouette.
	MaxCardWidth = 110
)

// ContentWidth returns the effective card content width for a writer.
// Resolution order: COLUMNS environment variable, live TTY size, fallback width.
// Values below MinUsableWidth are ignored so tiny or corrupt values never shred layout.
func ContentWidth(w io.Writer, fallback int) int {
	if cols := os.Getenv("COLUMNS"); cols != "" {
		if n, err := strconv.Atoi(cols); err == nil && n >= MinUsableWidth {
			return n
		}
	}
	if f, ok := w.(*os.File); ok && IsTerminalWriter(w) {
		if width, _, err := term.GetSize(f.Fd()); err == nil && width >= MinUsableWidth {
			return width
		}
	}
	if fallback < MinUsableWidth {
		return DefaultContentWidth
	}
	return fallback
}

// WrapWords wraps text to a rune-safe content width. Words longer than width
// are hard-split to guarantee every returned line fits. Returns at least one line.
func WrapWords(s string, width int) []string {
	if width < 1 {
		width = 1
	}
	s = strings.ReplaceAll(s, "\t", "    ")

	var lines []string
	var current strings.Builder
	currentLen := 0

	flushCurrent := func() {
		lines = append(lines, strings.TrimRight(current.String(), " "))
		current.Reset()
		currentLen = 0
	}

	for _, word := range strings.Fields(s) {
		wordRunes := []rune(word)
		if len(wordRunes) > width {
			if currentLen > 0 {
				flushCurrent()
			}
			for len(wordRunes) > width {
				lines = append(lines, string(wordRunes[:width]))
				wordRunes = wordRunes[width:]
			}
			if len(wordRunes) > 0 {
				current.WriteString(string(wordRunes))
				currentLen = len(wordRunes)
			}
			continue
		}
		if currentLen == 0 {
			current.WriteString(word)
			currentLen = len(wordRunes)
			continue
		}
		if currentLen+1+len(wordRunes) > width {
			flushCurrent()
			current.WriteString(word)
			currentLen = len(wordRunes)
			continue
		}
		current.WriteString(" ")
		current.WriteString(word)
		currentLen += 1 + len(wordRunes)
	}

	if currentLen > 0 {
		flushCurrent()
	}
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}
