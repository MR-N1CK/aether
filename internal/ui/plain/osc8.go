package plain

import (
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/x/ansi"
)

// OSC 8 terminal hyperlink support (DESIGN.md §6): file paths in plain
// output become clickable in modern terminals. The escape sequences carry
// zero display width — ANSI-aware width functions skip them — so card
// layout math is unaffected.

// osc8Enabled reports whether OSC 8 hyperlinks may be emitted on w:
// only on real terminals, and never when AETHER_NO_OSC8 is set.
func osc8Enabled(w io.Writer) bool {
	if os.Getenv("AETHER_NO_OSC8") != "" {
		return false
	}
	return IsTerminalWriter(w)
}

// osc8Link wraps text in an OSC 8 hyperlink pointing at the file:// URI of
// path. Returns text unchanged when path is empty.
func osc8Link(path, text string) string {
	if path == "" || text == "" {
		return text
	}
	return "\x1b]8;;file://" + path + "\x1b\\" + text + "\x1b]8;;\x1b\\"
}

// padCell pads s with trailing spaces up to a visible display width,
// correctly ignoring ANSI color and OSC 8 escape sequences.
func padCell(s string, width int) string {
	if vis := ansi.StringWidth(s); vis < width {
		return s + strings.Repeat(" ", width-vis)
	}
	return s
}
