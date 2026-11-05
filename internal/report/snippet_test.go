package report

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCaptureSnippet_ContextLines(t *testing.T) {
	data := []byte("line one\nline two\nline three MATCH HERE\nline four\nline five\nline six")
	off := bytes.Index(data, []byte("MATCH"))

	sn := CaptureSnippet(data, off)
	if sn == nil {
		t.Fatal("expected snippet, got nil")
	}
	if len(sn.Lines) != 5 {
		t.Fatalf("expected 5 context lines (2 before + match + 2 after), got %d", len(sn.Lines))
	}
	if sn.MatchIndex != 2 {
		t.Errorf("expected MatchIndex 2, got %d", sn.MatchIndex)
	}
	if sn.Lines[sn.MatchIndex].Number != 3 {
		t.Errorf("expected match line number 3, got %d", sn.Lines[sn.MatchIndex].Number)
	}
	for i, l := range sn.Lines {
		wantMatch := i == 2
		if l.IsMatch != wantMatch {
			t.Errorf("line %d: IsMatch = %v, want %v", i, l.IsMatch, wantMatch)
		}
		if l.Number != i+1 {
			t.Errorf("line %d: Number = %d, want %d", i, l.Number, i+1)
		}
	}
	if want := len("line three "); sn.MatchCol != want {
		t.Errorf("expected MatchCol %d, got %d", want, sn.MatchCol)
	}
}

func TestCaptureSnippet_MatchAtBoundaries(t *testing.T) {
	// Match on the very first line: no leading context, only trailing.
	data := []byte("MATCH FIRST\nb\nc\nd")
	sn := CaptureSnippet(data, 0)
	if sn == nil || len(sn.Lines) != 3 || sn.MatchIndex != 0 || !sn.Lines[0].IsMatch {
		t.Fatalf("unexpected snippet at start: %+v", sn)
	}

	// Match on the last byte.
	data = []byte("a\nb\nc\nlast MATCH")
	off := bytes.Index(data, []byte("MATCH"))
	sn = CaptureSnippet(data, off)
	if sn == nil || len(sn.Lines) != 3 || sn.MatchIndex != 2 {
		t.Fatalf("unexpected snippet at end: %+v", sn)
	}
	if sn.Lines[sn.MatchIndex].Number != 4 || !sn.Lines[sn.MatchIndex].IsMatch {
		t.Fatalf("match line wrong: %+v", sn.Lines[sn.MatchIndex])
	}
}

func TestCaptureSnippet_InvalidOffsets(t *testing.T) {
	if CaptureSnippet(nil, 0) != nil {
		t.Error("empty data must return nil")
	}
	if CaptureSnippet([]byte("abc"), -1) != nil {
		t.Error("negative offset must return nil")
	}
	if CaptureSnippet([]byte("abc"), 3) != nil {
		t.Error("offset == len(data) must return nil")
	}
}

func TestCaptureSnippet_TruncatesLongLines(t *testing.T) {
	long := strings.Repeat("A", 600)
	data := []byte("x\n" + long + "\ny")
	off := bytes.Index(data, []byte(long))

	sn := CaptureSnippet(data, off)
	if sn == nil {
		t.Fatal("expected snippet")
	}
	text := sn.Lines[sn.MatchIndex].Text
	runes := []rune(text)
	if len(runes) != SnippetMaxLineLen+1 { // truncated body + ellipsis
		t.Fatalf("expected %d runes (truncated + …), got %d", SnippetMaxLineLen+1, len(runes))
	}
	if !strings.HasSuffix(text, "…") {
		t.Error("truncated line must end with ellipsis")
	}
}

func TestCaptureSnippet_RuneColumn(t *testing.T) {
	// Multi-byte prefix: MatchCol must count runes, not bytes.
	data := []byte("héllo MATCH")
	off := bytes.Index(data, []byte("MATCH"))
	sn := CaptureSnippet(data, off)
	if want := utf8.RuneCountInString("héllo "); sn.MatchCol != want {
		t.Errorf("expected rune column %d, got %d", want, sn.MatchCol)
	}
}

func TestSnippetContext_MatchedLineHelpers(t *testing.T) {
	var nilSnip *SnippetContext
	if text, no := nilSnip.MatchedLine(); text != "" || no != 0 {
		t.Error("nil snippet must return empty matched line")
	}

	sn := &SnippetContext{Lines: []SnippetLine{{Number: 7, Text: "hit", IsMatch: true}}, MatchIndex: 0}
	if text, no := sn.MatchedLine(); text != "hit" || no != 7 {
		t.Errorf("unexpected matched line %q@%d", text, no)
	}

	// Out-of-range index degrades to empty.
	sn.MatchIndex = 5
	if text, _ := sn.MatchedLine(); text != "" {
		t.Error("out-of-range MatchIndex must return empty text")
	}
}
