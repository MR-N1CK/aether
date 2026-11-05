package yara

import (
	"bytes"
	"regexp"
	"testing"
)

// reTestABC is a test-only compiled regex for fallbackPatternMatches offsets.
var reTestABC = regexp.MustCompile(`ABC`)

// fallbackEngineForTests compiles the embedded core rules without demo rules.
func fallbackEngineForTests(t *testing.T) *FallbackEngine {
	t.Helper()
	e := NewFallbackEngine(nil, nil)
	if len(e.rules) == 0 {
		t.Fatal("fallback engine compiled zero embedded rules")
	}
	return e
}

func TestFallbackFirstOffset_LiteralRule(t *testing.T) {
	e := fallbackEngineForTests(t)
	sc := e.NewScanner()
	defer sc.Destroy()

	data := []byte("xx c99shell payload yy")
	matches, err := sc.Scan(ScanTarget{Data: data})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	found := false
	for _, m := range matches {
		if m.RuleName != "Linux_Webshell_PHP_Known_Families" {
			continue
		}
		found = true
		if want := bytes.Index(data, []byte("c99shell")); m.FirstOffset != want {
			t.Errorf("FirstOffset = %d, want %d", m.FirstOffset, want)
		}
	}
	if !found {
		t.Fatal("c99shell sample did not match Linux_Webshell_PHP_Known_Families")
	}
}

func TestFallbackFirstOffset_RegexRule(t *testing.T) {
	e := fallbackEngineForTests(t)
	sc := e.NewScanner()
	defer sc.Destroy()

	data := []byte("padding\n<?php eval($_POST['cmd']);\n")
	matches, err := sc.Scan(ScanTarget{Data: data})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	found := false
	for _, m := range matches {
		if m.RuleName != "Linux_Webshell_PHP_Generic_Backdoor" {
			continue
		}
		found = true
		if m.FirstOffset < 0 || m.FirstOffset >= len(data) {
			t.Errorf("FirstOffset = %d out of range", m.FirstOffset)
		}
		if !bytes.Contains(data[m.FirstOffset:], []byte("eval")) {
			t.Errorf("offset %d does not point at the eval match region", m.FirstOffset)
		}
	}
	if !found {
		t.Fatal("eval($_POST sample did not match Linux_Webshell_PHP_Generic_Backdoor")
	}
}

func TestFallbackFirstOffset_NoMatch(t *testing.T) {
	e := fallbackEngineForTests(t)
	sc := e.NewScanner()
	defer sc.Destroy()

	matches, err := sc.Scan(ScanTarget{Data: []byte("nothing to see here")})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	for _, m := range matches {
		t.Errorf("unexpected match %s on benign buffer", m.RuleName)
	}
}

func TestFallbackPatternMatchesOffsets(t *testing.T) {
	data := []byte("ABCDEF tail")
	low := bytes.ToLower(data)

	regexPat := fallbackPattern{ID: "$r", IsRegex: true, Regex: reTestABC}
	if ok, off := fallbackPatternMatches(regexPat, data, low); !ok || off != 0 {
		t.Errorf("regex pattern: (%v,%d), want (true,0)", ok, off)
	}

	litPat := fallbackPattern{ID: "$l", Literal: []byte("DEF")}
	if ok, off := fallbackPatternMatches(litPat, data, low); !ok || off != 3 {
		t.Errorf("literal pattern: (%v,%d), want (true,3)", ok, off)
	}

	nocasePat := fallbackPattern{ID: "$n", NoCase: true, Literal: []byte("def"), LitLow: []byte("def")}
	if ok, off := fallbackPatternMatches(nocasePat, data, low); !ok || off != 3 {
		t.Errorf("nocase pattern: (%v,%d), want (true,3)", ok, off)
	}

	missPat := fallbackPattern{ID: "$m", Literal: []byte("zzz")}
	if ok, off := fallbackPatternMatches(missPat, data, low); ok || off != -1 {
		t.Errorf("missing pattern: (%v,%d), want (false,-1)", ok, off)
	}
}
