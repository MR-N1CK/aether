package yara

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// This file implements a pure-Go interpreter for the YARA subset used by
// Aether's embedded rule set. Both the YARA-X engine (yara build tag) and the
// fallback engine compile the exact same rule source (EmbeddedCoreLinuxRules),
// so the two engines cannot drift apart. When extending the embedded rules,
// keep them inside this grammar:
//
//	rule NAME {
//	    meta: key = "value" | key = number
//	    strings: $id = "literal" [ascii] [nocase]
//	           | $id = /regex/ [ascii] [nocase]
//	    condition: boolean expression over $ids, filesize, uint32(0)
//	}
//
// Condition grammar: and/or/not, parentheses, $id, "any of them",
// "all of them", "N of ($prefix*)", "N of ($a, $b)", "filesize < N[MB|KB]",
// "uint32(N) == 0xHEX". Regexes must be RE2-compatible (no backreferences).

// fallbackPattern is one compiled string entry of a fallback rule.
type fallbackPattern struct {
	ID      string
	IsRegex bool
	Literal []byte // raw literal bytes when !IsRegex
	LitLow  []byte // lowercase literal when NoCase && !IsRegex, else nil
	Regex   *regexp.Regexp
	NoCase  bool
}

// fallbackRule is a fully compiled rule ready for evaluation.
type fallbackRule struct {
	Name     string
	Meta     map[string]interface{}
	Patterns []fallbackPattern
	Cond     condNode
	MaxSize  int64 // smallest filesize cap found in the condition; math.MaxInt64 if none
}

// ---------------------------------------------------------------------------
// Condition AST
// ---------------------------------------------------------------------------

type condNode interface {
	eval(c *condCtx) bool
}

// condCtx carries per-file evaluation state: the buffer, which pattern ids
// matched, and the full id list of the rule (for "of them" / wildcard sets).
type condCtx struct {
	data    []byte
	allIDs  []string
	matched map[string]bool
}

type condAnd struct{ L, R condNode }

func (n condAnd) eval(c *condCtx) bool { return n.L.eval(c) && n.R.eval(c) }

type condOr struct{ L, R condNode }

func (n condOr) eval(c *condCtx) bool { return n.L.eval(c) || n.R.eval(c) }

type condNot struct{ X condNode }

func (n condNot) eval(c *condCtx) bool { return !n.X.eval(c) }

type condBool struct{ V bool }

func (n condBool) eval(*condCtx) bool { return n.V }

type condID struct{ ID string }

func (n condID) eval(c *condCtx) bool { return c.matched[n.ID] }

type condFilesizeLT struct{ Max int64 }

func (n condFilesizeLT) eval(c *condCtx) bool { return int64(len(c.data)) < n.Max }

type condUint32Eq struct {
	Off uint64
	Val uint32
}

func (n condUint32Eq) eval(c *condCtx) bool {
	if n.Off+4 > uint64(len(c.data)) {
		return false
	}
	v := uint32(c.data[n.Off]) | uint32(c.data[n.Off+1])<<8 |
		uint32(c.data[n.Off+2])<<16 | uint32(c.data[n.Off+3])<<24
	return v == n.Val
}

// condCountOf is true when at least N of the listed identifiers match.
// N == countAll means all listed identifiers must match.
type condCountOf struct {
	IDs []string
	N   int
}

const countAll = -1

func (n condCountOf) eval(c *condCtx) bool {
	need := n.N
	if need == countAll {
		need = len(n.IDs)
	}
	count := 0
	for _, id := range n.IDs {
		if c.matched[id] {
			count++
			if count >= need {
				return true
			}
		}
	}
	return count >= need
}

// condOfThem counts over every pattern of the rule ("any/all of them").
type condOfThem struct{ All bool }

func (n condOfThem) eval(c *condCtx) bool {
	count := 0
	for _, id := range c.allIDs {
		if c.matched[id] {
			count++
			if !n.All {
				return true
			}
		}
	}
	return n.All && count == len(c.allIDs)
}

// condOfPrefix counts over every pattern whose id starts with Prefix
// ("N of ($foo*)").
type condOfPrefix struct {
	Prefix string
	N      int
}

func (n condOfPrefix) eval(c *condCtx) bool {
	count := 0
	for _, id := range c.allIDs {
		if strings.HasPrefix(id, n.Prefix) && c.matched[id] {
			count++
			if count >= n.N {
				return true
			}
		}
	}
	return false
}

// smallestFilesizeCap walks the AST and returns the strictest filesize limit.
// Disjunction caps widen (a rule matches if either branch allows the size).
func smallestFilesizeCap(n condNode) int64 {
	switch t := n.(type) {
	case condAnd:
		return minInt64(smallestFilesizeCap(t.L), smallestFilesizeCap(t.R))
	case condOr:
		return maxInt64(smallestFilesizeCap(t.L), smallestFilesizeCap(t.R))
	case condFilesizeLT:
		return t.Max
	}
	return math.MaxInt64
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

type tokenKind int

const (
	tokEOF tokenKind = iota
	tokIdent
	tokDollarIdent // $foo
	tokStar        // * (wildcard inside "of (...)" sets)
	tokString      // "literal" (decoded bytes in text)
	tokRegex       // /regex/ (raw pattern text without delimiters)
	tokNumber      // integer; unit multiplier (KB/MB) already applied
	tokHex         // 0x... ; numeric value in num
	tokLBrace
	tokRBrace
	tokLParen
	tokRParen
	tokAssign // =
	tokColon
	tokComma
	tokLT // <
	tokEq // ==
	tokSemi
)

type token struct {
	kind tokenKind
	text string
	num  int64
}

type lexer struct {
	src  string
	pos  int
	toks []token
}

func lexYARASubset(src string) ([]token, error) {
	l := &lexer{src: src}
	for {
		l.skipWhitespaceAndComments()
		if l.pos >= len(l.src) {
			l.emit(token{kind: tokEOF})
			return l.toks, nil
		}
		c := l.src[l.pos]
		switch {
		case c == '{':
			l.emit(token{kind: tokLBrace, text: "{"})
			l.pos++
		case c == '}':
			l.emit(token{kind: tokRBrace, text: "}"})
			l.pos++
		case c == '(':
			l.emit(token{kind: tokLParen, text: "("})
			l.pos++
		case c == ')':
			l.emit(token{kind: tokRParen, text: ")"})
			l.pos++
		case c == '*':
			l.emit(token{kind: tokStar, text: "*"})
			l.pos++
		case c == '[':
			// YARA `[...]` counting / offset syntax is not in the subset.
			return nil, fmt.Errorf("unsupported '[' at offset %d (square-bracket condition syntax is outside the fallback subset)", l.pos)
		case c == '=':
			if strings.HasPrefix(l.src[l.pos:], "==") {
				l.emit(token{kind: tokEq, text: "=="})
				l.pos += 2
			} else {
				l.emit(token{kind: tokAssign, text: "="})
				l.pos++
			}
		case c == ':':
			l.emit(token{kind: tokColon, text: ":"})
			l.pos++
		case c == ',':
			l.emit(token{kind: tokComma, text: ","})
			l.pos++
		case c == '<':
			l.emit(token{kind: tokLT, text: "<"})
			l.pos++
		case c == ';':
			l.emit(token{kind: tokSemi, text: ";"})
			l.pos++
		case c == '$':
			start := l.pos
			l.pos++
			for l.pos < len(l.src) && isIdentChar(l.src[l.pos]) {
				l.pos++
			}
			if l.pos == start+1 {
				return nil, fmt.Errorf("bare '$' at offset %d", start)
			}
			l.emit(token{kind: tokDollarIdent, text: l.src[start:l.pos]})
		case c == '"':
			raw, err := l.lexQuoted()
			if err != nil {
				return nil, err
			}
			l.emit(token{kind: tokString, text: raw})
		case c == '/':
			if l.pos+1 < len(l.src) && l.src[l.pos+1] == '/' {
				// line comment
				for l.pos < len(l.src) && l.src[l.pos] != '\n' {
					l.pos++
				}
				continue
			}
			raw, err := l.lexRegex()
			if err != nil {
				return nil, err
			}
			l.emit(token{kind: tokRegex, text: raw})
		case c == '0' && strings.HasPrefix(l.src[l.pos:], "0x"):
			start := l.pos
			l.pos += 2
			for l.pos < len(l.src) && isHexDigit(l.src[l.pos]) {
				l.pos++
			}
			v, err := strconv.ParseInt(l.src[start:l.pos], 0, 64)
			if err != nil {
				return nil, fmt.Errorf("bad hex number %q: %v", l.src[start:l.pos], err)
			}
			l.emit(token{kind: tokHex, num: v})
		case c >= '0' && c <= '9':
			start := l.pos
			for l.pos < len(l.src) && l.src[l.pos] >= '0' && l.src[l.pos] <= '9' {
				l.pos++
			}
			v, err := strconv.ParseInt(l.src[start:l.pos], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("bad number %q: %v", l.src[start:l.pos], err)
			}
			// optional KB/MB multiplier
			if strings.HasPrefix(l.src[l.pos:], "MB") {
				v *= 1024 * 1024
				l.pos += 2
			} else if strings.HasPrefix(l.src[l.pos:], "KB") {
				v *= 1024
				l.pos += 2
			}
			l.emit(token{kind: tokNumber, num: v})
		case isIdentStart(c):
			start := l.pos
			for l.pos < len(l.src) && isIdentChar(l.src[l.pos]) {
				l.pos++
			}
			l.emit(token{kind: tokIdent, text: l.src[start:l.pos]})
		default:
			return nil, fmt.Errorf("unexpected character %q at offset %d", string(c), l.pos)
		}
	}
}

func (l *lexer) emit(t token) { l.toks = append(l.toks, t) }

func (l *lexer) skipWhitespaceAndComments() {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			l.pos++
			continue
		}
		if c == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '*' {
			end := strings.Index(l.src[l.pos+2:], "*/")
			if end < 0 {
				l.pos = len(l.src)
				return
			}
			l.pos += 2 + end + 2
			continue
		}
		return
	}
}

// lexQuoted reads a double-quoted string starting at l.pos and returns the
// unescaped bytes.
func (l *lexer) lexQuoted() (string, error) {
	l.pos++ // opening quote
	var b strings.Builder
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if c == '"' {
			l.pos++
			return b.String(), nil
		}
		if c == '\\' && l.pos+1 < len(l.src) {
			n := l.src[l.pos+1]
			switch n {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '\\':
				b.WriteByte('\\')
			case '"':
				b.WriteByte('"')
			case 'x':
				if l.pos+3 < len(l.src) {
					v, err := strconv.ParseUint(l.src[l.pos+2:l.pos+4], 16, 8)
					if err != nil {
						return "", fmt.Errorf("bad \\x escape at offset %d", l.pos)
					}
					b.WriteByte(byte(v))
					l.pos += 4
					continue
				}
				return "", fmt.Errorf("truncated \\x escape at offset %d", l.pos)
			default:
				// Keep unknown escapes verbatim so regex-relevant data survives.
				b.WriteByte('\\')
				b.WriteByte(n)
			}
			l.pos += 2
			continue
		}
		b.WriteByte(c)
		l.pos++
	}
	return "", fmt.Errorf("unterminated string literal")
}

// lexRegex reads a /regex/ body starting at l.pos (the opening delimiter) and
// returns the raw pattern text without delimiters.
func (l *lexer) lexRegex() (string, error) {
	l.pos++ // opening '/'
	start := l.pos
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if c == '\\' && l.pos+1 < len(l.src) {
			l.pos += 2
			continue
		}
		if c == '/' {
			pat := l.src[start:l.pos]
			l.pos++
			return pat, nil
		}
		l.pos++
	}
	return "", fmt.Errorf("unterminated regex literal at offset %d", start)
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentChar(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

type fallbackParser struct {
	toks []token
	pos  int
}

// parseYARASubset compiles a YARA-subset rule source into fallback rules.
// Rules that use syntax outside the subset return an error naming the rule.
func parseYARASubset(src string) ([]fallbackRule, error) {
	toks, err := lexYARASubset(src)
	if err != nil {
		return nil, err
	}
	p := &fallbackParser{toks: toks}
	var rules []fallbackRule
	for p.peek().kind != tokEOF {
		r, err := p.parseRule()
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func (p *fallbackParser) peek() token { return p.toks[p.pos] }

func (p *fallbackParser) next() token {
	t := p.toks[p.pos]
	if t.kind != tokEOF {
		p.pos++
	}
	return t
}

func (p *fallbackParser) expectKind(k tokenKind, what string) (token, error) {
	t := p.next()
	if t.kind != k {
		return t, fmt.Errorf("expected %s, got %q", what, t.text)
	}
	return t, nil
}

func (p *fallbackParser) expectKeyword(kw string) error {
	t := p.next()
	if t.kind != tokIdent || t.text != kw {
		return fmt.Errorf("expected keyword %q, got %q", kw, t.text)
	}
	return nil
}

func (p *fallbackParser) atKeyword(kw string) bool {
	t := p.peek()
	return t.kind == tokIdent && t.text == kw
}

func (p *fallbackParser) parseRule() (fallbackRule, error) {
	var r fallbackRule
	if err := p.expectKeyword("rule"); err != nil {
		return r, err
	}
	nameTok, err := p.expectKind(tokIdent, "rule name")
	if err != nil {
		return r, err
	}
	r.Name = nameTok.text

	// Optional ":tag" list is not used by the embedded rules.
	if _, err := p.expectKind(tokLBrace, "'{'"); err != nil {
		return r, err
	}

	r.Meta = map[string]interface{}{}
	seenCond := false
	for {
		t := p.peek()
		if t.kind == tokRBrace {
			p.next()
			break
		}
		if t.kind == tokEOF {
			return r, fmt.Errorf("rule %s: unexpected end of source inside rule", r.Name)
		}
		if t.kind == tokIdent && t.text == "meta" {
			p.next()
			if _, err := p.expectKind(tokColon, "':' after meta"); err != nil {
				return r, err
			}
			if err := p.parseMeta(r.Meta); err != nil {
				return r, fmt.Errorf("rule %s meta: %v", r.Name, err)
			}
			continue
		}
		if t.kind == tokIdent && t.text == "strings" {
			p.next()
			if _, err := p.expectKind(tokColon, "':' after strings"); err != nil {
				return r, err
			}
			pats, err := p.parseStrings()
			if err != nil {
				return r, fmt.Errorf("rule %s strings: %v", r.Name, err)
			}
			r.Patterns = pats
			continue
		}
		if t.kind == tokIdent && t.text == "condition" {
			p.next()
			if _, err := p.expectKind(tokColon, "':' after condition"); err != nil {
				return r, err
			}
			cond, err := p.parseExpr()
			if err != nil {
				return r, fmt.Errorf("rule %s condition: %v", r.Name, err)
			}
			r.Cond = cond
			seenCond = true
			continue
		}
		return r, fmt.Errorf("rule %s: unexpected token %q (expected meta/strings/condition/})", r.Name, t.text)
	}
	if !seenCond {
		return r, fmt.Errorf("rule %s: missing condition section", r.Name)
	}
	if r.Cond == nil {
		return r, fmt.Errorf("rule %s: empty condition", r.Name)
	}

	r.MaxSize = smallestFilesizeCap(r.Cond)

	if err := validateConditionIDs(r.Cond, r.Patterns, r.Name); err != nil {
		return r, err
	}
	return r, nil
}

func (p *fallbackParser) parseMeta(meta map[string]interface{}) error {
	for {
		// A meta key is an identifier immediately followed by '='; anything
		// else (e.g. the "strings"/"condition" section keywords) ends the
		// meta block.
		if p.peek().kind != tokIdent || p.pos+1 >= len(p.toks) ||
			p.toks[p.pos+1].kind != tokAssign {
			return nil
		}
		key := p.next().text
		if _, err := p.expectKind(tokAssign, "'='"); err != nil {
			return err
		}
		v := p.next()
		switch v.kind {
		case tokString:
			meta[key] = v.text
		case tokNumber, tokHex:
			meta[key] = int(v.num)
		case tokIdent: // bare identifiers such as true/false
			meta[key] = v.text
		default:
			return fmt.Errorf("meta %s: unsupported value token %q", key, v.text)
		}
	}
}

func (p *fallbackParser) parseStrings() ([]fallbackPattern, error) {
	var pats []fallbackPattern
	for {
		t := p.peek()
		if t.kind != tokDollarIdent {
			return pats, nil
		}
		id := p.next().text
		if _, err := p.expectKind(tokAssign, "'='"); err != nil {
			return nil, err
		}
		val := p.next()
		var pat fallbackPattern
		pat.ID = id
		switch val.kind {
		case tokString:
			pat.Literal = []byte(val.text)
		case tokRegex:
			pat.IsRegex = true
		default:
			return nil, fmt.Errorf("%s: unsupported pattern value %q (hex strings { .. } are not supported)", id, val.text)
		}

		// modifiers; the "condition" section keyword terminates the strings
		// block, not a modifier list.
		for {
			m := p.peek()
			if m.kind != tokIdent || m.text == "condition" {
				break
			}
			switch m.text {
			case "ascii":
				p.next()
			case "nocase":
				p.next()
				pat.NoCase = true
			case "wide", "fullword", "private", "xor", "base64":
				return nil, fmt.Errorf("%s: modifier %q is outside the fallback subset", id, m.text)
			default:
				return nil, fmt.Errorf("%s: unknown modifier %q", id, m.text)
			}
		}

		if pat.IsRegex {
			re, err := compileFallbackRegex(val.text, pat.NoCase)
			if err != nil {
				return nil, fmt.Errorf("%s: regex %q is not RE2-compatible: %v (rewrite the rule to stay within the fallback subset)", id, val.text, err)
			}
			pat.Regex = re
		} else if pat.NoCase {
			pat.LitLow = []byte(strings.ToLower(string(pat.Literal)))
		}
		pats = append(pats, pat)
	}
}

// compileFallbackRegex compiles a YARA regex body for Go's RE2 engine. YARA
// escapes forward slashes (\/); RE2 accepts that escape directly, so the
// pattern is passed through unchanged apart from an optional (?i) prefix.
func compileFallbackRegex(pat string, nocase bool) (*regexp.Regexp, error) {
	if nocase {
		pat = "(?i)" + pat
	}
	return regexp.Compile(pat)
}

func (p *fallbackParser) parseExpr() (condNode, error) {
	return p.parseOr()
}

func (p *fallbackParser) parseOr() (condNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.atKeyword("or") {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = condOr{L: left, R: right}
	}
	return left, nil
}

func (p *fallbackParser) parseAnd() (condNode, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.atKeyword("and") {
		p.next()
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = condAnd{L: left, R: right}
	}
	return left, nil
}

func (p *fallbackParser) parseNot() (condNode, error) {
	if p.atKeyword("not") {
		p.next()
		x, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return condNot{X: x}, nil
	}
	return p.parsePrimary()
}

func (p *fallbackParser) parsePrimary() (condNode, error) {
	t := p.peek()
	switch t.kind {
	case tokLParen:
		p.next()
		inner, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expectKind(tokRParen, "')'"); err != nil {
			return nil, err
		}
		return inner, nil
	case tokDollarIdent:
		p.next()
		return condID{ID: t.text}, nil
	case tokIdent:
		switch t.text {
		case "true", "false":
			p.next()
			return condBool{V: t.text == "true"}, nil
		case "filesize":
			p.next()
			if _, err := p.expectKind(tokLT, "'<'"); err != nil {
				return nil, fmt.Errorf("only 'filesize < N' is supported: %v", err)
			}
			num, err := p.expectKind(tokNumber, "file size bound")
			if err != nil {
				return nil, err
			}
			return condFilesizeLT{Max: num.num}, nil
		case "uint8", "uint16", "uint32":
			p.next()
			if _, err := p.expectKind(tokLParen, "'('"); err != nil {
				return nil, err
			}
			off, err := p.expectKind(tokNumber, "offset")
			if err != nil {
				return nil, err
			}
			if _, err := p.expectKind(tokRParen, "')'"); err != nil {
				return nil, err
			}
			if _, err := p.expectKind(tokEq, "'=='"); err != nil {
				return nil, fmt.Errorf("only '%s(N) == 0x..' is supported: %v", t.text, err)
			}
			val, err := p.expectKind(tokHex, "hex constant")
			if err != nil {
				return nil, err
			}
			if t.text != "uint32" {
				return nil, fmt.Errorf("%s(N) comparisons are outside the fallback subset", t.text)
			}
			return condUint32Eq{Off: uint64(off.num), Val: uint32(val.num)}, nil
		case "any", "all":
			p.next()
			if err := p.expectKeyword("of"); err != nil {
				return nil, err
			}
			if p.peek().kind == tokIdent && p.peek().text == "them" {
				p.next()
				return condOfThem{All: t.text == "all"}, nil
			}
			set, err := p.parseOfSet()
			if err != nil {
				return nil, err
			}
			return set.withCount(1)
		default:
			return nil, fmt.Errorf("unsupported identifier %q in condition", t.text)
		}
	case tokNumber:
		// "N of (...)" counted form.
		p.next()
		n := t.num
		if err := p.expectKeyword("of"); err != nil {
			return nil, err
		}
		set, err := p.parseOfSet()
		if err != nil {
			return nil, err
		}
		return set.withCount(int(n))
	}
	return nil, fmt.Errorf("unexpected token %q in condition", t.text)
}

// ofSet is the intermediate parse result of the list after "of".
type ofSet struct {
	ids    []string // explicit id list ($a, $b) — set when !wildcard
	prefix string   // "$foo*" wildcard — set when ids == nil
	all    bool     // "them"
}

// withCount converts the set into a condition node requiring n matches.
func (s ofSet) withCount(n int) (condNode, error) {
	if s.all {
		return condOfThem{All: true}, nil
	}
	if s.ids == nil {
		return condOfPrefix{Prefix: s.prefix, N: n}, nil
	}
	return condCountOf{IDs: s.ids, N: n}, nil
}

// parseOfSet parses "( $a, $b, ... )" or "( $prefix* )" or bare "them".
func (p *fallbackParser) parseOfSet() (ofSet, error) {
	t := p.peek()
	if t.kind == tokIdent && t.text == "them" {
		p.next()
		return ofSet{all: true}, nil
	}
	if _, err := p.expectKind(tokLParen, "'(' after 'of'"); err != nil {
		return ofSet{}, err
	}
	var ids []string
	wildcard := false
	var prefix string
	for {
		idTok, err := p.expectKind(tokDollarIdent, "'$id' inside 'of (...)'")
		if err != nil {
			return ofSet{}, err
		}
		if wildcard {
			return ofSet{}, fmt.Errorf("cannot mix wildcard and explicit ids inside 'of (...)'")
		}
		nt := p.next()
		if nt.kind == tokStar {
			wildcard = true
			prefix = idTok.text
			nt = p.next()
		} else {
			ids = append(ids, idTok.text)
		}
		switch nt.kind {
		case tokComma:
			continue
		case tokRParen:
			if wildcard {
				return ofSet{prefix: prefix}, nil
			}
			return ofSet{ids: ids}, nil
		default:
			return ofSet{}, fmt.Errorf("unexpected token %q inside 'of (...)'", nt.text)
		}
	}
}

// validateConditionIDs rejects conditions referencing undefined $ids.
func validateConditionIDs(n condNode, pats []fallbackPattern, ruleName string) error {
	defined := map[string]bool{}
	for _, p := range pats {
		defined[p.ID] = true
	}
	var ids []string
	collectCondIDs(n, &ids)
	for _, id := range ids {
		if !defined[id] {
			return fmt.Errorf("rule %s: condition references undefined identifier %s", ruleName, id)
		}
	}
	return nil
}

func collectCondIDs(n condNode, out *[]string) {
	switch t := n.(type) {
	case condAnd:
		collectCondIDs(t.L, out)
		collectCondIDs(t.R, out)
	case condOr:
		collectCondIDs(t.L, out)
		collectCondIDs(t.R, out)
	case condNot:
		collectCondIDs(t.X, out)
	case condID:
		*out = append(*out, t.ID)
	case condCountOf:
		*out = append(*out, t.IDs...)
	}
}
