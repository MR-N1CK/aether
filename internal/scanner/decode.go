package scanner

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"aether/internal/config"
	"aether/internal/pkgdb"
	"aether/internal/report"
	"aether/internal/yara"
)

const (
	// maxDecodeDepth bounds the deobfuscation BFS. Depth 5 catches nested
	// chains such as base64(gzip(base64(gzip(payload)))) — common in staged
	// droppers — while the candidate cap (50), match cap (20), per-candidate
	// 32MB decompression cap, memory budget, and context cancellation bound
	// the compute cost.
	maxDecodeDepth       = 5
	maxDecompressedBytes = 32 * 1024 * 1024 // 32 MB safety cap
	minCandidateLen      = 16
)

var (
	base64Pattern      = regexp.MustCompile(`[A-Za-z0-9+/=]{32,}`)
	hexPattern         = regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}){16,}|[0-9a-fA-F]{32,}`)
	reRevEcho          = regexp.MustCompile(`(?:echo|printf)\s+(?:'([^']{16,})'|"([^"]{16,})")\s*\|\s*(?:ba|z|da)?sh\s*\|\s*rev|(?:echo|printf)\s+(?:'([^']{16,})'|"([^"]{16,})")\s*\|\s*rev`)
	reRevHeredoc       = regexp.MustCompile(`rev\s*<<<\s*(?:'([^']{16,})'|"([^"]{16,})")`)
	reRevPython        = regexp.MustCompile(`(?:'([^']{16,})'|"([^"]{16,})")\[::-1\]`)
	reRot13            = regexp.MustCompile(`str_rot13\s*\(\s*(?:'([^']{16,})'|"([^"]{16,})")\s*\)`)
	rePythonB64        = regexp.MustCompile(`(?i)(?:__import__\s*\(\s*['"]base64['"]\s*\)\.b64decode|base64\.b64decode)\s*\(\s*b?['"]([A-Za-z0-9+/=]{16,})['"]\s*\)`)
	rePythonHex        = regexp.MustCompile(`(?i)(?:__import__\s*\(\s*['"]binascii['"]\s*\)\.unhexlify|binascii\.unhexlify)\s*\(\s*b?['"]([0-9a-fA-F]{16,})['"]\s*\)`)
	reB64PipeSh        = regexp.MustCompile(`(?:echo|printf)\s+(?:'([A-Za-z0-9+/=]{16,})'|"([A-Za-z0-9+/=]{16,})")\s*\|\s*base64\s+-(?:d|-decode)`)
	reSingleCharSingle = regexp.MustCompile(`'([a-zA-Z0-9_\-\./])'`)
	reSingleCharDouble = regexp.MustCompile(`"([a-zA-Z0-9_\-\./])"`)
)

// tryGzipDecompress attempts to decompress gzip or zlib data up to maxBytes.
func tryGzipDecompress(data []byte, maxBytes int64) ([]byte, bool) {
	if len(data) < 2 {
		return nil, false
	}

	// 1. Check Gzip magic (\x1f\x8b)
	if bytes.HasPrefix(data, []byte{0x1f, 0x8b}) {
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, false
		}
		defer r.Close()

		limitR := io.LimitReader(r, maxBytes)
		out, err := io.ReadAll(limitR)
		if err == nil && len(out) > 0 {
			return out, true
		}
	}

	// 2. Check Zlib magic (\x78\x01, \x78\x9c, \x78\xda)
	if data[0] == 0x78 && (data[1] == 0x01 || data[1] == 0x9c || data[1] == 0xda) {
		r, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, false
		}
		defer r.Close()

		limitR := io.LimitReader(r, maxBytes)
		out, err := io.ReadAll(limitR)
		if err == nil && len(out) > 0 {
			return out, true
		}
	}

	return nil, false
}

// tryBase64Decode attempts standard and URL base64 decoding on candidate text.
func tryBase64Decode(data []byte) (decoded []byte, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			decoded = nil
			ok = false
		}
	}()

	clean := bytes.TrimSpace(data)
	if len(clean) < minCandidateLen {
		return nil, false
	}

	// Fast rejection: all bytes must belong to base64 alphabet
	for _, b := range clean {
		if !((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') ||
			b == '+' || b == '/' || b == '=' || b == '-' || b == '_' || b == '\r' || b == '\n') {
			return nil, false
		}
	}

	s := strings.TrimSpace(string(clean))
	// Remove internal whitespace/newlines for decoding.
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, " ", "")
	if len(s) < minCandidateLen {
		return nil, false
	}
	// Reject malformed padding: '=' only valid at end (max 2).
	if idx := strings.IndexByte(s, '='); idx != -1 {
		for i := idx; i < len(s); i++ {
			if s[i] != '=' {
				return nil, false
			}
		}
		if len(s)-idx > 2 {
			return nil, false
		}
		// StdEncoding requires len % 4 == 0 when padding present.
		if len(s)%4 != 0 {
			return nil, false
		}
	} else {
		// Without padding, len % 4 == 1 is never valid base64.
		if len(s)%4 == 1 {
			return nil, false
		}
	}

	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil && len(decoded) > 0 {
		return decoded, true
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(decoded) > 0 {
		return decoded, true
	}
	if decoded, err := base64.URLEncoding.DecodeString(s); err == nil && len(decoded) > 0 {
		return decoded, true
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(s); err == nil && len(decoded) > 0 {
		return decoded, true
	}

	return nil, false
}

// tryHexDecode attempts to decode hex character blocks or \xHH escape sequences.
func tryHexDecode(data []byte) ([]byte, bool) {
	clean := bytes.TrimSpace(data)
	if len(clean) < minCandidateLen {
		return nil, false
	}

	s := string(clean)
	if strings.Contains(s, `\x`) {
		cleaned := strings.ReplaceAll(s, `\x`, "")
		if len(cleaned)%2 == 0 && len(cleaned) >= minCandidateLen {
			if decoded, err := hex.DecodeString(cleaned); err == nil && len(decoded) > 0 {
				return decoded, true
			}
		}
	}

	if len(s)%2 == 0 {
		if decoded, err := hex.DecodeString(s); err == nil && len(decoded) > 0 {
			return decoded, true
		}
	}

	return nil, false
}

type decodedCandidate struct {
	data  []byte
	layer string
}

// extractDecodedCandidates inspects raw data for embedded or standalone base64, hex, and gzip payloads.
func extractDecodedCandidates(data []byte, maxBytes int64) []decodedCandidate {
	if len(data) < minCandidateLen {
		return nil
	}

	var results []decodedCandidate

	addResult := func(d []byte, layer string) {
		if len(d) < 16 {
			return
		}
		for _, r := range results {
			if bytes.Equal(r.data, d) {
				return
			}
		}
		results = append(results, decodedCandidate{data: d, layer: layer})
	}

	// 1. Direct gzip / zlib check
	if decompressed, ok := tryGzipDecompress(data, maxBytes); ok {
		addResult(decompressed, "gzip")
	}

	// 2. Direct whole-buffer base64 check
	if decoded, ok := tryBase64Decode(data); ok {
		addResult(decoded, "base64")
	}

	// 3. Scan for embedded base64 blocks (only text without null bytes)
	if len(data) <= 1024*1024 && bytes.IndexByte(data, 0) == -1 {
		matches := base64Pattern.FindAll(data, 10)
		for _, m := range matches {
			if decoded, ok := tryBase64Decode(m); ok {
				addResult(decoded, "base64")
			}
		}

		// 4. Scan for embedded hex blocks
		hexMatches := hexPattern.FindAll(data, 5)
		for _, hm := range hexMatches {
			if decoded, ok := tryHexDecode(hm); ok {
				addResult(decoded, "hex")
			}
		}

		// 5. Scan for rev payload patterns
		for _, m := range reRevEcho.FindAllSubmatch(data, 5) {
			for i := 1; i < len(m); i++ {
				if len(m[i]) >= 16 {
					if rev := tryRevDecode(m[i]); rev != nil {
						addResult(rev, "rev")
					}
					break
				}
			}
		}
		for _, m := range reRevHeredoc.FindAllSubmatch(data, 5) {
			for i := 1; i < len(m); i++ {
				if len(m[i]) >= 16 {
					if rev := tryRevDecode(m[i]); rev != nil {
						addResult(rev, "rev")
					}
					break
				}
			}
		}
		for _, m := range reRevPython.FindAllSubmatch(data, 5) {
			for i := 1; i < len(m); i++ {
				if len(m[i]) >= 16 {
					if rev := tryRevDecode(m[i]); rev != nil {
						addResult(rev, "rev")
					}
					break
				}
			}
		}

		// 6. Scan for rot13 payload patterns
		for _, m := range reRot13.FindAllSubmatch(data, 5) {
			for i := 1; i < len(m); i++ {
				if len(m[i]) >= 16 {
					if rot := tryRot13Decode(m[i]); rot != nil {
						addResult(rot, "rot13")
					}
					break
				}
			}
		}

		// 7. Scan for Python dynamic base64/hex decode patterns
		for _, m := range rePythonB64.FindAllSubmatch(data, 5) {
			if len(m) > 1 && len(m[1]) >= 16 {
				if dec, ok := tryBase64Decode(m[1]); ok {
					addResult(dec, "base64")
				}
			}
		}
		for _, m := range rePythonHex.FindAllSubmatch(data, 5) {
			if len(m) > 1 && len(m[1]) >= 16 {
				if dec, ok := tryHexDecode(m[1]); ok {
					addResult(dec, "hex")
				}
			}
		}
		for _, m := range reB64PipeSh.FindAllSubmatch(data, 5) {
			for i := 1; i < len(m); i++ {
				if len(m[i]) >= 16 {
					if dec, ok := tryBase64Decode(m[i]); ok {
						addResult(dec, "base64")
					}
					break
				}
			}
		}

		// 8. Shell concatenation / de-quoting evasion
		if dequoted := tryShellDequote(data); dequoted != nil {
			addResult(dequoted, "dequote")
		}
	}

	return results
}

// tryShellDequote normalizes bash concatenation and character escaping evasion:
// - Removes empty quote pairs: ba”sh -> bash, c""url -> curl
// - Unquotes single characters inside words: b'a's'h -> bash, c"u"r"l -> curl
// - Strips obfuscating backslashes before alphanumeric/path characters: b\ash -> bash, \b\a\s\h -> bash, \/bin\/sh -> /bin/sh
func tryShellDequote(data []byte) []byte {
	if len(data) < 8 || len(data) > 1024*1024 {
		return nil
	}
	hasEmptySingle := bytes.Contains(data, []byte("''"))
	hasEmptyDouble := bytes.Contains(data, []byte(`""`))
	hasBackslash := bytes.Contains(data, []byte(`\`))
	hasQuote := bytes.Contains(data, []byte("'")) || bytes.Contains(data, []byte(`"`))

	if !hasEmptySingle && !hasEmptyDouble && !hasBackslash && !hasQuote {
		return nil
	}

	work := data

	// 1. Remove empty quotes
	if hasEmptySingle {
		work = bytes.ReplaceAll(work, []byte("''"), nil)
	}
	if hasEmptyDouble {
		work = bytes.ReplaceAll(work, []byte(`""`), nil)
	}

	// 2. Unquote single-character fragments in words (e.g. b'a's'h -> bash, c"u"r"l -> curl)
	if hasQuote {
		work = reSingleCharSingle.ReplaceAll(work, []byte("$1"))
		work = reSingleCharDouble.ReplaceAll(work, []byte("$1"))
	}

	// 3. Strip backslashes escaping ASCII letters or path separators
	if hasBackslash {
		var buf bytes.Buffer
		buf.Grow(len(work))
		for i := 0; i < len(work); i++ {
			if work[i] == '\\' && i+1 < len(work) {
				next := work[i+1]
				// Preserve \xHH for hex decode
				if (next == 'x' || next == 'X') && i+3 < len(work) && isHex(work[i+2]) && isHex(work[i+3]) {
					buf.WriteByte('\\')
					continue
				}
				// Preserve standard C escapes \n, \r, \t, \0, \\
				if next == 'n' || next == 'r' || next == 't' || next == '0' || next == '\\' {
					buf.WriteByte('\\')
					continue
				}
				// Strip backslash before ASCII letter, digit, '/', '-', '_'
				if (next >= 'a' && next <= 'z') || (next >= 'A' && next <= 'Z') ||
					(next >= '0' && next <= '9') || next == '/' || next == '-' || next == '_' {
					continue
				}
			}
			buf.WriteByte(work[i])
		}
		work = buf.Bytes()
	}

	if !bytes.Equal(work, data) {
		return work
	}
	return nil
}

func isHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func tryRevDecode(b []byte) []byte {
	if len(b) < 16 {
		return nil
	}
	rev := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		rev[i] = b[len(b)-1-i]
	}
	return rev
}

func tryRot13Decode(b []byte) []byte {
	if len(b) < 16 {
		return nil
	}
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			out[i] = 'a' + (c-'a'+13)%26
		} else if c >= 'A' && c <= 'Z' {
			out[i] = 'A' + (c-'A'+13)%26
		} else {
			out[i] = c
		}
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// DecodeAndRescan progressively decodes up to 3 layers of obfuscation in memory and evaluates
// whether the inner payload contains malicious scripts or stolen keys.
func DecodeAndRescan(
	ctx context.Context,
	path string,
	data []byte,
	pkgDB pkgdb.PackageDB,
	cfg *config.Config,
	budget *MemoryBudget,
) (*HeuristicMatch, []string) {
	matches, layers, _ := DecodeAndRescanWithYARA(ctx, path, data, pkgDB, cfg, budget, nil)
	if len(matches) > 0 {
		return matches[0], layers
	}
	return nil, nil
}

// DecodeAndRescanWithYARA evaluates both native heuristics and compiled YARA rules across
// progressively decoded candidates in memory up to 3 layers deep, collecting ALL matching threats.
func DecodeAndRescanWithYARA(
	ctx context.Context,
	path string,
	data []byte,
	pkgDB pkgdb.PackageDB,
	cfg *config.Config,
	budget *MemoryBudget,
	yScanner yara.Scanner,
) ([]*HeuristicMatch, []string, []yara.RuleMatch) {
	if len(data) < minCandidateLen || IsELF(data) {
		return nil, nil, nil
	}

	maxCap := int64(maxDecompressedBytes)
	if cfg != nil && cfg.Scan.MaxFileSize > 0 && cfg.Scan.MaxFileSize < maxCap {
		maxCap = cfg.Scan.MaxFileSize
	}

	type queueItem struct {
		current []byte
		layers  []string
		depth   int
	}

	queue := []queueItem{{current: data, layers: nil, depth: 0}}
	var allMatches []*HeuristicMatch
	var allLayers []string
	var allYaraMatches []yara.RuleMatch
	seenMatches := make(map[string]bool)

	totalCandidatesEvaluated := 0
	const maxCandidatesLimit = 50
	const maxMatchesLimit = 20

	for len(queue) > 0 && totalCandidatesEvaluated < maxCandidatesLimit && len(allMatches) < maxMatchesLimit {
		select {
		case <-ctx.Done():
			return allMatches, allLayers, allYaraMatches
		default:
		}

		item := queue[0]
		queue = queue[1:]

		if item.depth >= maxDecodeDepth {
			continue
		}

		candidates := extractDecodedCandidates(item.current, maxCap)
		for _, c := range candidates {
			totalCandidatesEvaluated++
			newLayers := append(append([]string(nil), item.layers...), c.layer)

			// 1. Evaluate decoded stream with multi-signal script heuristics
			scriptMatches := CheckAllSuspiciousScriptContent(path, c.data, pkgDB, cfg)
			for _, h := range scriptMatches {
				key := fmt.Sprintf("%s:%s", h.Name, h.Reason)
				if seenMatches[key] {
					continue
				}
				seenMatches[key] = true
				if len(allLayers) == 0 {
					allLayers = newLayers
				}

				score := h.Score + 5
				if score > 100 {
					score = 100
				}
				sev := h.Severity
				if sev == report.SeverityAlert && score < 90 {
					score = 90
				}
				allMatches = append(allMatches, &HeuristicMatch{
					Name:     "Script_Obfuscated_Payload",
					Reason:   fmt.Sprintf("Obfuscated payload (%s decoded) matches %s: %s", strings.Join(newLayers, " -> "), h.Name, h.Reason),
					Score:    score,
					Severity: sev,
				})
			}

			// 2. Evaluate decoded stream for hidden private keys
			if k := CheckSuspiciousPrivateKeyMaterial(path, c.data, pkgDB, cfg); k != nil {
				key := fmt.Sprintf("%s:%s", k.Name, k.Reason)
				if !seenMatches[key] {
					seenMatches[key] = true
					if len(allLayers) == 0 {
						allLayers = newLayers
					}
					allMatches = append(allMatches, &HeuristicMatch{
						Name:     "Script_Obfuscated_Payload",
						Reason:   fmt.Sprintf("Obfuscated payload (%s decoded) matches %s: %s", strings.Join(newLayers, " -> "), k.Name, k.Reason),
						Score:    70,
						Severity: report.SeverityWarning,
					})
				}
			}

			// 3. Evaluate decoded stream with compiled YARA rules (if engine active)
			if yScanner != nil {
				target := yara.ScanTarget{
					Path:      path,
					Filename:  filepath.Base(path),
					Extension: filepath.Ext(path),
					Data:      c.data,
				}
				if yMatches, err := yScanner.Scan(target); err == nil && len(yMatches) > 0 {
					for _, ym := range yMatches {
						key := fmt.Sprintf("yara:%s", ym.RuleName)
						if !seenMatches[key] {
							seenMatches[key] = true
							if len(allLayers) == 0 {
								allLayers = newLayers
							}
							allYaraMatches = append(allYaraMatches, ym)

							score := ym.Score
							sev := ym.Severity
							if sev == report.SeverityAlert && score < 85 {
								score = 85
							}
							allMatches = append(allMatches, &HeuristicMatch{
								Name:     "Script_Obfuscated_Payload",
								Reason:   fmt.Sprintf("Obfuscated payload (%s decoded) matches YARA rule %s", strings.Join(newLayers, " -> "), ym.RuleName),
								Score:    score,
								Severity: sev,
							})
						}
					}
				}
			}

			// 4. Queue candidate for deeper iteration if within depth limit
			if item.depth+1 < maxDecodeDepth {
				queue = append(queue, queueItem{
					current: c.data,
					layers:  newLayers,
					depth:   item.depth + 1,
				})
			}
		}
	}

	return allMatches, allLayers, allYaraMatches
}
