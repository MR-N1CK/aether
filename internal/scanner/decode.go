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
	"regexp"
	"strings"

	"aether/internal/config"
	"aether/internal/pkgdb"
	"aether/internal/report"
)

const (
	maxDecodeDepth       = 3
	maxDecompressedBytes = 32 * 1024 * 1024 // 32 MB safety cap
	minCandidateLen      = 32
)

var (
	base64Pattern = regexp.MustCompile(`[A-Za-z0-9+/=]{32,}`)
	hexPattern    = regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}){16,}|[0-9a-fA-F]{32,}`)
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
	}

	return results
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
	if len(data) < minCandidateLen || IsELF(data) {
		return nil, nil
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

	for len(queue) > 0 {
		select {
		case <-ctx.Done():
			return nil, nil
		default:
		}

		item := queue[0]
		queue = queue[1:]

		if item.depth >= maxDecodeDepth {
			continue
		}

		candidates := extractDecodedCandidates(item.current, maxCap)
		for _, c := range candidates {
			newLayers := append(append([]string(nil), item.layers...), c.layer)

			// 1. Evaluate decoded stream with script heuristics
			if h := CheckSuspiciousScriptContent(path, c.data, pkgDB, cfg); h != nil {
				return &HeuristicMatch{
					Name:     "Script_Obfuscated_Payload",
					Reason:   fmt.Sprintf("Obfuscated payload (%s decoded) matches %s: %s", strings.Join(newLayers, " -> "), h.Name, h.Reason),
					Score:    85,
					Severity: report.SeverityAlert,
				}, newLayers
			}

			// 2. Evaluate decoded stream for hidden private keys
			if k := CheckSuspiciousPrivateKeyMaterial(path, c.data, pkgDB, cfg); k != nil {
				return &HeuristicMatch{
					Name:     "Script_Obfuscated_Payload",
					Reason:   fmt.Sprintf("Obfuscated payload (%s decoded) matches %s: %s", strings.Join(newLayers, " -> "), k.Name, k.Reason),
					Score:    85,
					Severity: report.SeverityAlert,
				}, newLayers
			}

			// 3. Queue candidate for deeper iteration if within depth limit
			if item.depth+1 < maxDecodeDepth {
				queue = append(queue, queueItem{
					current: c.data,
					layers:  newLayers,
					depth:   item.depth + 1,
				})
			}
		}
	}

	return nil, nil
}
