package ioc

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// maxIntelFeedBytes caps the downloaded feed payload before it is staged for
// the forensic import pipeline, so a misbehaving remote feed cannot exhaust
// disk or memory.
const maxIntelFeedBytes = int64(16 << 20)

// intelRefreshTimeout bounds a single production refresh attempt.
const intelRefreshTimeout = 60 * time.Second

// intelUserAgent identifies Aether to feed hosts.
const intelUserAgent = "Aether-Threat-Hunter/0.1.0"

// RefreshIntelFeed downloads a threat-intelligence feed over HTTPS and
// ingests it through the same forensic import pipeline as `aether intel
// import` (validation, dedup, append-only persistence). The payload is
// staged with the feed's own basename so STIX/line-format detection and
// rule source labels stay meaningful, then removed.
//
// Security posture:
//   - URLs must be HTTPS; redirects may never downgrade to another scheme.
//   - At most maxIntelFeedBytes are accepted from the feed.
//   - The temporary staging directory is removed on all paths.
func RefreshIntelFeed(url, destDir string, overwrite bool) (*ImportSummary, error) {
	client := &http.Client{
		Timeout: intelRefreshTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 4 {
				return errors.New("too many redirects")
			}
			if req.URL != nil && req.URL.Scheme != "https" {
				return fmt.Errorf("refusing redirect to non-HTTPS scheme %q", req.URL.Scheme)
			}
			return nil
		},
	}
	return RefreshIntelFeedWithClient(client, url, destDir, overwrite)
}

// RefreshIntelFeedWithClient performs the refresh with a caller-provided HTTP
// client (used by tests to inject TLS endpoints); the HTTPS-only and
// redirect-guard rules still apply to the transport result.
func RefreshIntelFeedWithClient(client *http.Client, url, destDir string, overwrite bool) (*ImportSummary, error) {
	if client == nil {
		return nil, errors.New("nil HTTP client")
	}
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("intel feed URL must use HTTPS, got %q", url)
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid intel feed URL: %w", err)
	}
	req.Header.Set("User-Agent", intelUserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("intel feed download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("intel feed server returned HTTP %d for %s", resp.StatusCode, url)
	}

	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxIntelFeedBytes+1))
	if err != nil {
		return nil, fmt.Errorf("intel feed read failed: %w", err)
	}
	if int64(len(payload)) > maxIntelFeedBytes {
		return nil, fmt.Errorf("intel feed exceeds the %d MiB safety cap", maxIntelFeedBytes>>20)
	}
	if len(bytes.TrimSpace(payload)) == 0 {
		return nil, errors.New("intel feed is empty")
	}

	base := sanitizeFeedName(resp.Request.URL.Path)

	// Stage the payload under a fresh directory so the deterministic,
	// sanitized source basename survives into the import pipeline; the
	// staging directory is always removed afterwards.
	stageDir, err := os.MkdirTemp("", "aether-intel-")
	if err != nil {
		return nil, fmt.Errorf("cannot stage intel feed: %w", err)
	}
	defer os.RemoveAll(stageDir)
	staged := filepath.Join(stageDir, base)
	if err := os.WriteFile(staged, payload, 0o600); err != nil {
		return nil, fmt.Errorf("cannot stage intel feed: %w", err)
	}

	return ImportIntelFile(staged, destDir, overwrite)
}

// sanitizeFeedName derives a safe staging basename from the feed URL path,
// stripping queries, fragments, and empties, defaulting to feed.txt.
func sanitizeFeedName(urlPath string) string {
	// Defensive: drop any query/fragment suffix even though net/url keeps
	// them out of Request.URL.Path.
	if idx := strings.IndexAny(urlPath, "?#"); idx >= 0 {
		urlPath = urlPath[:idx]
	}
	base := path.Base(strings.TrimSpace(urlPath))
	switch base {
	case "", ".", "/":
		return "feed.txt"
	}
	var sb strings.Builder
	sb.Grow(len(base))
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			sb.WriteRune(r)
		default:
			sb.WriteRune('_')
		}
	}
	out := sb.String()
	if len(out) > 64 {
		out = out[len(out)-64:]
	}
	return out
}
