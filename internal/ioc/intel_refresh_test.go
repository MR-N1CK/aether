package ioc

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureFeed is a minimal line-delimited hash feed.
var fixtureFeed = `# suspicious sample hashes
44d886ef53a8ed4ca82d0f1ec4b8b3e3 # eicar-style marker
0123456789abcdef0123456789abcdef
`

func TestRefreshIntelFeed_IngestsHTTPSFeed(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, fixtureFeed)
	}))
	defer srv.Close()

	dest := t.TempDir()
	summary, err := RefreshIntelFeedWithClient(srv.Client(), srv.URL+"/feeds/malware-hashes.txt", dest, false)
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	if summary.TotalParsed != 2 {
		t.Errorf("expected 2 parsed hashes, got %d", summary.TotalParsed)
	}
	if summary.NewImported != 2 {
		t.Errorf("expected 2 imported hashes, got %d", summary.NewImported)
	}
	// Source label must carry the sanitized feed basename.
	if !strings.Contains(summary.SourceFile, "malware-hashes.txt") {
		t.Errorf("expected sanitized source label, got %q", summary.SourceFile)
	}
	// Destination actually contains the ingested hashes.
	blob, readErr := os.ReadFile(filepath.Join(dest, "imported_hashes.txt"))
	if readErr != nil {
		t.Fatalf("destination file missing: %v", readErr)
	}
	if !strings.Contains(string(blob), "44d886ef53a8ed4ca82d0f1ec4b8b3e3") {
		t.Errorf("ingested hash missing from destination: %s", blob)
	}
}

func TestRefreshIntelFeed_IngestsSTIXBundle(t *testing.T) {
	stix := `{"type":"bundle","objects":[{"type":"indicator","name":"malware","pattern":"[file:hashes.md5 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']"}]}`
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, stix)
	}))
	defer srv.Close()

	dest := t.TempDir()
	summary, err := RefreshIntelFeedWithClient(srv.Client(), srv.URL+"/bundle.json", dest, false)
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	if summary.NewImported != 1 {
		t.Errorf("expected 1 STIX indicator imported, got %+v", summary)
	}
}

func TestRefreshIntelFeed_RejectsPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	if _, err := RefreshIntelFeedWithClient(srv.Client(), srv.URL+"/feed.txt", t.TempDir(), false); err == nil {
		t.Fatal("plain HTTP feed must be rejected")
	}
}

func TestRefreshIntelFeed_RejectsHTTPDowngradeRedirect(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://insecure.example/feed.txt", http.StatusFound)
	}))
	defer srv.Close()
	if _, err := RefreshIntelFeedWithClient(srv.Client(), srv.URL+"/start.txt", t.TempDir(), false); err == nil {
		t.Fatal("redirect downgrading to HTTP must be refused")
	}
}

func TestRefreshIntelFeed_RejectsOversize(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve more than the cap in chunks (16 MiB + 1).
		filler := strings.Repeat("0", 4096)
		n := (maxIntelFeedBytes / int64(len(filler))) + 2
		for i := int64(0); i < n; i++ {
			if _, err := fmt.Fprint(w, filler); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	if _, err := RefreshIntelFeedWithClient(srv.Client(), srv.URL+"/big.txt", t.TempDir(), false); err == nil {
		t.Fatal("oversized feed must be rejected")
	}
}

func TestRefreshIntelFeed_ServerError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := RefreshIntelFeedWithClient(srv.Client(), srv.URL+"/feed.txt", t.TempDir(), false); err == nil {
		t.Fatal("HTTP 500 must surface as an error")
	}
}

func TestRefreshIntelFeed_RedirectChainIntoHTTPSOk(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/final.txt" {
			fmt.Fprint(w, fixtureFeed)
			return
		}
		http.Redirect(w, r, "https://"+r.Host+"/final.txt", http.StatusFound)
	}))
	defer srv.Close()

	dest := t.TempDir()
	summary, err := RefreshIntelFeedWithClient(srv.Client(), srv.URL+"/start.txt", dest, false)
	if err != nil {
		t.Fatalf("same-scheme redirect chain must succeed: %v", err)
	}
	if summary.TotalParsed != 2 {
		t.Errorf("expected 2 parsed hashes after redirect, got %d", summary.TotalParsed)
	}
}

func TestRefreshIntelFeed_SanitizeFeedName(t *testing.T) {
	cases := map[string]string{
		"/feeds/a b/c.md5?x=1":                 "c.md5",
		"/":                                    "feed.txt",
		"/../etc/passwd":                       "passwd", // path.Base collapses traversal
		"/feed":                                "feed",
		"/" + strings.Repeat("a", 70) + "MARK": strings.Repeat("a", 60) + "MARK", // tail-64 kept
	}
	for in, want := range cases {
		if got := sanitizeFeedName(in); got != want {
			t.Errorf("sanitizeFeedName(%q) = %q, want %q", in, got, want)
		}
	}
}
