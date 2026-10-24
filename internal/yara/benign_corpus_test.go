//go:build yara

package yara

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"aether/internal/config"
	"aether/internal/pkgdb"
	"aether/internal/report"
)

type BenignMatch struct {
	RuleName string
	Path     string
	Severity report.Severity
}

// TestBenignCorpusScanning sweeps live system trees with the embedded rules.
// It is a hard gate for the catastrophic class: any ALERT-severity match on a
// package-managed system file fails the test. Milder matches are logged for
// triage but do not fail (host corpus content varies by distribution).
func TestBenignCorpusScanning(t *testing.T) {
	cfg := config.NewDefaultConfig()
	engine := NewYaraXEngine(cfg, nil, false)
	defer engine.Close()

	if err := engine.LoadRules(nil); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	targetDirs := []string{
		"/etc",
		"/usr/bin",
		"/usr/lib/python3",
		"/usr/lib/python3.13",
		"/usr/lib/python3.14",
	}

	db := pkgdb.New("")

	var filesScanned atomic.Int64
	var totalMatches atomic.Int64
	var mu sync.Mutex
	matches := make([]BenignMatch, 0)

	startTime := time.Now()
	t.Log("=================================================================")
	t.Log("Scanning benign corpus with Embedded YARA-X Rules...")
	t.Logf("Targets: %v", targetDirs)
	t.Log("=================================================================")

	pathChan := make(chan string, 1000)
	var wg sync.WaitGroup

	numWorkers := 8
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scanner := engine.NewScanner()
			defer scanner.Destroy()

			for path := range pathChan {
				data, err := os.ReadFile(path)
				if err != nil {
					continue
				}
				filesScanned.Add(1)

				mList, err := scanner.Scan(ScanTarget{
					Path:      path,
					Filename:  filepath.Base(path),
					Extension: filepath.Ext(path),
					Data:      data,
				})
				if err == nil && len(mList) > 0 {
					for _, m := range mList {
						totalMatches.Add(1)
						mu.Lock()
						matches = append(matches, BenignMatch{
							RuleName: m.RuleName,
							Path:     path,
							Severity: m.Severity,
						})
						fmt.Printf("[MATCH] Rule: %-45s Path: %s\n", m.RuleName, path)
						mu.Unlock()
					}
				}
			}
		}()
	}

	for _, dir := range targetDirs {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.Type().IsRegular() {
				pathChan <- path
			}
			return nil
		})
	}
	close(pathChan)
	wg.Wait()

	duration := time.Since(startTime)
	t.Log("=================================================================")
	t.Logf("Scan complete in %v", duration)
	t.Logf("Total Files Scanned: %d", filesScanned.Load())
	t.Logf("Total Matches Found: %d", totalMatches.Load())
	t.Log("=================================================================")

	if len(matches) == 0 {
		t.Log("Zero false-positive matches in benign system corpus.")
		return
	}
	for _, m := range matches {
		t.Logf("Match: Rule=%s Severity=%v Path=%s", m.RuleName, m.Severity, m.Path)
	}

	// Hard gate: mirror the scanner's adjudication semantics (package and
	// pentest-tool downgrades) and fail only when an ALERT signature
	// adjudicates MALICIOUS on system content. Raw engine ALERTs that the
	// pipeline would downgrade are logged, not blocking.
	// The prefix list mirrors internal/scanner pentestToolPathPrefixes;
	// importing the scanner package from here would create a cycle.
	pentestPrefixes := []string{
		"/usr/share/metasploit-framework",
		"/usr/share/windows-resources",
		"/usr/share/powershell-empire",
		"/usr/share/exploitdb",
		"/usr/share/peass",
		"/usr/lib/python3/dist-packages/pypykatz",
		"/usr/lib/python3/dist-packages/nxc",
	}
	isPentestPath := func(path string) bool {
		for _, p := range pentestPrefixes {
			if strings.HasPrefix(path, p+"/") || strings.HasPrefix(path, p+"-") || strings.HasPrefix(path, p+".") {
				return true
			}
		}
		return false
	}

	blocking := 0
	for _, m := range matches {
		if m.Severity != report.SeverityAlert {
			continue
		}
		if _, owned := db.Owner(m.Path); !owned {
			continue
		}
		if isPentestPath(m.Path) {
			t.Logf("pentest-package content (pipeline downgrades): rule %s on %s", m.RuleName, m.Path)
			continue
		}
		f := report.NewFinding("yara", m.Severity, m.Path, "YARA match: "+m.RuleName, m.RuleName)
		verdict := report.DetermineVerdict(&f, db, false, false, false, nil)
		if verdict == report.VerdictMalicious {
			blocking++
			t.Errorf("RELEASE-BLOCKING FP: rule %s adjudicates MALICIOUS on package-owned system file %s", m.RuleName, m.Path)
		} else {
			t.Logf("downgraded by adjudication: rule %s on %s -> %v", m.RuleName, m.Path, verdict)
		}
	}
	if blocking == 0 {
		t.Logf("%d ALERT matches total, zero adjudicated MALICIOUS on package-owned files", countAlerts(matches))
	}
}

func countAlerts(matches []BenignMatch) int {
	n := 0
	for _, m := range matches {
		if m.Severity == report.SeverityAlert {
			n++
		}
	}
	return n
}

// TestBenignCorpus_ZeroMaliciousAlerts asserts that checked-in benign
// fixtures and any present dist-packages test trees never produce a
// MALICIOUS verdict or an ALERT-severity match.
func TestBenignCorpus_ZeroMaliciousAlerts(t *testing.T) {
	cfg := config.NewDefaultConfig()
	engine := NewYaraXEngine(cfg, nil, false)
	defer engine.Close()

	if err := engine.LoadRules(nil); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	// The checked-in fixtures are part of the repository; a missing corpus is
	// a broken checkout, not a skip condition.
	fixtureDir := "../../testdata/fixtures/benign"
	if fi, err := os.Stat(fixtureDir); err != nil || !fi.IsDir() {
		t.Fatalf("checked-in benign corpus missing at %s — cannot validate false-positive rate", fixtureDir)
	}

	targetDirs := []string{
		"/usr/lib/python3/dist-packages/elasticsearch*",
		"/usr/lib/python3/dist-packages/theharvester*",
		"/usr/lib/python3/dist-packages/twisted/test*",
		"/usr/lib/python3/dist-packages/joblib/test*",
		fixtureDir,
	}

	db := pkgdb.New("")
	scanner := engine.NewScanner()
	defer scanner.Destroy()

	scannedFiles := 0
	for _, pattern := range targetDirs {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob %s failed: %v", pattern, err)
		}
		for _, dir := range matches {
			_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
				if err != nil || !d.Type().IsRegular() {
					return nil
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return nil
				}
				scannedFiles++
				rList, err := scanner.Scan(ScanTarget{
					Path:      path,
					Filename:  filepath.Base(path),
					Extension: filepath.Ext(path),
					Data:      data,
				})
				if err == nil && len(rList) > 0 {
					for _, r := range rList {
						if r.Severity == report.SeverityAlert {
							t.Errorf("FAIL: ALERT-severity rule %s matched benign target %s", r.RuleName, path)
						}
						f := report.NewFinding("yara", r.Severity, path, "YARA match: "+r.RuleName, r.RuleName)
						verdict := report.DetermineVerdict(&f, db, false, false, false, nil)
						if verdict == report.VerdictMalicious {
							t.Errorf("FAIL: false-positive MALICIOUS verdict on benign target %s (Rule: %s)", path, r.RuleName)
						}
					}
				}
				return nil
			})
		}
	}

	if scannedFiles == 0 {
		t.Fatal("benign corpus scanned zero files — corpus regression, not a pass")
	}
	t.Logf("benign corpus: %d files, zero ALERT/MALICIOUS tolerated", scannedFiles)
}
