//go:build yara

package yara

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
}

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
	} else {
		for _, m := range matches {
			t.Logf("Match: Rule=%s Path=%s", m.RuleName, m.Path)
		}
	}
}

func TestBenignCorpus_ZeroMaliciousAlerts(t *testing.T) {
	cfg := config.NewDefaultConfig()
	engine := NewYaraXEngine(cfg, nil, false)
	defer engine.Close()

	if err := engine.LoadRules(nil); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	targetDirs := []string{
		"/usr/lib/python3/dist-packages/elasticsearch*",
		"/usr/lib/python3/dist-packages/theharvester*",
		"/usr/lib/python3/dist-packages/twisted/test*",
		"/usr/lib/python3/dist-packages/joblib/test*",
		"../../testdata/fixtures/benign",
	}

	db := pkgdb.New("")
	scanner := engine.NewScanner()
	defer scanner.Destroy()

	for _, pattern := range targetDirs {
		matches, err := filepath.Glob(pattern)
		if err != nil || len(matches) == 0 {
			continue
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
				rList, err := scanner.Scan(ScanTarget{
					Path:      path,
					Filename:  filepath.Base(path),
					Extension: filepath.Ext(path),
					Data:      data,
				})
				if err == nil && len(rList) > 0 {
					for _, r := range rList {
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
}
