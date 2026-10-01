package report_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"aether/internal/report"
)

func TestConcurrentReporter(t *testing.T) {
	tmpDir := t.TempDir()
	jsonOut := filepath.Join(tmpDir, "findings.json")

	rep, err := report.NewConcurrentReporter(jsonOut)
	if err != nil {
		t.Fatalf("failed to create reporter: %v", err)
	}

	const workerCount = 20
	const findingsPerWorker = 50

	var wg sync.WaitGroup
	wg.Add(workerCount)

	for i := 0; i < workerCount; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < findingsPerWorker; j++ {
				var sev report.Severity
				switch (workerID + j) % 4 {
				case 0:
					sev = report.SeverityInfo
				case 1:
					sev = report.SeverityNotice
				case 2:
					sev = report.SeverityWarning
				case 3:
					sev = report.SeverityAlert
				}
				f := report.NewFinding(
					fmt.Sprintf("mod-%d", workerID),
					sev,
					fmt.Sprintf("/tmp/test_%d_%d", workerID, j),
					"test reason",
					"RULE_TEST",
				)
				rep.Report(f)
			}
		}(i)
	}

	wg.Wait()

	if err := rep.Close(); err != nil {
		t.Fatalf("failed to close reporter: %v", err)
	}

	expectedTotal := workerCount * findingsPerWorker
	findings := rep.Findings()
	if len(findings) != expectedTotal {
		t.Errorf("expected %d findings, got %d", expectedTotal, len(findings))
	}

	total, alerts, warnings, notices, infos := rep.Summary()
	if total != expectedTotal {
		t.Errorf("expected total %d, got %d", expectedTotal, total)
	}
	if alerts+warnings+notices+infos != total {
		t.Errorf("summary counts do not sum to total: %d != %d", alerts+warnings+notices+infos, total)
	}

	// Verify JSON file exists and was written
	stat, err := os.Stat(jsonOut)
	if err != nil {
		t.Fatalf("json output file stat failed: %v", err)
	}
	if stat.Size() == 0 {
		t.Errorf("expected non-empty json output file")
	}
}
