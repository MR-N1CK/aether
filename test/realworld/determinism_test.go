package realworld_test

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

// TestRealWorldDeterminismTenRuns verifies that running Aether assessments 10 consecutive times
// over real-world environment profiles produces 100% deterministic, byte-for-byte identical output.
func TestRealWorldDeterminismTenRuns(t *testing.T) {
	baseCorpus := findTestProfilesDir(t)

	profiles := []string{
		"desktop-standard",
		"server-web",
		"workstation-pentest",
		"upgraded-pending",
	}

	fixedTimestamp := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

	for _, pName := range profiles {
		t.Run(pName, func(t *testing.T) {
			profileDir := filepath.Join(baseCorpus, pName)

			const runs = 10
			var firstFindingsJSON []byte
			var firstPosture string

			for run := 1; run <= runs; run++ {
				_, findings, ass, _ := runProfileAudit(t, profileDir)

				// Normalize timestamps to fixed epoch for byte-for-byte deterministic comparison
				for i := range findings {
					findings[i].Timestamp = fixedTimestamp
				}

				findingsJSON, err := json.Marshal(findings)
				if err != nil {
					t.Fatalf("run %d: failed to marshal findings: %v", run, err)
				}

				if run == 1 {
					firstFindingsJSON = findingsJSON
					firstPosture = string(ass.Posture)
					continue
				}

				if string(ass.Posture) != firstPosture {
					t.Fatalf("run %d: posture divergence: got %s, expected %s",
						run, ass.Posture, firstPosture)
				}

				if !bytes.Equal(findingsJSON, firstFindingsJSON) {
					t.Fatalf("run %d: byte-for-byte findings divergence from run 1:\nRun 1: %s\nRun %d: %s",
						run, string(firstFindingsJSON), run, string(findingsJSON))
				}
			}

			t.Logf("[%s] 10 consecutive runs produced 100%% byte-for-byte identical verdicts and findings.", pName)
		})
	}
}
