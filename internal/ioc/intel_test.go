package ioc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aether/internal/report"
)

func TestLoadBuiltin_CISA(t *testing.T) {
	eng, err := NewEngine(nil, nil)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// Should contain at least 1 demo hash + 17 CISA hashes = 18 hashes
	count := eng.HashRuleCount()
	if count < 18 {
		t.Errorf("expected at least 18 hash rules loaded from built-ins, got %d", count)
	}

	// Verify BPFDoor sample hash is present
	bpfDoorHash := "a918a2d7f9dc6e88c751270dc582496a796695fb42d6cc51e58288cf2f440bf5"
	res := eng.CheckHash(bpfDoorHash)
	if res == nil {
		t.Fatalf("expected BPFDoor hash %s to match, got nil", bpfDoorHash)
	}
	if res.Severity != report.SeverityAlert {
		t.Errorf("expected SeverityAlert, got %v", res.Severity)
	}
	if res.Score != 100 {
		t.Errorf("expected score 100 for hash match, got %d", res.Score)
	}

	// Verify sources summary
	sources := eng.SourceSummary()
	if len(sources) < 2 {
		t.Errorf("expected at least 2 sources in SourceSummary, got %d", len(sources))
	}

	foundCISA := false
	for _, s := range sources {
		if strings.Contains(s.Source, "cisa_linux_malware.txt") {
			foundCISA = true
			if s.Count != 22 {
				t.Errorf("expected 22 indicators in cisa_linux_malware.txt, got %d", s.Count)
			}
		}
	}
	if !foundCISA {
		t.Errorf("cisa_linux_malware.txt source not found in SourceSummary")
	}
}

func TestLoadIntelPackage_Formats(t *testing.T) {
	t.Run("LineDelimitedAndComments", func(t *testing.T) {
		feed := `
# Threat Feed - Top Miners
# Date: 2026-10-13

9e107d9d372bb6826bd81d3542a419d6 # Kinsing crypto miner ELF
01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b # XorDDoS ELF bot
`
		rules, err := LoadIntelPackage(strings.NewReader(feed), "feed.txt")
		if err != nil {
			t.Fatalf("unexpected error parsing feed: %v", err)
		}
		if len(rules) != 2 {
			t.Fatalf("expected 2 rules, got %d", len(rules))
		}
		if rules[0].Type != TypeMD5 || rules[0].Hash != "9e107d9d372bb6826bd81d3542a419d6" {
			t.Errorf("unexpected first rule: %+v", rules[0])
		}
		if rules[1].Type != TypeSHA256 || rules[1].Hash != "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b" {
			t.Errorf("unexpected second rule: %+v", rules[1])
		}
	})

	t.Run("STIX_2x_Bundle", func(t *testing.T) {
		stixJSON := `{
  "type": "bundle",
  "id": "bundle--00000000-0000-0000-0000-000000000001",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--00000000-0000-0000-0000-000000000002",
      "name": "TeamTNT Rootkit",
      "description": "TeamTNT Diamorphine LKM drop",
      "pattern": "[file:hashes.'SHA-256' = '34301d0a514757c91d4e861219b16be9cbff01e4a6e35cb31682855f9630c5e7']"
    },
    {
      "type": "identity",
      "name": "Threat Org"
    }
  ]
}`
		rules, err := LoadIntelPackage(strings.NewReader(stixJSON), "stix_intel.json")
		if err != nil {
			t.Fatalf("unexpected error parsing STIX feed: %v", err)
		}
		if len(rules) != 1 {
			t.Fatalf("expected 1 rule from STIX bundle, got %d", len(rules))
		}
		if rules[0].Hash != "34301d0a514757c91d4e861219b16be9cbff01e4a6e35cb31682855f9630c5e7" {
			t.Errorf("unexpected hash: %s", rules[0].Hash)
		}
		if !strings.Contains(rules[0].Description, "TeamTNT") {
			t.Errorf("expected description to contain TeamTNT, got %q", rules[0].Description)
		}
	})

	t.Run("Generic_JSON_List", func(t *testing.T) {
		jsonList := `[
  {"hash": "d41d8cd98f00b204e9800998ecf8427e", "description": "Empty MD5 test"},
  {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "name": "Empty SHA256"}
]`
		rules, err := LoadIntelPackage(strings.NewReader(jsonList), "list.json")
		if err != nil {
			t.Fatalf("unexpected error parsing generic JSON: %v", err)
		}
		if len(rules) != 2 {
			t.Fatalf("expected 2 rules from JSON list, got %d", len(rules))
		}
	})
}

func TestImportIntelFile_DedupAndPersist(t *testing.T) {
	tmpDir := t.TempDir()

	// Source file 1: contains two unique hashes and one duplicate
	srcContent1 := `
# Feed 1
01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b # Malware A
01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b # Malware A duplicate
34301d0a514757c91d4e861219b16be9cbff01e4a6e35cb31682855f9630c5e7 # Malware B
`
	srcFile1 := filepath.Join(tmpDir, "source1.txt")
	if err := os.WriteFile(srcFile1, []byte(srcContent1), 0644); err != nil {
		t.Fatalf("failed writing test file: %v", err)
	}

	destDir := filepath.Join(tmpDir, "imported_iocs")

	// Import 1
	sum1, err := ImportIntelFile(srcFile1, destDir, false)
	if err != nil {
		t.Fatalf("ImportIntelFile failed: %v", err)
	}
	if sum1.TotalParsed != 2 { // LoadIntelPackage already deduplicates internally
		t.Errorf("expected TotalParsed 2, got %d", sum1.TotalParsed)
	}
	if sum1.NewImported != 2 {
		t.Errorf("expected NewImported 2, got %d", sum1.NewImported)
	}
	if sum1.DuplicatesSkipped != 0 {
		t.Errorf("expected DuplicatesSkipped 0, got %d", sum1.DuplicatesSkipped)
	}

	// Verify imported file was created
	destFile := filepath.Join(destDir, "imported_hashes.txt")
	contentBytes, err := os.ReadFile(destFile)
	if err != nil {
		t.Fatalf("destination file not created: %v", err)
	}
	contentStr := string(contentBytes)
	if !strings.Contains(contentStr, "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b") {
		t.Errorf("missing hash 1 in dest file")
	}

	// Source file 2: contains one already imported hash and one new hash
	srcContent2 := `
# Feed 2
01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b # Already imported
e33e46c75cf707470fcf147230aa7cc7dc22d86f7ef5ebba230ef1d48d4fb9f8 # Brand new malware C
`
	srcFile2 := filepath.Join(tmpDir, "source2.txt")
	if err := os.WriteFile(srcFile2, []byte(srcContent2), 0644); err != nil {
		t.Fatalf("failed writing test file 2: %v", err)
	}

	// Import 2 (append & dedup)
	sum2, err := ImportIntelFile(srcFile2, destDir, false)
	if err != nil {
		t.Fatalf("ImportIntelFile 2 failed: %v", err)
	}
	if sum2.TotalParsed != 2 {
		t.Errorf("expected TotalParsed 2, got %d", sum2.TotalParsed)
	}
	if sum2.NewImported != 1 {
		t.Errorf("expected NewImported 1, got %d", sum2.NewImported)
	}
	if sum2.DuplicatesSkipped != 1 {
		t.Errorf("expected DuplicatesSkipped 1, got %d", sum2.DuplicatesSkipped)
	}

	// Import 3 with overwrite: should overwrite with only source2 contents
	sum3, err := ImportIntelFile(srcFile2, destDir, true)
	if err != nil {
		t.Fatalf("ImportIntelFile overwrite failed: %v", err)
	}
	if sum3.NewImported != 2 {
		t.Errorf("expected NewImported 2 with overwrite, got %d", sum3.NewImported)
	}
}

func TestCISAIntel_AuthenticityAndNoCollisions(t *testing.T) {
	data, err := embeddedIntelFS.ReadFile("intel/cisa_linux_malware.txt")
	if err != nil {
		t.Fatalf("failed to read embedded cisa_linux_malware.txt: %v", err)
	}

	rules, err := ParseHashFile(strings.NewReader(string(data)), "cisa_linux_malware.txt")
	if err != nil {
		t.Fatalf("failed to parse cisa hashes: %v", err)
	}

	if len(rules) != 22 {
		t.Fatalf("expected 22 CISA rules, got %d", len(rules))
	}

	for i := 0; i < len(rules); i++ {
		h1 := rules[i].Hash
		if len(h1) != 64 {
			t.Errorf("rule %s has invalid hash length %d: %s", rules[i].ThreatName, len(h1), h1)
		}
		for j := i + 1; j < len(rules); j++ {
			h2 := rules[j].Hash
			overlap := longestCommonSubstring(h1, h2)
			if overlap >= 12 {
				t.Errorf("suspicious hash collision: rule %q and %q share %d contiguous hex chars: %s vs %s",
					rules[i].ThreatName, rules[j].ThreatName, overlap, h1, h2)
			}
		}
	}
}

func longestCommonSubstring(s1, s2 string) int {
	maxLen := 0
	for i := 0; i < len(s1); i++ {
		for j := 0; j < len(s2); j++ {
			k := 0
			for i+k < len(s1) && j+k < len(s2) && s1[i+k] == s2[j+k] {
				k++
			}
			if k > maxLen {
				maxLen = k
			}
		}
	}
	return maxLen
}
