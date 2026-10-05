package report_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aether/internal/report"
)

func TestRuntimeFindingSchemaCompliance(t *testing.T) {
	finding := report.Finding{
		Module:              "process",
		RuleName:            "Process_Memfd_Execution",
		Path:                "/proc/1337/exe",
		Reason:              "Anonymous memory descriptor execution",
		Severity:            report.SeverityAlert,
		Verdict:             report.VerdictMalicious,
		Confidence:          report.ConfidenceHigh,
		ConfidenceRationale: "Direct ELF magic in anonymous memfd",
		MITRE: []report.MITREMapping{
			{Tactic: "Defense Evasion", Technique: "T1620", TechniqueName: "Reflective Code Loading"},
		},
		EvidenceRecord: &report.EvidenceRecord{
			DetectorType:     "heuristic",
			RuleName:         "Process_Memfd_Execution",
			EvidenceStrength: report.StrengthDirect,
			MatchedCondition: "ELF magic header in /memfd:payload (deleted)",
			TargetPath:       "/proc/1337/exe",
			PID:              1337,
			Comm:             "memfd_runner",
			Cmdline:          "/tmp/runner --stealth",
			SocketInfo:       "0.0.0.0:4444",
			MountNamespace:   "mnt:[4026531840]",
			PackageStatus:    "unowned",
			ContextProfile:   "standard",
			CorroboratingSignals: []string{
				"network:0.0.0.0:4444",
			},
			CorroborationDetails: []report.CorroboratingSignal{
				{
					Domain:      report.DomainNetwork,
					RuleName:    "Network_Wildcard_Listener",
					Description: "Wildcard listener active on port 4444",
					TargetRef:   "Socket: 0.0.0.0:4444",
					Confidence:  "HIGH",
				},
			},
		},
	}

	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal into raw map failed: %v", err)
	}

	// Required top-level properties per runtime-finding-schema.json
	requiredProps := []string{"module", "rule_name", "path", "reason", "severity", "verdict", "confidence", "evidence_record"}
	for _, prop := range requiredProps {
		if _, exists := raw[prop]; !exists {
			t.Errorf("Missing required property in Finding JSON: %q", prop)
		}
	}

	// Validate evidence_record fields
	evRaw, ok := raw["evidence_record"].(map[string]interface{})
	if !ok {
		t.Fatalf("evidence_record is not a JSON object")
	}

	requiredEvProps := []string{"detector_type", "rule_name", "evidence_strength", "package_status"}
	for _, prop := range requiredEvProps {
		if _, exists := evRaw[prop]; !exists {
			t.Errorf("Missing required property in EvidenceRecord JSON: %q", prop)
		}
	}

	// Check runtime fields
	if pid, ok := evRaw["pid"].(float64); !ok || int(pid) != 1337 {
		t.Errorf("Expected pid 1337, got %v", evRaw["pid"])
	}
	if comm, ok := evRaw["comm"].(string); !ok || comm != "memfd_runner" {
		t.Errorf("Expected comm memfd_runner, got %v", evRaw["comm"])
	}
	if sock, ok := evRaw["socket_info"].(string); !ok || sock != "0.0.0.0:4444" {
		t.Errorf("Expected socket_info 0.0.0.0:4444, got %v", evRaw["socket_info"])
	}
	if mnt, ok := evRaw["mount_namespace"].(string); !ok || mnt != "mnt:[4026531840]" {
		t.Errorf("Expected mount_namespace mnt:[4026531840], got %v", evRaw["mount_namespace"])
	}
}

func TestCorrelationContextSchemaCompliance(t *testing.T) {
	ctx := report.CorrelationContext{
		CorrelationID:    "corr-test-001",
		PrimaryTarget:    "/proc/1337/exe",
		PrimaryPID:       1337,
		PrimaryHash:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		DomainsInvolved:  []report.CorroboratingDomain{report.DomainProcess, report.DomainNetwork},
		EvidenceStrength: report.StrengthCorroborated,
		Verdict:          report.VerdictMalicious,
		Severity:         report.SeverityAlert,
		Confidence:       report.ConfidenceHigh,
		Signals: []report.CorroboratingSignal{
			{
				Domain:      report.DomainProcess,
				RuleName:    "Process_Memfd_Execution",
				Description: "Memfd payload execution",
				TargetRef:   "PID: 1337",
				Confidence:  "HIGH",
				Timestamp:   time.Now().UTC(),
			},
			{
				Domain:      report.DomainNetwork,
				RuleName:    "Network_Wildcard_Listener",
				Description: "Active listener on port 4444",
				TargetRef:   "Socket: 0.0.0.0:4444",
				Confidence:  "HIGH",
				Timestamp:   time.Now().UTC(),
			},
		},
	}

	data, err := json.Marshal(ctx)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal into raw map failed: %v", err)
	}

	// Required fields per correlation-context-schema.json
	requiredFields := []string{
		"correlation_id", "primary_target", "domains_involved",
		"evidence_strength", "verdict", "signals",
	}
	for _, f := range requiredFields {
		if _, exists := raw[f]; !exists {
			t.Errorf("Missing required field %q in CorrelationContext JSON", f)
		}
	}
}

func TestSchemaFilesExist(t *testing.T) {
	schemas := []string{
		"../../specs/003-runtime-threat-assessment/contracts/runtime-finding-schema.json",
		"../../specs/003-runtime-threat-assessment/contracts/correlation-context-schema.json",
		"../../specs/003-runtime-threat-assessment/contracts/benchmark-runtime-schema.json",
	}

	for _, relPath := range schemas {
		absPath, err := filepath.Abs(relPath)
		if err != nil {
			t.Fatalf("Failed to resolve path %s: %v", relPath, err)
		}
		if _, err := os.Stat(absPath); os.IsNotExist(err) {
			t.Errorf("Required schema file does not exist: %s", absPath)
		}
	}
}
