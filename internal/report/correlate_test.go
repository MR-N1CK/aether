package report_test

import (
	"testing"
	"time"

	"aether/internal/report"
)

func TestCorrelateFindings_MultiVectorThreatEscalation(t *testing.T) {
	// Scenario: Suspicious dropper script on disk + running process + active network listener
	now := time.Now().UTC()

	fsFinding := report.Finding{
		Module:     "scanner",
		Severity:   report.SeverityWarning,
		Verdict:    report.VerdictSuspicious,
		Confidence: report.ConfidenceMedium,
		Path:       "/tmp/dropper.sh",
		Reason:     "Remote pipe execution command detected (curl | bash)",
		RuleName:   "Script_Download_And_Execute",
		EvidenceRecord: &report.EvidenceRecord{
			DetectorType:        "heuristic",
			RuleName:            "Script_Download_And_Execute",
			TargetPath:          "/tmp/dropper.sh",
			EvidenceStrength:    report.StrengthContextual,
			PackageStatus:       "unowned",
			ContextProfile:      "standard",
			ConfidenceRationale: "Contextual anomaly without execution corroboration",
		},
	}

	procFinding := report.Finding{
		Module:     "process",
		Severity:   report.SeverityWarning,
		Verdict:    report.VerdictSuspicious,
		Confidence: report.ConfidenceMedium,
		Path:       "/proc/1337/exe -> /tmp/dropper.sh",
		Reason:     "Process operating in temporary directory",
		RuleName:   "Process_Exe_Or_Cwd_In_Temp",
		Metadata: map[string]interface{}{
			"pid":  1337,
			"comm": "dropper.sh",
		},
		EvidenceRecord: &report.EvidenceRecord{
			DetectorType:        "module",
			RuleName:            "Process_Exe_Or_Cwd_In_Temp",
			TargetPath:          "/tmp/dropper.sh",
			PID:                 1337,
			Comm:                "dropper.sh",
			EvidenceStrength:    report.StrengthContextual,
			PackageStatus:       "unowned",
			ContextProfile:      "standard",
			ConfidenceRationale: "Process running from temporary directory",
		},
	}

	netFinding := report.Finding{
		Module:     "network",
		Severity:   report.SeverityNotice,
		Verdict:    report.VerdictSuspicious,
		Confidence: report.ConfidenceMedium,
		Path:       "/proc/net/tcp",
		Reason:     "Wildcard network listener on 0.0.0.0:4444 owned by process \"dropper.sh\" (PID 1337)",
		RuleName:   "Network_Wildcard_Listener_Unrecognized_Process",
		Metadata: map[string]interface{}{
			"pid":        1337,
			"comm":       "dropper.sh",
			"local_ip":   "0.0.0.0",
			"local_port": 4444,
		},
		EvidenceRecord: &report.EvidenceRecord{
			DetectorType:        "module",
			RuleName:            "Network_Wildcard_Listener_Unrecognized_Process",
			TargetPath:          "/tmp/dropper.sh",
			PID:                 1337,
			Comm:                "dropper.sh",
			SocketInfo:          "0.0.0.0:4444",
			EvidenceStrength:    report.StrengthContextual,
			PackageStatus:       "unowned",
			ContextProfile:      "standard",
			ConfidenceRationale: "Unrecognized wildcard network listener",
		},
	}

	persFinding := report.Finding{
		Module:     "persistence",
		Severity:   report.SeverityWarning,
		Verdict:    report.VerdictSuspicious,
		Confidence: report.ConfidenceMedium,
		Path:       "/tmp/dropper.sh",
		Reason:     "Cron job invokes script in temporary directory (/etc/cron.d/sync -> /tmp/dropper.sh)",
		RuleName:   "Persistence_Cron_Temp_Target",
		EvidenceRecord: &report.EvidenceRecord{
			DetectorType:        "module",
			RuleName:            "Persistence_Cron_Temp_Target",
			TargetPath:          "/tmp/dropper.sh",
			EvidenceStrength:    report.StrengthContextual,
			PackageStatus:       "unowned",
			ContextProfile:      "standard",
			ConfidenceRationale: "Cron job target in temporary directory",
		},
	}

	findings := []report.Finding{fsFinding, procFinding, netFinding, persFinding}
	_ = now

	correlated := report.CorrelateFindings(findings)

	// Verify that filesystem finding was elevated to ALERT / MALICIOUS / StrengthCorroborated
	var elevatedFS *report.Finding
	for i := range correlated {
		if correlated[i].Module == "scanner" {
			elevatedFS = &correlated[i]
			break
		}
	}

	if elevatedFS == nil {
		t.Fatalf("scanner finding not found after correlation")
	}

	if elevatedFS.Verdict != report.VerdictMalicious {
		t.Errorf("expected VerdictMalicious, got %v", elevatedFS.Verdict)
	}
	if elevatedFS.Severity != report.SeverityAlert {
		t.Errorf("expected SeverityAlert, got %v", elevatedFS.Severity)
	}
	if elevatedFS.Confidence != report.ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh, got %v", elevatedFS.Confidence)
	}
	if elevatedFS.EvidenceRecord.EvidenceStrength != report.StrengthCorroborated {
		t.Errorf("expected StrengthCorroborated, got %v", elevatedFS.EvidenceRecord.EvidenceStrength)
	}
	if len(elevatedFS.EvidenceRecord.CorroborationDetails) < 2 {
		t.Errorf("expected >= 2 corroboration details, got %d", len(elevatedFS.EvidenceRecord.CorroborationDetails))
	}
}

func TestCorrelateFindings_UncorroboratedStandaloneScript(t *testing.T) {
	// Scenario: Uncorroborated standalone dual-use script without running process or network activity
	fsFinding := report.Finding{
		Module:     "scanner",
		Severity:   report.SeverityWarning,
		Verdict:    report.VerdictSuspicious,
		Confidence: report.ConfidenceMedium,
		Path:       "/usr/local/bin/installer.sh",
		Reason:     "curl | bash pipe detected",
		RuleName:   "Script_Download_And_Execute",
		EvidenceRecord: &report.EvidenceRecord{
			DetectorType:        "heuristic",
			RuleName:            "Script_Download_And_Execute",
			TargetPath:          "/usr/local/bin/installer.sh",
			EvidenceStrength:    report.StrengthContextual,
			PackageStatus:       "unowned",
			ContextProfile:      "standard",
			ConfidenceRationale: "Contextual anomaly without execution corroboration",
		},
	}

	findings := []report.Finding{fsFinding}
	correlated := report.CorrelateFindings(findings)

	if len(correlated) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(correlated))
	}

	f := correlated[0]
	if f.Verdict != report.VerdictSuspicious {
		t.Errorf("uncorroborated script must remain VerdictSuspicious, got %v", f.Verdict)
	}
	if f.Severity != report.SeverityWarning {
		t.Errorf("uncorroborated script must remain SeverityWarning, got %v", f.Severity)
	}
	if f.EvidenceRecord.EvidenceStrength != report.StrengthContextual {
		t.Errorf("uncorroborated script must remain StrengthContextual, got %v", f.EvidenceRecord.EvidenceStrength)
	}
}

func TestCorrelateFindings_DocMetadataPreserved(t *testing.T) {
	// Scenario: Doc metadata pattern in package wheel must never be elevated
	docFinding := report.Finding{
		Module:     "scanner",
		Severity:   report.SeverityNotice,
		Verdict:    report.VerdictSafe,
		Confidence: report.ConfidenceLow,
		Path:       "/usr/lib/python3/dist-packages/test.dist-info/METADATA",
		Reason:     "Documentation pattern match",
		RuleName:   "Doc_Metadata_Match",
		EvidenceRecord: &report.EvidenceRecord{
			DetectorType:        "heuristic",
			RuleName:            "Doc_Metadata_Match",
			TargetPath:          "/usr/lib/python3/dist-packages/test.dist-info/METADATA",
			EvidenceStrength:    report.StrengthContextual,
			PackageStatus:       "verified_package",
			ContextProfile:      "doc_metadata",
			ConfidenceRationale: "Inert metadata",
		},
	}

	findings := []report.Finding{docFinding}
	correlated := report.CorrelateFindings(findings)

	if len(correlated) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(correlated))
	}

	f := correlated[0]
	if f.Verdict != report.VerdictSafe {
		t.Errorf("doc metadata must remain VerdictSafe, got %v", f.Verdict)
	}
}

// TestCorrelateSkipsAggregateFindings locks the legitimate-daemon false
// positive: a directory-level aggregate finding ("/usr/bin" grouping key)
// must never be elevated to MALICIOUS by cross-domain corroboration, because
// some persistence entry always references some file under /usr/bin.
func TestCorrelateSkipsAggregateFindings(t *testing.T) {
	agg := report.Finding{
		Module: "filesystem", Severity: report.SeverityWarning,
		Path: "/usr/bin", RuleName: "ELF_AntiAnalysis_Corrupted_Header",
		Count: 3, Paths: []string{"/usr/bin/upx-ucl", "/usr/bin/tool-a", "/usr/bin/tool-b"},
	}
	pers := report.Finding{
		Module: "persistence", Severity: report.SeverityNotice,
		Path: "/etc/systemd/system/sniffer.service", RuleName: "Systemd_Unit_Exec_Unknown_Binary",
	}
	out := report.CorrelateFindings([]report.Finding{agg, pers})
	for _, f := range out {
		if f.RuleName == agg.RuleName && f.Verdict == report.VerdictMalicious {
			t.Fatalf("aggregate finding elevated to MALICIOUS: %+v", f)
		}
	}

	// Control: a concrete single-file finding correlated across domains still elevates.
	concrete := report.Finding{
		Module: "filesystem", Severity: report.SeverityWarning,
		Path: "/tmp/.cache/implant", RuleName: "ELF_Behavioral_ReverseShell_Combo",
	}
	proc := report.Finding{
		Module: "process", Severity: report.SeverityWarning,
		Path: "/tmp/.cache/implant", RuleName: "Process_Memfd_Execution", Metadata: map[string]interface{}{"pid": 4242},
	}
	out2 := report.CorrelateFindings([]report.Finding{concrete, proc})
	elevated := false
	for _, f := range out2 {
		if f.RuleName == concrete.RuleName && f.Verdict == report.VerdictMalicious {
			elevated = true
		}
	}
	if !elevated {
		t.Fatal("concrete cross-domain threat failed to elevate to MALICIOUS — correlation over-suppressed")
	}
}
