package process_test

import (
	"testing"

	"aether/internal/config"
	"aether/internal/modules/process"
	"aether/internal/report"
)

func TestContainerMountNamespaceScoreAdjustment(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// 1. Path-based warning signal inside a container namespace
	signals := []*process.ProcessSignal{
		{
			RuleName:    "Process_Exe_Or_Cwd_In_Temp",
			Reason:      "Process operating in temporary directory /tmp",
			Score:       55,
			Severity:    report.SeverityWarning,
			IsPathBased: true,
		},
	}

	info := &process.ProcessInfo{
		PID:   1001,
		Comm:  "app",
		Exe:   "/tmp/app",
		MntNs: "mnt:[4026532888]",
	}

	selfMntNs := "mnt:[4026531840]"
	isContainer := process.ApplyContainerScoreAdjustment(signals, info, selfMntNs, cfg.Scan.ContainerScoreReduction)
	if !isContainer {
		t.Fatalf("expected isContainer to be true for distinct mount namespaces")
	}

	// 55 - 20 = 35 -> drops below 50 -> SeverityNotice
	if signals[0].Score != 35 {
		t.Errorf("expected score 35, got %d", signals[0].Score)
	}
	if signals[0].Severity != report.SeverityNotice {
		t.Errorf("expected SeverityNotice after container adjustment, got %v", signals[0].Severity)
	}

	finding := process.ConsolidateProcessSignals(signals, info, isContainer)
	if finding == nil {
		t.Fatalf("expected non-nil finding")
	}
	if finding.EvidenceRecord == nil || finding.EvidenceRecord.ContextProfile != "container_namespace" {
		t.Errorf("expected ContextProfile container_namespace, got %v", finding.EvidenceRecord)
	}
}

func TestContainerDirectThreatPreserved(t *testing.T) {
	// 2. Direct threat signal inside container: IOC match or Direct evidence must NOT be reduced
	signals := []*process.ProcessSignal{
		{
			RuleName:    "Threat_IOC_Match_CobaltStrike",
			Reason:      "Cryptographic IOC SHA-256 match",
			Score:       100,
			Severity:    report.SeverityAlert,
			IsIOCMatch:  true,
			IsPathBased: false,
		},
	}

	info := &process.ProcessInfo{
		PID:   1002,
		Comm:  "beacon",
		Exe:   "/app/beacon",
		MntNs: "mnt:[4026532888]",
	}

	selfMntNs := "mnt:[4026531840]"
	isContainer := process.ApplyContainerScoreAdjustment(signals, info, selfMntNs, 20)
	if !isContainer {
		t.Fatalf("expected isContainer to be true")
	}

	// IOC match score is NOT reduced
	if signals[0].Score != 100 {
		t.Errorf("expected score 100 for IOC match, got %d", signals[0].Score)
	}
	if signals[0].Severity != report.SeverityAlert {
		t.Errorf("expected SeverityAlert for IOC match, got %v", signals[0].Severity)
	}

	finding := process.ConsolidateProcessSignals(signals, info, isContainer)
	if finding == nil {
		t.Fatalf("expected non-nil finding")
	}
	if finding.Severity != report.SeverityAlert {
		t.Errorf("expected finding SeverityAlert, got %v", finding.Severity)
	}
}
