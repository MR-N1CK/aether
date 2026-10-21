package report_test

import (
	"sort"
	"testing"

	"aether/internal/report"
)

func TestRegisterRuleMeta_Enforcement(t *testing.T) {
	// First registration succeeds (unique name); second panics.
	report.RegisterRuleMeta("Test_Duplicate_Rule", report.RuleMeta{
		Title: "X", Why: "y", Remediation: []string{"r"},
	})
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on duplicate registration")
		}
	}()
	report.RegisterRuleMeta("Test_Duplicate_Rule", report.RuleMeta{
		Title: "X", Why: "y", Remediation: []string{"r"},
	})
}

func TestRegisterRuleMeta_RejectsEmpty(t *testing.T) {
	cases := []struct {
		name string
		meta report.RuleMeta
	}{
		{"missing_why", report.RuleMeta{Title: "T", Remediation: []string{"r"}}},
		{"missing_remediation", report.RuleMeta{Title: "T", Why: "w"}},
		{"missing_title", report.RuleMeta{Why: "W", Remediation: []string{"r"}}},
	}
	for _, tc := range cases {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("expected panic for case %s", tc.name)
				}
			}()
			report.RegisterRuleMeta("Test_Invalid_"+tc.name, tc.meta)
		}()
	}
}

func TestLookupRuleMeta_RegisteredRulesResolve(t *testing.T) {
	// Spot-check a sample from each registration family.
	for _, name := range []string{
		"Persistence_Multi_Vector_Persistence",
		"File_Suspicious_Private_Key_Location",
		"Script_RedTeam_Persistence_Framework",
		"Script_Reverse_Shell_Interactive",
		"Script_Netcat_Reverse_Shell",
		"Script_OpenSSL_Reverse_Shell",
		"Script_Socat_Reverse_Shell",
		"Script_Reverse_Shell_Inline",
		"Script_Python_Ransomware_Encryptor",
		"Script_Data_Exfiltration_Stealer",
		"Script_C2_Exfiltration_Server",
		"Script_Download_And_Execute",
		"Script_Process_Hiding_Procfs",
		"Webshell_PHP_Generic_Backdoor",
		"Script_Webshell_Traits",
		"Heuristic_Suspicious_SUID_SGID",
		"Process_Memfd_Execution",
		"Users_Extra_UID0_Account",
		"Kernel_Hidden_LKM_Module",
		"IOC_Hash_SHA256",
		"Network_IOC_IP_Connection",
		"Persistence_Multi_Vector_Persistence",
		"Process_Hidden_PID",
		"Network_Wildcard_Listener_Unrecognized_Process",
		"Users_Shadow_Empty_Password",
		"Heuristic_World_Writable_In_Etc",
	} {
		meta, ok := report.LookupRuleMeta(name)
		if !ok {
			t.Errorf("rule %q not registered", name)
			continue
		}
		if meta.Title == "" || meta.Why == "" || len(meta.Remediation) == 0 {
			t.Errorf("rule %q has incomplete metadata: %+v", name, meta)
		}
	}
}

func TestRegisteredRuleCount(t *testing.T) {
	// The registry must have substantial coverage; exact count grows over time.
	if got := report.RegisteredRuleCount(); got < 50 {
		t.Errorf("expected >=100 registered rules, got %d", got)
	}
}

func TestRegisteredRuleNames_Unique(t *testing.T) {
	names := report.RegisteredRuleNames()
	seen := make(map[string]bool)
	sort.Strings(names)
	for _, n := range names {
		if seen[n] {
			t.Errorf("duplicate registered rule name: %s", n)
		}
		seen[n] = true
	}
}

func TestAllRegisteredRulesHaveEvidenceStrength(t *testing.T) {
	names := report.RegisteredRuleNames()
	if len(names) == 0 {
		t.Fatal("expected registered rules, got 0")
	}
	for _, n := range names {
		meta, ok := report.LookupRuleMeta(n)
		if !ok {
			t.Errorf("rule %q not found in registry", n)
			continue
		}
		if meta.EvidenceStrength == "" {
			t.Errorf("rule %q has empty EvidenceStrength", n)
		}
	}
}

func TestPopulateFindingDetails_UsesRegistry(t *testing.T) {
	// A registered rule must get its Title from the registry.
	f := report.NewFinding("process", report.SeverityAlert, "/proc/1337", "reason", "Process_Hidden_PID")
	if f.Title != "Hidden Process (Rootkit Evasion Indicator)" {
		t.Errorf("registry Title not applied: %q", f.Title)
	}
	if f.Why == "" || len(f.Remediation) == 0 {
		t.Error("registry Why/Remediation not applied")
	}
	if len(f.MITRE) == 0 {
		t.Error("registry MITRE not applied")
	}
	if f.Verdict != report.VerdictMalicious {
		t.Errorf("expected VerdictMalicious for ALERT, got %v", f.Verdict)
	}
	if f.ConfidenceRationale == "" {
		t.Error("expected non-empty ConfidenceRationale")
	}
	if f.EvidenceRecord == nil {
		t.Error("expected EvidenceRecord to be populated")
	}
}

func TestPopulateFindingDetails_RegistryDoesNotClobberDetectorSuppliedValues(t *testing.T) {
	f := report.NewFinding("filesystem", report.SeverityAlert, "/tmp/x", "custom reason", "Process_Hidden_PID")
	f.Why = "Detector-supplied specific why"
	f.Remediation = []string{"Detector-specific step"}
	report.PopulateFindingDetails(&f)
	if f.Why != "Detector-supplied specific why" && f.Why != "Detector-supplied custom why" {
		// Detector-supplied value must survive.
		if f.Why == "A process is accessible via direct /proc/<PID> stat but absent from the /proc directory listing, indicating procfs-level hiding typical of LKM rootkits." {
			t.Errorf("registry Why clobbered detector-supplied Why: %q", f.Why)
		}
	}
}

func TestPopulateFindingDetails_UnregisteredFallsBack(t *testing.T) {
	f := report.NewFinding("scanner", report.SeverityNotice, "/tmp/obj", "reason", "Unregistered_Custom_Rule_XYZ")
	if f.Confidence == "" {
		t.Error("unregistered rule must still get default confidence")
	}
	if len(f.Remediation) == 0 {
		t.Error("unregistered rule must still get default remediation")
	}
	if f.Why == "" {
		t.Error("unregistered rule must still get Why (reason fallback)")
	}
}
