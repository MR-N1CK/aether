package report_test

import (
	"testing"

	"aether/internal/report"
)

// mockPkgDB implements pkgdb.PackageDB for testing
type mockPkgDB struct {
	owners map[string]string
}

func (m *mockPkgDB) Owner(path string) (string, bool) {
	if m.owners == nil {
		return "", false
	}
	owner, ok := m.owners[path]
	return owner, ok
}

func (m *mockPkgDB) IsAvailable() bool  { return true }
func (m *mockPkgDB) StatusNote() string { return "mock db" }
func (m *mockPkgDB) VerifyDigest(path string, actualMD5 string) (bool, string, bool) {
	return true, "", false
}

func TestDetermineVerdict_Matrix(t *testing.T) {
	pkgDB := &mockPkgDB{
		owners: map[string]string{
			"/usr/lib/python3/dist-packages/elasticsearch.dist-info/METADATA": "python3-elasticsearch",
			"/usr/lib/python3/dist-packages/twisted/test/test_fdset.py":       "python3-twisted",
			"/usr/sbin/nginx": "nginx",
			"/usr/bin/curl":   "curl",
		},
	}

	tests := []struct {
		name               string
		path               string
		ruleName           string
		reason             string
		isExec             bool
		isDoc              bool
		isTestFixture      bool
		corroboration      []string
		expectedVerdict    report.Verdict
		expectedSeverity   report.Severity
		expectedConfidence report.Confidence
		expectedPkgStatus  string
		expectedStrength   report.EvidenceStrength
		expectedProfile    string
	}{
		{
			name:               "Direct malware on unowned path",
			path:               "/tmp/rev.sh",
			ruleName:           "Script_Reverse_Shell_Interactive",
			reason:             "Interactive reverse shell command detected",
			isExec:             true,
			expectedVerdict:    report.VerdictMalicious,
			expectedSeverity:   report.SeverityAlert,
			expectedConfidence: report.ConfidenceHigh,
			expectedPkgStatus:  "unowned",
			expectedStrength:   report.StrengthDirect,
			expectedProfile:    "standard",
		},
		{
			name:               "Direct malware on package file (compromised/trojaned)",
			path:               "/usr/sbin/nginx",
			ruleName:           "Script_Reverse_Shell_Interactive",
			reason:             "Interactive reverse shell command detected",
			isExec:             true,
			expectedVerdict:    report.VerdictMalicious,
			expectedSeverity:   report.SeverityAlert,
			expectedConfidence: report.ConfidenceHigh,
			expectedPkgStatus:  "modified_package",
			expectedStrength:   report.StrengthDirect,
			expectedProfile:    "standard",
		},
		{
			name:               "Doc metadata with dropper pattern (.dist-info/METADATA)",
			path:               "/usr/lib/python3/dist-packages/elasticsearch.dist-info/METADATA",
			ruleName:           "Linux_Dropper_Remote_Pipe_Shell_Execution",
			reason:             "Remote pipe execution command detected",
			isExec:             false,
			expectedVerdict:    report.VerdictSafe,
			expectedSeverity:   report.SeverityNotice,
			expectedConfidence: report.ConfidenceLow,
			expectedPkgStatus:  "verified_package",
			expectedStrength:   report.StrengthContextual,
			expectedProfile:    "doc_metadata",
		},
		{
			name:               "Package test fixture with mock server",
			path:               "/usr/lib/python3/dist-packages/twisted/test/test_fdset.py",
			ruleName:           "Linux_Malware_Data_Exfiltration_Server",
			reason:             "Network server listener detected",
			isExec:             false,
			expectedVerdict:    report.VerdictSafe,
			expectedSeverity:   report.SeverityNotice,
			expectedConfidence: report.ConfidenceLow,
			expectedPkgStatus:  "verified_package",
			expectedStrength:   report.StrengthContextual,
			expectedProfile:    "package_test",
		},
		{
			name:               "Dropper script with persistence corroboration",
			path:               "/tmp/drop.sh",
			ruleName:           "Script_Download_And_Execute",
			reason:             "curl | sh pipe detected",
			isExec:             true,
			corroboration:      []string{"persistence:/etc/cron.d/payload"},
			expectedVerdict:    report.VerdictMalicious,
			expectedSeverity:   report.SeverityAlert,
			expectedConfidence: report.ConfidenceHigh,
			expectedPkgStatus:  "unowned",
			expectedStrength:   report.StrengthCorroborated,
			expectedProfile:    "standard",
		},
		{
			name:               "Uncorroborated dropper script",
			path:               "/usr/local/bin/installer.sh",
			ruleName:           "Script_Download_And_Execute",
			reason:             "curl | sh pipe detected",
			isExec:             true,
			expectedVerdict:    report.VerdictSuspicious,
			expectedSeverity:   report.SeverityWarning,
			expectedConfidence: report.ConfidenceMedium,
			expectedPkgStatus:  "unowned",
			expectedStrength:   report.StrengthContextual,
			expectedProfile:    "standard",
		},
		{
			name:               "Deleted binary of packaged app (post apt upgrade)",
			path:               "/usr/sbin/nginx",
			ruleName:           "Process_Deleted_Binary",
			reason:             "Process running from deleted executable",
			isExec:             true,
			expectedVerdict:    report.VerdictSuspicious,
			expectedSeverity:   report.SeverityNotice,
			expectedConfidence: report.ConfidenceLow,
			expectedPkgStatus:  "verified_package",
			expectedStrength:   report.StrengthContextual,
			expectedProfile:    "standard",
		},
		{
			name:               "Deleted binary in tmp with active socket corroboration",
			path:               "/tmp/.x11-unix/payload (deleted)",
			ruleName:           "Process_Deleted_Binary",
			reason:             "Process running from deleted executable",
			isExec:             true,
			corroboration:      []string{"active_socket:0.0.0.0:4444"},
			expectedVerdict:    report.VerdictMalicious,
			expectedSeverity:   report.SeverityAlert,
			expectedConfidence: report.ConfidenceHigh,
			expectedPkgStatus:  "unowned",
			expectedStrength:   report.StrengthCorroborated,
			expectedProfile:    "standard",
		},
		{
			name:               "Memory execution with spawned shell corroboration",
			path:               "/memfd:sh (deleted)",
			ruleName:           "Process_Memfd_Execution",
			reason:             "Anonymous memory descriptor execution",
			isExec:             true,
			corroboration:      []string{"spawned_shell:/bin/bash"},
			expectedVerdict:    report.VerdictMalicious,
			expectedSeverity:   report.SeverityAlert,
			expectedConfidence: report.ConfidenceHigh,
			expectedPkgStatus:  "unowned",
			expectedStrength:   report.StrengthCorroborated,
			expectedProfile:    "standard",
		},
		{
			name:               "Permission Denied / Incomplete observation",
			path:               "/etc/shadow",
			ruleName:           "Permission_Denied",
			reason:             "open /etc/shadow: permission denied",
			isExec:             false,
			expectedVerdict:    report.VerdictUnknown,
			expectedSeverity:   report.SeverityInfo,
			expectedConfidence: report.ConfidenceLow,
			expectedPkgStatus:  "unowned",
			expectedStrength:   report.StrengthIncomplete,
			expectedProfile:    "standard",
		},
		{
			name:               "Build Tree non-executable artifact",
			path:               "/home/user/project/target/debug/build/helper",
			ruleName:           "File_ELF_In_Temp_Or_Dev",
			reason:             "ELF binary found in workspace",
			isExec:             false,
			expectedVerdict:    report.VerdictSafe,
			expectedSeverity:   report.SeverityNotice,
			expectedConfidence: report.ConfidenceLow,
			expectedPkgStatus:  "unowned",
			expectedStrength:   report.StrengthContextual,
			expectedProfile:    "build_tree",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := report.NewFinding("scanner", report.SeverityWarning, tt.path, tt.reason, tt.ruleName)
			if tt.expectedProfile == "build_tree" {
				// simulate build tree profile
				f.EvidenceRecord = &report.EvidenceRecord{
					ContextProfile: "build_tree",
				}
			}

			verdict := report.DetermineVerdict(&f, pkgDB, tt.isExec, tt.isDoc, tt.isTestFixture, tt.corroboration)

			if verdict != tt.expectedVerdict {
				t.Errorf("Verdict = %v, want %v", verdict, tt.expectedVerdict)
			}
			if f.Severity != tt.expectedSeverity {
				t.Errorf("Severity = %v, want %v", f.Severity, tt.expectedSeverity)
			}
			if f.Confidence != tt.expectedConfidence {
				t.Errorf("Confidence = %v, want %v", f.Confidence, tt.expectedConfidence)
			}
			if f.EvidenceRecord == nil {
				t.Fatal("EvidenceRecord is nil")
			}
			if f.EvidenceRecord.PackageStatus != tt.expectedPkgStatus {
				t.Errorf("PackageStatus = %q, want %q", f.EvidenceRecord.PackageStatus, tt.expectedPkgStatus)
			}
			if f.EvidenceRecord.EvidenceStrength != tt.expectedStrength {
				t.Errorf("EvidenceStrength = %v, want %v", f.EvidenceRecord.EvidenceStrength, tt.expectedStrength)
			}
			if f.EvidenceRecord.ContextProfile != tt.expectedProfile {
				t.Errorf("ContextProfile = %q, want %q", f.EvidenceRecord.ContextProfile, tt.expectedProfile)
			}
			if f.ConfidenceRationale == "" {
				t.Error("ConfidenceRationale is empty")
			}
		})
	}
}

// TestVendorAppTreeDemotion locks the legitimate-software false-positive
// fixes from the live triage: string-level signatures inside third-party
// vendor trees (/opt apps, node_modules, Electron resources) demote to
// SUSPICIOUS while hostile paths and cryptographic IOC matches keep full
// MALICIOUS strength.
func TestVendorAppTreeDemotion(t *testing.T) {
	newFinding := func(rule, path string, exec bool) report.Finding {
		mode := uint32(0o644)
		if exec {
			mode = 0o755
		}
		f := report.NewFinding("filesystem", report.SeverityAlert, path, "matched reverse shell one-liner", rule)
		f.Metadata = map[string]interface{}{}
		_ = mode
		return f
	}

	cases := []struct {
		name     string
		rule     string
		path     string
		exec     bool
		ioc      bool
		expected report.Verdict
	}{
		{"electron app js", "Script_Netcat_Reverse_Shell", "/opt/antigravity-ide/resources/app/out/jetskiAgent/main.js", false, false, report.VerdictSuspicious},
		{"node_modules bundle", "Script_Netcat_Reverse_Shell", "/opt/app/resources/app/node_modules/mermaid/dist/index.js", false, false, report.VerdictSuspicious},
		{"vendor elf string family", "Linux_Botnet_XorDDoS_ELF", "/opt/ide/IDE-binary", true, false, report.VerdictSuspicious},
		{"corroborated in vendor tree", "ELF_AntiAnalysis_Corrupted_Header", "/opt/android-studio/jbr/lib/server/libjvm.so", true, false, report.VerdictSuspicious},
		{"hostile path stays malicious", "Script_Netcat_Reverse_Shell", "/tmp/.cache/nc-clone.sh", true, false, report.VerdictMalicious},
		{"home dropped script stays malicious", "Script_Netcat_Reverse_Shell", "/home/dev/.config/rev.sh", true, false, report.VerdictMalicious},
		{"hash IOC in vendor tree stays malicious", "Script_Netcat_Reverse_Shell", "/opt/app/resources/payload.bin", true, true, report.VerdictMalicious},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFinding(tc.rule, tc.path, tc.exec)
			if tc.ioc {
				f.Metadata["is_ioc_match"] = true
			}
			verdict := report.DetermineVerdict(&f, nil, tc.exec, false, false, nil)
			if verdict != tc.expected {
				t.Errorf("expected %v, got %v (rationale: %s)", tc.expected, verdict, f.ConfidenceRationale)
			}
			if tc.expected == report.VerdictMalicious && f.Severity != report.SeverityAlert {
				t.Errorf("expected ALERT severity for malicious, got %v", f.Severity)
			}
			if tc.expected == report.VerdictSuspicious && f.Severity != report.SeverityWarning {
				t.Errorf("expected WARNING severity for demoted vendor finding, got %v", f.Severity)
			}
		})
	}
}

func TestClassifyContextProfile_VendorAndConf(t *testing.T) {
	cases := []struct {
		path     string
		exec     bool
		expected string
	}{
		{"/opt/anything/resources/app/x.js", false, "vendor_app_tree"},
		{"/opt/vendor-binary", true, "vendor_app_tree"},
		{"/srv/app/node_modules/pkg/index.js", false, "vendor_app_tree"},
		{"/usr/share/doc/pkg/examples/nc-test.txt", false, "vendor_app_tree"},
		{"/etc/netsniff-ng/oui.conf", false, "historical_artifact"},
		{"/etc/ld.so.preload", false, "standard"},
		{"/tmp/payload.conf", false, "standard"},
	}
	for _, tc := range cases {
		got := report.ClassifyContextProfile(tc.path, tc.exec, false)
		if got != tc.expected {
			t.Errorf("ClassifyContextProfile(%q, exec=%v) = %q, want %q", tc.path, tc.exec, got, tc.expected)
		}
	}
}
