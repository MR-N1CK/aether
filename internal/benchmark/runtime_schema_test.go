package benchmark_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"aether/internal/benchmark"
)

func TestBenchmarkRuntimeFixtureSchemaCompliance(t *testing.T) {
	fixture := benchmark.BenchmarkRuntimeFixture{
		CaseID:            "SUSP-LISTEN-001",
		MockProcfsRelPath: "suspicious/03_unmapped_listeners/mock_proc",
		MockProcesses: []benchmark.MockProcessFixture{
			{
				PID:          1337,
				PPID:         1,
				Comm:         "python3",
				Exe:          "/usr/bin/python3",
				Cmdline:      []string{"python3", "dev_server.py"},
				Cwd:          "/home/developer/app",
				EUID:         1000,
				IsDeleted:    false,
				IsMemfd:      false,
				HasELFHeader: false,
				MntNs:        "mnt:[4026531840]",
			},
		},
		MockSockets: []benchmark.MockSocketFixture{
			{
				Protocol:   "TCP",
				LocalIP:    "0.0.0.0",
				LocalPort:  4444,
				RemoteIP:   "0.0.0.0",
				RemotePort: 0,
				State:      "LISTEN",
				Inode:      98765,
				OwningPID:  1337,
			},
		},
	}

	data, err := json.Marshal(fixture)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if raw["case_id"] != "SUSP-LISTEN-001" {
		t.Errorf("Expected case_id SUSP-LISTEN-001, got %v", raw["case_id"])
	}

	procs, ok := raw["mock_processes"].([]interface{})
	if !ok || len(procs) != 1 {
		t.Fatalf("Expected 1 mock process, got %v", raw["mock_processes"])
	}

	p0 := procs[0].(map[string]interface{})
	if p0["comm"] != "python3" || int(p0["pid"].(float64)) != 1337 {
		t.Errorf("Unexpected process contents: %v", p0)
	}

	sockets, ok := raw["mock_sockets"].([]interface{})
	if !ok || len(sockets) != 1 {
		t.Fatalf("Expected 1 mock socket, got %v", raw["mock_sockets"])
	}

	s0 := sockets[0].(map[string]interface{})
	if s0["protocol"] != "TCP" || int(s0["local_port"].(float64)) != 4444 {
		t.Errorf("Unexpected socket contents: %v", s0)
	}
}

func TestBenchmarkRuntimeSchemaFileExists(t *testing.T) {
	schemaPath := "../../specs/003-runtime-threat-assessment/contracts/benchmark-runtime-schema.json"
	absPath, err := filepath.Abs(schemaPath)
	if err != nil {
		t.Fatalf("Failed to resolve schema path: %v", err)
	}
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		t.Errorf("Schema file not found at %s", absPath)
	}
}
