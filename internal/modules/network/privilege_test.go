package network_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"aether/internal/config"
	"aether/internal/modules/network"
	"aether/internal/report"
)

func TestNetworkNonRootUnmappedSockets(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	procNet := filepath.Join(proc, "net")
	_ = os.MkdirAll(procNet, 0755)

	// Sockets without matching /proc/<pid>/fd entries (simulating non-root unable to read other users' fd)
	tcpContent := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1 0000000083791369 100 0 0 10 0                     
   1: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22222 1 0000000083791369 100 0 0 10 0                     
`
	_ = os.WriteFile(filepath.Join(procNet, "tcp"), []byte(tcpContent), 0644)

	cov := network.NetworkCoverage{}
	sockets, err := network.ParseAllSockets(proc, make(map[uint64]*network.ProcessSocketOwner), nil)
	if err != nil {
		t.Fatalf("unexpected error parsing sockets: %v", err)
	}

	// Run detections with isRoot = false
	findings := network.EvaluateNetworkDetections(context.Background(), sockets, false, config.NewDefaultConfig(), nil, &cov, nil)

	if cov.UnmappedSocketsNonRoot != 2 {
		t.Errorf("expected 2 unmapped sockets recorded in coverage, got %d", cov.UnmappedSocketsNonRoot)
	}

	// Must not emit standalone findings for unmapped listeners as non-root
	for _, f := range findings {
		if f.Severity == report.SeverityAlert || f.Severity == report.SeverityWarning {
			t.Errorf("unmapped sockets as non-root must not trigger warning/alert: %s", f.RuleName)
		}
	}
}
