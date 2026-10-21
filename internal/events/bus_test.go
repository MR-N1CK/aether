package events_test

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"aether/internal/events"
	"aether/internal/report"
)

// Test100kLosslessFindingsUnderLoad verifies that 100k findings are all delivered
// to the Reporter without dropping a single event, even with a deliberately slow
// secondary UI subscriber and multiple concurrent publishers.
func Test100kLosslessFindingsUnderLoad(t *testing.T) {
	bus := events.NewEventBus()
	defer bus.Close()

	// 1. Fast subscriber: simulated Reporter
	reporterSub := bus.Subscribe()
	defer reporterSub.Close()

	// 2. Deliberately slow subscriber: simulated UI reader with latency
	slowSub := bus.Subscribe()
	defer slowSub.Close()

	var slowReceived atomic.Int64
	slowDone := make(chan struct{})
	go func() {
		defer close(slowDone)
		// Simulates a slow UI reading in chunks with artificial delay
		for range slowSub.Events() {
			slowReceived.Add(1)
			// Small sleep on every 500 items to simulate slow frame rendering
			if slowReceived.Load()%500 == 0 {
				time.Sleep(1 * time.Millisecond)
			}
		}
	}()

	const totalFindings = 100_000
	const numPublishers = 10
	findingsPerPub := totalFindings / numPublishers

	// Start consuming findings on the fast subscriber (Reporter)
	var reporterCount atomic.Int64
	reporterDone := make(chan struct{})
	go func() {
		defer close(reporterDone)
		for e := range reporterSub.Events() {
			if e.Type() == events.TypeFindingRaised {
				if reporterCount.Add(1) == totalFindings {
					return
				}
			}
		}
	}()

	// Also publish a flood of ephemeral events concurrently to test non-interference
	var pubWg sync.WaitGroup
	pubWg.Add(numPublishers)

	start := time.Now()
	for p := 0; p < numPublishers; p++ {
		go func(pubID int) {
			defer pubWg.Done()
			for i := 0; i < findingsPerPub; i++ {
				f := report.NewFinding(
					"test-mod",
					report.SeverityAlert,
					fmt.Sprintf("/path/test_%d_%d", pubID, i),
					"benchmark finding",
					"TEST_RULE",
				)
				bus.Publish(events.FindingRaised{
					Time:    time.Now(),
					Finding: f,
				})

				// Interleave ephemeral events
				if i%10 == 0 {
					bus.Publish(events.FileScanned{
						Time: time.Now(),
						Path: fmt.Sprintf("/path/test_%d_%d", pubID, i),
						Size: 1024,
					})
				}
			}
		}(p)
	}

	pubWg.Wait()
	publishDuration := time.Since(start)
	t.Logf("Published %d findings across %d goroutines in %v", totalFindings, numPublishers, publishDuration)

	// Wait for reporter to finish receiving all 100k findings with a timeout
	select {
	case <-reporterDone:
		t.Logf("Reporter received all %d findings successfully", totalFindings)
	case <-time.After(15 * time.Second):
		t.Fatalf("Timeout waiting for reporter: received %d out of %d findings", reporterCount.Load(), totalFindings)
	}

	if reporterCount.Load() != totalFindings {
		t.Errorf("Expected %d findings in reporter, got %d", totalFindings, reporterCount.Load())
	}
}

func TestEphemeralEventsCanDropWithoutBlocking(t *testing.T) {
	bus := events.NewEventBus()
	defer bus.Close()

	// Subscriber that does not read anything
	sub := bus.Subscribe()
	defer sub.Close()

	// Publish thousands of ephemeral events rapidly
	done := make(chan struct{})
	go func() {
		for i := 0; i < 50_000; i++ {
			bus.Publish(events.FileScanned{
				Time: time.Now(),
				Path: fmt.Sprintf("/tmp/ephem_%d", i),
				Size: int64(i),
			})
		}
		close(done)
	}()

	select {
	case <-done:
		// Succeeded in publishing without blocking on unread subscriber
	case <-time.After(2 * time.Second):
		t.Fatal("Publisher blocked on lagging subscriber during ephemeral events")
	}
}

func TestComputeVerdict(t *testing.T) {
	if v, _ := events.ComputeVerdict(nil, 0, 0, 0, 0); v != events.VerdictClean {
		t.Errorf("expected CLEAN, got %s", v)
	}
	if v, reason := events.ComputeVerdict(nil, 0, 0, 1, 0); v != events.VerdictClean || reason != "CLEAN, 1 notices to review" {
		t.Errorf("expected CLEAN, 1 notices to review, got %s (%s)", v, reason)
	}
	if v, reason := events.ComputeVerdict(nil, 0, 0, 10, 0); v != events.VerdictClean || reason != "CLEAN, 10 notices to review" {
		t.Errorf("expected CLEAN, 10 notices to review, got %s (%s)", v, reason)
	}
	// With notices threshold enabled
	if v, _ := events.ComputeVerdict(nil, 0, 0, 3, 3); v != events.VerdictSuspicious {
		t.Errorf("expected SUSPICIOUS when threshold 3 reached, got %s", v)
	}
	if v, _ := events.ComputeVerdict(nil, 0, 1, 0, 0); v != events.VerdictSuspicious {
		t.Errorf("expected SUSPICIOUS for 1 warning, got %s", v)
	}

	// Alert without high confidence -> capped at SUSPICIOUS
	weakAlert := report.NewFinding("test", report.SeverityAlert, "/path", "weak alert", "Test_Alert")
	if v, reason := events.ComputeVerdict([]report.Finding{weakAlert}, 1, 0, 0, 0); v != events.VerdictSuspicious {
		t.Errorf("expected SUSPICIOUS for alert without high confidence, got %s (reason: %s)", v, reason)
	}

	// Alert with high confidence -> COMPROMISED
	hcFinding := report.NewFinding("test", report.SeverityAlert, "/path", "reverse shell", "Persistence_Reverse_Shell_Primitive")
	hcFinding.Metadata["high_confidence"] = true
	if v, reason := events.ComputeVerdict([]report.Finding{hcFinding}, 1, 0, 0, 0); v != events.VerdictCompromised {
		t.Errorf("expected COMPROMISED for high-confidence alert, got %s (reason: %s)", v, reason)
	}

	// Alert with structured EvidenceStrength = StrengthDirect but arbitrary rule name
	structuredFinding := report.NewFinding("test", report.SeverityAlert, "/path", "arbitrary threat", "Arbitrary_Threat_XYZ")
	structuredFinding.EvidenceStrength = report.StrengthDirect
	if v, reason := events.ComputeVerdict([]report.Finding{structuredFinding}, 1, 0, 0, 0); v != events.VerdictCompromised {
		t.Errorf("expected COMPROMISED for structured StrengthDirect alert regardless of rule name, got %s (reason: %s)", v, reason)
	}
}

func TestCoverageStats_DenominatorAndPercentage(t *testing.T) {
	cov := events.CoverageStats{
		FilesScanned:      4000,
		SkippedPermission: 500,
		SkippedOversize:   500,
	}

	if cov.TotalSkipped() != 1000 {
		t.Fatalf("expected TotalSkipped 1000, got %d", cov.TotalSkipped())
	}
	if cov.TotalEligible() != 5000 {
		t.Fatalf("expected TotalEligible 5000, got %d", cov.TotalEligible())
	}
	if pct := cov.CoveragePercentage(); pct != 80.0 {
		t.Fatalf("expected CoveragePercentage 80.0%%, got %.2f%%", pct)
	}

	emptyCov := events.CoverageStats{}
	if pct := emptyCov.CoveragePercentage(); pct != 100.0 {
		t.Fatalf("expected 100.0%% for zero-file empty coverage, got %.2f%%", pct)
	}
}
