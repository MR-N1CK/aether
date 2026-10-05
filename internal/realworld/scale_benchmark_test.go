package realworld

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"aether/internal/events"
)

func TestReadCurrentRSS(t *testing.T) {
	rss, err := ReadCurrentRSS()
	if err != nil {
		t.Fatalf("unexpected error reading RSS: %v", err)
	}
	if rss <= 0 {
		t.Errorf("expected RSS > 0, got %d", rss)
	}
}

func TestReadMemoryStats(t *testing.T) {
	stats := ReadMemoryStats()
	if stats.RSSBytes <= 0 {
		t.Errorf("expected RSSBytes > 0, got %d", stats.RSSBytes)
	}
	if stats.RSSMB <= 0 {
		t.Errorf("expected RSSMB > 0, got %f", stats.RSSMB)
	}
	if stats.SysBytes <= 0 {
		t.Errorf("expected SysBytes > 0, got %d", stats.SysBytes)
	}
}

func TestMemoryTracker(t *testing.T) {
	tracker := NewMemoryTracker(5 * time.Millisecond)
	tracker.Start()

	// Allocate some memory to ensure tracker detects memory activity
	data := make([][]byte, 10)
	for i := range data {
		data[i] = make([]byte, 1024*1024) // 1MB each
	}

	time.Sleep(20 * time.Millisecond)
	peak := tracker.Stop()

	if peak.RSSBytes <= 0 {
		t.Errorf("expected peak RSSBytes > 0, got %d", peak.RSSBytes)
	}
	if tracker.PeakRSSMB() <= 0 {
		t.Errorf("expected PeakRSSMB > 0, got %f", tracker.PeakRSSMB())
	}
	if tracker.Baseline().RSSBytes <= 0 {
		t.Errorf("expected Baseline RSSBytes > 0, got %d", tracker.Baseline().RSSBytes)
	}
}

func TestGenerateScaleHierarchy(t *testing.T) {
	tmpDir := t.TempDir()
	res, err := GenerateScaleHierarchy(tmpDir, 500)
	if err != nil {
		t.Fatalf("failed to generate scale hierarchy: %v", err)
	}

	if res.FileCount < 500 {
		t.Errorf("expected at least 500 files, got %d", res.FileCount)
	}
	if res.DirCount <= 0 {
		t.Errorf("expected DirCount > 0, got %d", res.DirCount)
	}
	if res.TotalBytes <= 0 {
		t.Errorf("expected TotalBytes > 0, got %d", res.TotalBytes)
	}

	// Verify some files exist on disk
	var diskCount int
	err = filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			diskCount++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}
	if diskCount != res.FileCount {
		t.Errorf("expected disk count %d, got %d", res.FileCount, diskCount)
	}
}

func TestSubsystemMetricsCollector(t *testing.T) {
	c := NewSubsystemMetricsCollector()

	stopWalk := c.StartTimer(SubsystemFilesystemWalk)
	time.Sleep(10 * time.Millisecond)
	stopWalk()

	c.RecordDuration(SubsystemHashing, 25*time.Millisecond)
	c.RecordDuration(SubsystemProcess, 15*time.Millisecond)
	c.RecordDuration(SubsystemCorrelation, 5*time.Millisecond)

	bd := c.CalculateBreakdown(100 * time.Millisecond)

	if bd.FilesystemWalk < 5*time.Millisecond {
		t.Errorf("expected FilesystemWalk >= 5ms, got %v", bd.FilesystemWalk)
	}
	if bd.Hashing != 25*time.Millisecond {
		t.Errorf("expected Hashing 25ms, got %v", bd.Hashing)
	}
	if bd.Process != 15*time.Millisecond {
		t.Errorf("expected Process 15ms, got %v", bd.Process)
	}
	if bd.Correlation != 5*time.Millisecond {
		t.Errorf("expected Correlation 5ms, got %v", bd.Correlation)
	}
	if bd.Total != 100*time.Millisecond {
		t.Errorf("expected Total 100ms, got %v", bd.Total)
	}

	throughput := c.CalculateThroughput(5000, 2*time.Second)
	if throughput != 2500.0 {
		t.Errorf("expected throughput 2500.0, got %f", throughput)
	}
}

func TestSubsystemMetricsCollector_EventBus(t *testing.T) {
	bus := events.NewEventBus()
	c := NewSubsystemMetricsCollector()
	sub := c.AttachBus(bus)
	defer bus.Unsubscribe(sub)

	bus.Publish(events.ModuleFinished{
		ModuleName: "filesystem",
		Duration:   50 * time.Millisecond,
	})
	bus.Publish(events.ModuleFinished{
		ModuleName: "process",
		Duration:   20 * time.Millisecond,
	})
	bus.Publish(events.ModuleFinished{
		ModuleName: "network",
		Duration:   10 * time.Millisecond,
	})

	time.Sleep(20 * time.Millisecond)

	bd := c.CalculateBreakdown(100 * time.Millisecond)

	if bd.Process != 20*time.Millisecond {
		t.Errorf("expected Process 20ms, got %v", bd.Process)
	}
	if bd.Network != 10*time.Millisecond {
		t.Errorf("expected Network 10ms, got %v", bd.Network)
	}
	// Filesystem decomposed
	if bd.FilesystemWalk == 0 || bd.Hashing == 0 || bd.Heuristics == 0 {
		t.Errorf("expected decomposed filesystem components, got walk=%v, hash=%v, heur=%v",
			bd.FilesystemWalk, bd.Hashing, bd.Heuristics)
	}
}
