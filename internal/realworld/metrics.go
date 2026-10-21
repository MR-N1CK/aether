package realworld

import (
	"strings"
	"sync"
	"time"

	"aether/internal/events"
)

// Standard subsystem names used in duration profiling.
const (
	SubsystemFilesystem     = "filesystem"
	SubsystemFilesystemWalk = "filesystem_walk"
	SubsystemHashing        = "hashing"
	SubsystemHeuristics     = "heuristics"
	SubsystemYARA           = "yara"
	SubsystemProcess        = "process"
	SubsystemNetwork        = "network"
	SubsystemPersistence    = "persistence"
	SubsystemUsers          = "users"
	SubsystemKernel         = "kernel"
	SubsystemCorrelation    = "correlation"
	SubsystemReporting      = "reporting"
)

// SubsystemMetricsCollector records and calculates granular duration telemetry across
// all inspection subsystems.
type SubsystemMetricsCollector struct {
	mu           sync.Mutex
	durations    map[string]time.Duration
	activeTimers map[string]time.Time
}

// NewSubsystemMetricsCollector creates an empty metrics collector.
func NewSubsystemMetricsCollector() *SubsystemMetricsCollector {
	return &SubsystemMetricsCollector{
		durations:    make(map[string]time.Duration),
		activeTimers: make(map[string]time.Time),
	}
}

// StartTimer begins timing a subsystem and returns a stop function.
func (c *SubsystemMetricsCollector) StartTimer(subsystem string) func() {
	c.mu.Lock()
	c.activeTimers[subsystem] = time.Now()
	c.mu.Unlock()

	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		start, ok := c.activeTimers[subsystem]
		if ok {
			elapsed := time.Since(start)
			c.durations[subsystem] += elapsed
			delete(c.activeTimers, subsystem)
		}
	}
}

// RecordDuration adds elapsed duration to a named subsystem.
func (c *SubsystemMetricsCollector) RecordDuration(subsystem string, d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.durations[subsystem] += d
}

// GetDuration returns the recorded duration for a subsystem.
func (c *SubsystemMetricsCollector) GetDuration(subsystem string) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.durations[subsystem]
}

// AttachBus registers event bus listeners to automatically record module durations.
// It returns an events.Subscription that can be unsubscribed when done.
func (c *SubsystemMetricsCollector) AttachBus(bus *events.EventBus) *events.Subscription {
	if bus == nil {
		return nil
	}

	sub := bus.Subscribe()
	go func() {
		for ev := range sub.Events() {
			switch e := ev.(type) {
			case events.ModuleFinished:
				c.RecordDuration(strings.ToLower(e.ModuleName), e.Duration)
			case events.ScanFinished:
				if e.ProcessCoverage != nil && e.ProcessCoverage.DurationBreakdown.Total > 0 {
					bd := e.ProcessCoverage.DurationBreakdown
					c.RecordDuration(SubsystemProcess, bd.Total)
					if bd.Hashing > 0 {
						c.RecordDuration(SubsystemHashing, bd.Hashing)
					}
				}
			}
		}
	}()
	return sub
}

// CalculateBreakdown compiles recorded timings into a structured DurationBreakdown.
// If filesystem sub-phases were not measured individually, it cleanly attributes the
// filesystem module duration across walk, hashing, heuristics, and YARA.
func (c *SubsystemMetricsCollector) CalculateBreakdown(total time.Duration) DurationBreakdown {
	c.mu.Lock()
	defer c.mu.Unlock()

	bd := DurationBreakdown{
		FilesystemWalk: c.durations[SubsystemFilesystemWalk],
		Hashing:        c.durations[SubsystemHashing],
		Heuristics:     c.durations[SubsystemHeuristics],
		YARA:           c.durations[SubsystemYARA],
		Process:        c.durations[SubsystemProcess],
		Network:        c.durations[SubsystemNetwork],
		Persistence:    c.durations[SubsystemPersistence],
		Users:          c.durations[SubsystemUsers],
		Kernel:         c.durations[SubsystemKernel],
		Correlation:    c.durations[SubsystemCorrelation],
		Reporting:      c.durations[SubsystemReporting],
		Total:          total,
	}

	fsTotal := c.durations[SubsystemFilesystem]
	if fsTotal > 0 && bd.FilesystemWalk == 0 && bd.Hashing == 0 && bd.Heuristics == 0 {
		// Sub-phases were not measured individually; flag as estimated breakdown:
		// 30% directory traversal & safeopen stat
		// 45% cryptographic hashing (SHA-256 / MD5)
		// 15% pure-Go AST / regex heuristics
		// 10% YARA compiled rule evaluation
		bd.Estimated = true
		bd.FilesystemWalk = time.Duration(float64(fsTotal) * 0.30)
		bd.Hashing = time.Duration(float64(fsTotal) * 0.45)
		bd.Heuristics = time.Duration(float64(fsTotal) * 0.15)
		bd.YARA = time.Duration(float64(fsTotal) * 0.10)
	}

	if bd.Total == 0 {
		bd.Total = bd.FilesystemWalk + bd.Hashing + bd.Heuristics + bd.YARA +
			bd.Process + bd.Network + bd.Persistence + bd.Users + bd.Kernel +
			bd.Correlation + bd.Reporting
	}

	return bd
}

// CalculateThroughput returns files scanned per second given files count and duration.
func (c *SubsystemMetricsCollector) CalculateThroughput(filesScanned int64, duration time.Duration) float64 {
	if duration <= 0 || filesScanned <= 0 {
		return 0
	}
	return float64(filesScanned) / duration.Seconds()
}

// FromScanFinished constructs a DurationBreakdown from an events.ScanFinished event.
func FromScanFinished(sf events.ScanFinished, correlationDur time.Duration) DurationBreakdown {
	c := NewSubsystemMetricsCollector()
	if sf.ProcessCoverage != nil && sf.ProcessCoverage.DurationBreakdown.Total > 0 {
		c.RecordDuration(SubsystemProcess, sf.ProcessCoverage.DurationBreakdown.Total)
		if sf.ProcessCoverage.DurationBreakdown.Hashing > 0 {
			c.RecordDuration(SubsystemHashing, sf.ProcessCoverage.DurationBreakdown.Hashing)
		}
	}
	if correlationDur > 0 {
		c.RecordDuration(SubsystemCorrelation, correlationDur)
	}
	return c.CalculateBreakdown(sf.TotalDuration)
}
