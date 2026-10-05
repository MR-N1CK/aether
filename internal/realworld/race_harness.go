package realworld

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// RaceHarnessMetrics tracks the churn activity generated during a stress run.
type RaceHarnessMetrics struct {
	ProcessesSpawned atomic.Int64
	SocketsCycled    atomic.Int64
	FilesUnlinked    atomic.Int64
}

// RaceHarness generates high-frequency process, network, and filesystem churn to stress
// Aether's concurrent inspection sweeps against transient /proc entries and vanishing files.
type RaceHarness struct {
	tempDir string
	metrics RaceHarnessMetrics
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// NewRaceHarness constructs an initialized RaceHarness.
func NewRaceHarness(tempDir string) *RaceHarness {
	return &RaceHarness{
		tempDir: tempDir,
	}
}

// Start launches concurrent churn worker goroutines.
func (h *RaceHarness) Start(parentCtx context.Context) {
	ctx, cancel := context.WithCancel(parentCtx)
	h.cancel = cancel

	// 1. Process churn worker: spawn and quickly terminate short-lived helper processes
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				cmd := exec.CommandContext(ctx, "true")
				_ = cmd.Run()
				h.metrics.ProcessesSpawned.Add(1)
				time.Sleep(2 * time.Millisecond)
			}
		}
	}()

	// 2. Ephemeral socket churn worker: bind and close local TCP sockets rapidly
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err == nil {
					h.metrics.SocketsCycled.Add(1)
					time.Sleep(time.Millisecond)
					_ = ln.Close()
				}
				time.Sleep(time.Millisecond)
			}
		}
	}()

	// 3. Ephemeral file churn worker: create and delete files in temp directory
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		churnDir := filepath.Join(h.tempDir, "churn")
		_ = os.MkdirAll(churnDir, 0755)
		var counter int64

		for {
			select {
			case <-ctx.Done():
				return
			default:
				counter++
				fpath := filepath.Join(churnDir, fmt.Sprintf("tmp_%d.tmp", counter))
				if err := os.WriteFile(fpath, []byte("ephemeral data"), 0644); err == nil {
					time.Sleep(time.Millisecond)
					_ = os.Remove(fpath)
					h.metrics.FilesUnlinked.Add(1)
				}
				time.Sleep(time.Millisecond)
			}
		}
	}()
}

// Stop cleanly terminates all churn worker goroutines and waits for completion.
func (h *RaceHarness) Stop() {
	if h.cancel != nil {
		h.cancel()
	}
	h.wg.Wait()
}

// Metrics returns snapshot counts of churn operations executed.
func (h *RaceHarness) Metrics() (procs, sockets, files int64) {
	return h.metrics.ProcessesSpawned.Load(),
		h.metrics.SocketsCycled.Load(),
		h.metrics.FilesUnlinked.Load()
}
