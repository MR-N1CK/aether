package scanner

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestWorkerPoolTracker_LifecycleAndRecovery verifies:
// 1. Worker start and active worker tracking
// 2. Detection of stuck workers via checkTimeouts
// 3. Atomicity and idempotency of worker abandonment
// 4. Replacement worker spawning when feeding is active
// 5. Late return of abandoned worker does not double-decrement activeWorkers
// 6. Abandoned worker cap (8) prevents unbounded thread explosion
// 7. CloseFeeding prevents further replacement spawns during channel drain
// 8. Clean unblocking of Done() when all active workers complete
func TestWorkerPoolTracker_LifecycleAndRecovery(t *testing.T) {
	tracker := newWorkerPoolTracker()
	var nextID atomic.Int64
	nextID.Store(2) // Initial pool 0, 1, 2; next is 3

	// 1. Start initial workers
	if !tracker.startWorker(0) || !tracker.startWorker(1) || !tracker.startWorker(2) {
		t.Fatalf("failed to start initial workers")
	}
	if tracker.activeWorkers != 3 {
		t.Fatalf("expected 3 active workers, got %d", tracker.activeWorkers)
	}

	// Double start should fail
	if tracker.startWorker(0) {
		t.Errorf("expected duplicate startWorker(0) to return false")
	}

	// 2. Set active paths and simulate work
	tracker.setActive(0, "/fast/file1.txt")
	tracker.setActive(1, "/slow/pipe_or_fifo")
	tracker.setActive(2, "/fast/file2.txt")

	// Verify active paths
	paths := tracker.getActivePaths()
	if len(paths) != 3 {
		t.Fatalf("expected 3 active paths, got %d", len(paths))
	}

	// 3. Timeout check: with 1h timeout, nothing stuck
	if stuck := tracker.checkTimeouts(1 * time.Hour); len(stuck) != 0 {
		t.Errorf("expected 0 stuck workers with 1h timeout, got %d", len(stuck))
	}

	// With 0 timeout, all 3 active workers are returned
	stuck := tracker.checkTimeouts(0)
	if len(stuck) != 3 {
		t.Fatalf("expected 3 stuck workers with 0 timeout, got %d", len(stuck))
	}

	// 4. Abandon worker 1 (simulating watchdog timeout)
	newID, spawn, capExceeded, path, abandoned := tracker.abandonWorker(1, &nextID)
	if !abandoned {
		t.Fatalf("expected worker 1 to be abandoned successfully")
	}
	if path != "/slow/pipe_or_fifo" {
		t.Errorf("expected path /slow/pipe_or_fifo, got %s", path)
	}
	if !spawn {
		t.Errorf("expected spawn to be true")
	}
	if capExceeded {
		t.Errorf("capExceeded should be false on first abandonment")
	}
	if newID != 3 {
		t.Errorf("expected newID 3, got %d", newID)
	}
	// Active workers should still be 3 (3 - 1 + 1 replacement)
	if tracker.activeWorkers != 3 {
		t.Errorf("expected activeWorkers=3 after replacement, got %d", tracker.activeWorkers)
	}

	// Second abandonment on worker 1 must be rejected
	_, secondSpawn, _, _, secondAbandoned := tracker.abandonWorker(1, &nextID)
	if secondAbandoned || secondSpawn {
		t.Errorf("expected second abandonWorker on slot 1 to fail")
	}

	// 5. Late return: the abandoned worker 1 finally finishes its slow read
	tracker.clearActive(1)
	tracker.workerFinished(1) // Should be idempotent and NOT decrement activeWorkers
	if tracker.activeWorkers != 3 {
		t.Errorf("expected activeWorkers to remain 3 after abandoned worker finished, got %d", tracker.activeWorkers)
	}

	// Normal worker 0 finishes
	tracker.clearActive(0)
	tracker.workerFinished(0)
	if tracker.activeWorkers != 2 {
		t.Errorf("expected activeWorkers=2 after worker 0 finished, got %d", tracker.activeWorkers)
	}

	// 6. Test abandonment cap (max 8)
	// We currently have 1 abandoned worker. Let's abandon 7 more workers to hit cap of 8.
	for i := 4; i <= 10; i++ {
		slotID := int(nextID.Add(1))
		tracker.startWorker(slotID)
		tracker.setActive(slotID, "/stuck/file")
		nID, sp, capEx, _, ab := tracker.abandonWorker(slotID, &nextID)
		if !ab || !sp || capEx {
			t.Fatalf("expected worker %d abandonment to succeed (abandoned count %d)", slotID, tracker.abandoned)
		}
		_ = nID
	}
	if tracker.abandoned != 8 {
		t.Fatalf("expected exactly 8 abandoned workers, got %d", tracker.abandoned)
	}

	// 9th abandonment: exceeds cap (8) -> spawn must be false, capExceeded must be true
	ninthID := int(nextID.Add(1))
	tracker.startWorker(ninthID)
	tracker.setActive(ninthID, "/stuck/file9")
	_, sp9, capEx9, _, ab9 := tracker.abandonWorker(ninthID, &nextID)
	if !ab9 {
		t.Errorf("expected 9th abandonment to record abandoned status")
	}
	if sp9 {
		t.Errorf("expected spawn to be false when cap exceeded")
	}
	if !capEx9 {
		t.Errorf("expected capExceeded to be true for > 8 abandoned workers")
	}

	// 7. CloseFeeding: marks feedingDone and closes channel
	fileChan := make(chan string, 10)
	fileChan <- "remaining_file"
	tracker.CloseFeeding(fileChan)

	if !tracker.feedingDone {
		t.Errorf("expected feedingDone to be true after CloseFeeding")
	}

	// Channel should be closed
	select {
	case _, ok := <-fileChan:
		if !ok {
			t.Errorf("expected to read buffered item before closed state")
		}
	default:
	}

	// Abandonment during drain must NOT spawn any replacements
	drainWorkerID := 2
	_, drainSpawn, _, _, drainAb := tracker.abandonWorker(drainWorkerID, &nextID)
	if !drainAb {
		t.Errorf("expected drain worker abandonment to succeed")
	}
	if drainSpawn {
		t.Errorf("expected NO replacement spawned when feedingDone is true")
	}

	// Finish all remaining active workers
	tracker.mu.Lock()
	var remainingIDs []int
	for id, slot := range tracker.slots {
		if !slot.doneCalled.Load() {
			remainingIDs = append(remainingIDs, id)
		}
	}
	tracker.mu.Unlock()

	for _, id := range remainingIDs {
		tracker.workerFinished(id)
	}

	// 8. tracker.Done() must now be unblocked
	select {
	case <-tracker.Done():
		// Success!
	case <-time.After(1 * time.Second):
		t.Fatalf("tracker.Done() did not close after all workers finished (activeWorkers=%d)", tracker.activeWorkers)
	}

	if tracker.activeWorkers != 0 {
		t.Errorf("expected activeWorkers=0, got %d", tracker.activeWorkers)
	}
}

// TestWorkerPoolTracker_ConcurrentStress verifies zero race conditions and clean completion
// under intense concurrent worker finish, watchdog abandonment, and feeder closure.
func TestWorkerPoolTracker_ConcurrentStress(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		tracker := newWorkerPoolTracker()
		var nextID atomic.Int64
		numWorkers := 4
		nextID.Store(int64(numWorkers - 1))

		for i := 0; i < numWorkers; i++ {
			tracker.startWorker(i)
		}

		fileChan := make(chan string, 20)
		var feederWg sync.WaitGroup
		feederWg.Add(1)
		go func() {
			defer feederWg.Done()
			for i := 0; i < 20; i++ {
				fileChan <- "/test/path"
			}
			tracker.CloseFeeding(fileChan)
		}()

		var workersWg sync.WaitGroup
		var startWorkerFunc func(wid int)
		startWorkerFunc = func(wid int) {
			workersWg.Add(1)
			go func() {
				defer workersWg.Done()
				defer tracker.workerFinished(wid)

				tracker.setActive(wid, "/test/path")
				time.Sleep(100 * time.Microsecond)
				tracker.clearActive(wid)
			}()
		}

		for i := 0; i < numWorkers; i++ {
			startWorkerFunc(i)
		}

		// Watchdog goroutine
		stopWatchdog := make(chan struct{})
		go func() {
			ticker := time.NewTicker(50 * time.Microsecond)
			defer ticker.Stop()
			for {
				select {
				case <-stopWatchdog:
					return
				case <-ticker.C:
					stuck := tracker.checkTimeouts(0)
					for _, ws := range stuck {
						newID, spawn, _, _, _ := tracker.abandonWorker(ws.id, &nextID)
						if spawn {
							startWorkerFunc(newID)
						}
					}
				}
			}
		}()

		feederWg.Wait()
		select {
		case <-tracker.Done():
		case <-time.After(5 * time.Second):
			close(stopWatchdog)
			t.Fatalf("iter %d: tracker.Done() timed out", iter)
		}
		close(stopWatchdog)
		workersWg.Wait()
	}
}
