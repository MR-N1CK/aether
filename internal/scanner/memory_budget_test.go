package scanner

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestMemoryBudget_BasicAcquireRelease(t *testing.T) {
	mb := NewMemoryBudget(1024 * 1024) // 1MB budget

	ctx := context.Background()
	buf, capSize, err := mb.Acquire(ctx, 1000)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	if len(buf) != 1000 {
		t.Errorf("expected buf len 1000, got %d", len(buf))
	}
	if capSize != 64*1024 {
		t.Errorf("expected capSize 64KB, got %d", capSize)
	}
	if mb.Used() != 64*1024 {
		t.Errorf("expected used 64KB, got %d", mb.Used())
	}

	mb.Release(buf, capSize)
	if mb.Used() != 0 {
		t.Errorf("expected used 0 after release, got %d", mb.Used())
	}
}

func TestMemoryBudget_WaitAndUnblock(t *testing.T) {
	// Budget is 128KB (two 64KB allocations max)
	mb := NewMemoryBudget(128 * 1024)

	ctx := context.Background()
	buf1, cap1, err := mb.Acquire(ctx, 10000)
	if err != nil {
		t.Fatalf("Acquire 1 failed: %v", err)
	}
	buf2, cap2, err := mb.Acquire(ctx, 10000)
	if err != nil {
		t.Fatalf("Acquire 2 failed: %v", err)
	}

	// Budget is now fully consumed (64KB + 64KB = 128KB)
	if mb.Used() != 128*1024 {
		t.Fatalf("expected used 128KB, got %d", mb.Used())
	}

	acquiredChan := make(chan bool)
	go func() {
		buf3, cap3, err := mb.Acquire(ctx, 10000)
		if err != nil {
			return
		}
		mb.Release(buf3, cap3)
		acquiredChan <- true
	}()

	// Verify the third goroutine is blocked
	select {
	case <-acquiredChan:
		t.Fatalf("goroutine 3 should have blocked on exhausted budget")
	case <-time.After(50 * time.Millisecond):
		// Expected to be blocked
	}

	// Release buf1 to unblock goroutine 3
	mb.Release(buf1, cap1)

	select {
	case <-acquiredChan:
		// Successfully unblocked
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("goroutine 3 failed to unblock after release")
	}

	mb.Release(buf2, cap2)
	if mb.Used() != 0 {
		t.Errorf("expected used 0, got %d", mb.Used())
	}
}

func TestMemoryBudget_ContextCancellation(t *testing.T) {
	mb := NewMemoryBudget(64 * 1024)

	ctx, cancel := context.WithCancel(context.Background())
	buf1, cap1, err := mb.Acquire(ctx, 10000)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	defer mb.Release(buf1, cap1)

	// Second acquire with timeout
	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()

	_, _, err2 := mb.Acquire(ctx2, 10000)
	if err2 == nil {
		t.Fatalf("expected timeout error on second acquire")
	}
	if err2 != context.DeadlineExceeded {
		t.Errorf("expected DeadlineExceeded, got %v", err2)
	}

	// Manual cancellation test
	ctx3, cancel3 := context.WithCancel(context.Background())
	cancel3()
	_, _, err3 := mb.Acquire(ctx3, 10000)
	if err3 != context.Canceled {
		t.Errorf("expected Canceled, got %v", err3)
	}
	cancel()
}

func TestMemoryBudget_ExceedsTotalBudget(t *testing.T) {
	mb := NewMemoryBudget(64 * 1024) // 64KB budget

	ctx := context.Background()
	_, _, err := mb.Acquire(ctx, 1024*1024) // 1MB file
	if err == nil {
		t.Fatalf("expected error for file exceeding total memory budget")
	}
}

func TestMemoryBudget_ConcurrentStress(t *testing.T) {
	mb := NewMemoryBudget(1 * 1024 * 1024) // 1MB budget

	var wg sync.WaitGroup
	ctx := context.Background()

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				buf, capSize, err := mb.Acquire(ctx, int64((id+1)*1000))
				if err != nil {
					t.Errorf("concurrent acquire failed: %v", err)
					return
				}
				time.Sleep(1 * time.Millisecond)
				mb.Release(buf, capSize)
			}
		}(i)
	}

	wg.Wait()
	if mb.Used() != 0 {
		t.Errorf("expected used 0 after stress test, got %d", mb.Used())
	}
}
