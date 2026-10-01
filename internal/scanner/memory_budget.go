package scanner

import (
	"context"
	"fmt"
	"sync"
)

var sizeClasses = []int64{
	64 * 1024,        // 64 KB
	256 * 1024,       // 256 KB
	1 * 1024 * 1024,  // 1 MB
	4 * 1024 * 1024,  // 4 MB
	20 * 1024 * 1024, // 20 MB
}

// MemoryBudget governs concurrent buffer allocations to ensure total memory
// consumption does not exceed the configured limit.
type MemoryBudget struct {
	maxBytes  int64
	usedBytes int64
	mu        sync.Mutex
	pools     map[int64]*sync.Pool
	waitChan  chan struct{}
}

// NewMemoryBudget initializes a thread-safe buffer manager with a global memory limit.
func NewMemoryBudget(maxBytes int64) *MemoryBudget {
	if maxBytes <= 0 {
		maxBytes = 256 * 1024 * 1024
	}

	mb := &MemoryBudget{
		maxBytes: maxBytes,
		pools:    make(map[int64]*sync.Pool),
		waitChan: make(chan struct{}, 1),
	}

	for _, sc := range sizeClasses {
		capSize := sc
		mb.pools[capSize] = &sync.Pool{
			New: func() any {
				b := make([]byte, capSize)
				return &b
			},
		}
	}

	return mb
}

// SizeClassFor determines the smallest size-class capacity capable of holding fileSize bytes.
func (mb *MemoryBudget) SizeClassFor(fileSize int64) int64 {
	for _, sc := range sizeClasses {
		if fileSize <= sc {
			return sc
		}
	}
	return fileSize
}

// Acquire reserves memory from the budget and returns a sized buffer charged by its capacity.
// It blocks if the budget would be exceeded and honors context cancellation.
func (mb *MemoryBudget) Acquire(ctx context.Context, fileSize int64) ([]byte, int64, error) {
	if fileSize < 0 {
		return nil, 0, fmt.Errorf("invalid negative file size: %d", fileSize)
	}

	capSize := mb.SizeClassFor(fileSize)
	if capSize > mb.maxBytes {
		return nil, 0, fmt.Errorf("requested buffer size %d exceeds total memory budget %d", capSize, mb.maxBytes)
	}

	for {
		mb.mu.Lock()
		if mb.usedBytes+capSize <= mb.maxBytes {
			mb.usedBytes += capSize
			mb.mu.Unlock()

			// Retrieve pooled buffer
			var buf []byte
			if pool, exists := mb.pools[capSize]; exists {
				pBuf := pool.Get().(*[]byte)
				buf = (*pBuf)[:fileSize]
			} else {
				buf = make([]byte, fileSize, capSize)
			}
			return buf, capSize, nil
		}

		// Budget exceeded: wait on channel or context cancellation
		mb.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-mb.waitChan:
			// Woken up by a release; retry acquisition loop
		}
	}
}

// Release returns the buffer to the pool and restores capacity to the global budget.
func (mb *MemoryBudget) Release(buf []byte, capSize int64) {
	if capSize <= 0 {
		return
	}

	if pool, exists := mb.pools[capSize]; exists {
		if cap(buf) >= int(capSize) {
			b := buf[:capSize]
			pool.Put(&b)
		}
	}

	mb.mu.Lock()
	mb.usedBytes -= capSize
	if mb.usedBytes < 0 {
		mb.usedBytes = 0
	}
	mb.mu.Unlock()

	// Notify waiting workers non-blockingly
	select {
	case mb.waitChan <- struct{}{}:
	default:
	}
}

// Used returns current memory in flight.
func (mb *MemoryBudget) Used() int64 {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	return mb.usedBytes
}

// Max returns the configured maximum budget in bytes.
func (mb *MemoryBudget) Max() int64 {
	return mb.maxBytes
}
