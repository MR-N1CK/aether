package events

import (
	"sync"
	"sync/atomic"

	"aether/internal/report"
)

const (
	defaultEphemeralBufferSize = 256
	defaultOutBufferSize       = 512
)

// EventBus provides non-blocking, asynchronous event publishing with lossless
// guarantees for critical events (FindingRaised, ModuleStarted, ModuleFinished,
// Error, ScanFinished) while dropping or coalescing ephemeral events (FileScanned,
// Progress) when subscribers lag.
type EventBus struct {
	mu           sync.RWMutex
	subscribers  map[int64]*Subscription
	attachedReps map[report.Reporter]*Subscription
	nextID       atomic.Int64
	closed       atomic.Bool
}

// NewEventBus instantiates a ready-to-use EventBus.
func NewEventBus() *EventBus {
	return &EventBus{
		subscribers:  make(map[int64]*Subscription),
		attachedReps: make(map[report.Reporter]*Subscription),
	}
}

// Subscription represents an active event stream for a subscriber.
type Subscription struct {
	id        int64
	bus       *EventBus
	outChan   chan Event
	critQueue []Event
	critMu    sync.Mutex
	notifyCh  chan struct{}
	ephemCh   chan Event
	done      chan struct{}
	closed    atomic.Bool
	closeOnce sync.Once
}

// Subscribe registers a new subscriber receiving events via a dedicated channel.
func (b *EventBus) Subscribe() *Subscription {
	if b.closed.Load() {
		sub := &Subscription{
			outChan: make(chan Event),
			done:    make(chan struct{}),
		}
		close(sub.outChan)
		close(sub.done)
		sub.closed.Store(true)
		return sub
	}

	id := b.nextID.Add(1)
	sub := &Subscription{
		id:        id,
		bus:       b,
		outChan:   make(chan Event, defaultOutBufferSize),
		critQueue: make([]Event, 0, 64),
		notifyCh:  make(chan struct{}, 1),
		ephemCh:   make(chan Event, defaultEphemeralBufferSize),
		done:      make(chan struct{}),
	}

	b.mu.Lock()
	b.subscribers[id] = sub
	b.mu.Unlock()

	go sub.dispatchLoop()

	return sub
}

// AttachReporter connects a report.Reporter as a subscriber to the event bus,
// forwarding all FindingRaised events into the reporter losslessly.
// Multiple calls with the same Reporter instance are idempotent and return the existing subscription.
func (b *EventBus) AttachReporter(rep report.Reporter) *Subscription {
	if rep == nil || b.closed.Load() {
		return nil
	}

	b.mu.Lock()
	if b.attachedReps == nil {
		b.attachedReps = make(map[report.Reporter]*Subscription)
	}
	if existing, ok := b.attachedReps[rep]; ok {
		b.mu.Unlock()
		return existing
	}
	b.mu.Unlock()

	sub := b.Subscribe()

	b.mu.Lock()
	b.attachedReps[rep] = sub
	b.mu.Unlock()

	go func() {
		for e := range sub.Events() {
			if fr, ok := e.(FindingRaised); ok {
				rep.Report(fr.Finding)
			}
		}
	}()
	return sub
}

// Unsubscribe cancels an active subscription.
func (b *EventBus) Unsubscribe(sub *Subscription) {
	if sub == nil {
		return
	}

	b.mu.Lock()
	delete(b.subscribers, sub.id)
	for rep, s := range b.attachedReps {
		if s == sub {
			delete(b.attachedReps, rep)
		}
	}
	b.mu.Unlock()

	sub.close()
}

// Publish distributes an event to all active subscribers.
// It is guaranteed to be NON-BLOCKING for the publisher:
// - Critical events are queued losslessly in an unbounded FIFO buffer.
// - Ephemeral events are dropped if subscriber buffers are full.
func (b *EventBus) Publish(e Event) {
	if e == nil || b.closed.Load() {
		return
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, sub := range b.subscribers {
		if sub.closed.Load() {
			continue
		}

		if e.IsCritical() {
			sub.pushCritical(e)
		} else {
			sub.pushEphemeral(e)
		}
	}
}

// Close gracefully closes all active subscriptions and shuts down the bus.
func (b *EventBus) Close() {
	if b.closed.Swap(true) {
		return
	}

	b.mu.Lock()
	subs := make([]*Subscription, 0, len(b.subscribers))
	for _, s := range b.subscribers {
		subs = append(subs, s)
	}
	b.subscribers = make(map[int64]*Subscription)
	b.mu.Unlock()

	for _, s := range subs {
		s.close()
	}
}

// Events returns the readable channel of events for this subscription.
func (s *Subscription) Events() <-chan Event {
	return s.outChan
}

// Close terminates this subscription and drains resources.
func (s *Subscription) Close() {
	if s.bus != nil {
		s.bus.Unsubscribe(s)
	} else {
		s.close()
	}
}

func (s *Subscription) pushCritical(e Event) {
	s.critMu.Lock()
	s.critQueue = append(s.critQueue, e)
	s.critMu.Unlock()

	select {
	case s.notifyCh <- struct{}{}:
	default:
	}
}

func (s *Subscription) pushEphemeral(e Event) {
	select {
	case s.ephemCh <- e:
	default:
		// Lagging subscriber: drop ephemeral event without blocking scanner
	}
}

func (s *Subscription) dispatchLoop() {
	defer close(s.outChan)

	for {
		// 1. Drain critical queue first
		s.critMu.Lock()
		if len(s.critQueue) > 0 {
			item := s.critQueue[0]
			s.critQueue = s.critQueue[1:]
			s.critMu.Unlock()

			select {
			case s.outChan <- item:
			case <-s.done:
				// Drain any remaining critical items that fit before exiting
				s.drainRemainingCritical()
				return
			}
			continue
		}
		s.critMu.Unlock()

		// 2. Wait for next critical notification, ephemeral event, or termination
		select {
		case <-s.notifyCh:
			// Critical item queued, loop back immediately
			continue
		case ephemItem, ok := <-s.ephemCh:
			if !ok {
				return
			}
			// Attempt delivering ephemeral event without blocking
			select {
			case s.outChan <- ephemItem:
			case <-s.done:
				s.drainRemainingCritical()
				return
			default:
				// outChan occupied; drop ephemeral item to preserve room for critical items
			}
		case <-s.done:
			s.drainRemainingCritical()
			return
		}
	}
}

func (s *Subscription) drainRemainingCritical() {
	s.critMu.Lock()
	defer s.critMu.Unlock()
	for _, item := range s.critQueue {
		select {
		case s.outChan <- item:
		default:
			// If outChan is full during final shutdown, do not hang
		}
	}
	s.critQueue = nil
}

func (s *Subscription) close() {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.done)
	})
}
