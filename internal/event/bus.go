package event

import (
	"context"
	"log/slog"
	"sync"
)

// Sink consumes envelopes durably. Implemented by the storage package.
type Sink interface {
	Append(ctx context.Context, e Envelope) error
}

// Bus is a bounded, drop-on-full queue between sensors (hot path) and the
// evidence store (cold path). Sensors never block on storage; drops are
// counted and surfaced via metrics plus a rate-limited log line.
type Bus struct {
	ch        chan Envelope
	wg        sync.WaitGroup
	cancel    context.CancelFunc
	closeOnce sync.Once
	dropped   uint64

	log       *slog.Logger
	lifecycle sync.RWMutex
	closed    bool
	dropMu    sync.Mutex
}

// NewBus starts the bus with the given capacity and sink.
func NewBus(capacity int, sink Sink, log *slog.Logger) *Bus {
	if capacity < 1 {
		capacity = 1
	}
	if log == nil {
		log = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &Bus{
		ch:     make(chan Envelope, capacity),
		cancel: cancel,
		log:    log,
	}
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		for env := range b.ch {
			if err := sink.Append(ctx, env); err != nil && ctx.Err() == nil {
				log.Error("evidence write failed", "event_id", env.ID, "err", err)
			}
		}
	}()
	return b
}

// Submit enqueues without blocking. It returns false when the bus is full or
// closed.
func (b *Bus) Submit(e Envelope) bool {
	b.lifecycle.RLock()
	if b.closed {
		b.lifecycle.RUnlock()
		return false
	}
	select {
	case b.ch <- e:
		b.lifecycle.RUnlock()
		return true
	default:
		b.lifecycle.RUnlock()
		b.dropMu.Lock()
		b.dropped++
		n := b.dropped
		b.dropMu.Unlock()
		if n == 1 || n%1000 == 0 {
			b.log.Warn("event bus full; dropping events", "dropped_total", n)
		}
		return false
	}
}

// Dropped reports how many envelopes were dropped since start.
func (b *Bus) Dropped() uint64 {
	b.dropMu.Lock()
	defer b.dropMu.Unlock()
	return b.dropped
}

// Close stops intake, lets the worker finish writing everything already
// queued (bounded by channel contents), and releases resources. Idempotent.
func (b *Bus) Close() {
	b.closeOnce.Do(func() {
		b.lifecycle.Lock()
		b.closed = true
		close(b.ch)
		b.lifecycle.Unlock()
		b.wg.Wait()
		b.cancel()
	})
}
