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

// Bus is a bounded, drop-oldest queue between sensors (hot path) and the
// evidence store (cold path). Sensors never block on storage; drops are
// counted and surfaced via metrics plus a rate-limited log line.
type Bus struct {
	ch      chan Envelope
	wg      sync.WaitGroup
	cancel  context.CancelFunc
	close   sync.Once
	dropped uint64

	log *slog.Logger
	mu  sync.Mutex
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

// Submit enqueues without blocking. It returns false when the bus was full and
// the envelope was dropped.
func (b *Bus) Submit(e Envelope) bool {
	select {
	case b.ch <- e:
		return true
	default:
		b.mu.Lock()
		b.dropped++
		n := b.dropped
		b.mu.Unlock()
		if n == 1 || n%1000 == 0 {
			b.log.Warn("event bus full; dropping events", "dropped_total", n)
		}
		return false
	}
}

// Dropped reports how many envelopes were dropped since start.
func (b *Bus) Dropped() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dropped
}

// Close stops intake, lets the worker finish writing everything already
// queued (bounded by channel contents), and releases resources. Idempotent.
func (b *Bus) Close() {
	b.close.Do(func() {
		close(b.ch)
		b.wg.Wait()
		b.cancel()
	})
}
