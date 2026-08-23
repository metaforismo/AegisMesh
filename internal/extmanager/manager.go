// Package extmanager supervises verified out-of-process observer extensions:
// bounded delivery queues, drop accounting, revocation on failure, and a
// deterministic bounded shutdown. Extensions are data-only sinks — they
// receive observation envelopes and their replies carry acks/errors that can
// never influence decoy behavior, evidence, or policy (ADR-0006).
package extmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/ext"
	"github.com/metaforismo/aegismesh/internal/observe"
)

// maxObservationBytes bounds the per-delivery wire payload. Envelopes are
// already size-capped upstream; this is an independent defense so a single
// oversized observation can never wedge a slow extension pipe.
const maxObservationBytes = 128 << 10

// observeMethod is the only method the supervisor ever calls. The allowlist
// is the capability boundary: no extension input influences AegisMesh.
const observeMethod = "observe"

type metrics struct {
	delivered observe.LabeledCounter
	dropped   observe.LabeledCounter
	errors    observe.LabeledCounter
	revoked   observe.LabeledCounter
}

type entry struct {
	name    string
	callMS  int
	ch      chan event.Envelope
	host    *ext.Host
	revoked bool
}

// Manager owns the configured observer extensions. Construct with New.
// Deliver is safe for concurrent use while Start/Stop run on the lifecycle
// path.
type Manager struct {
	log       *slog.Logger
	flush     time.Duration
	manifests []*ext.Manifest
	m         metrics

	mu      sync.RWMutex
	entries []*entry
	started bool
	stopped bool
	wg      sync.WaitGroup
}

// New builds a manager for the given verified manifests. queueSize bounds
// each per-extension delivery queue; flush bounds the shutdown drain window.
func New(manifests []*ext.Manifest, meter observe.Meter, log *slog.Logger, queueSize int, flush time.Duration) *Manager {
	if log == nil {
		log = slog.Default()
	}
	if queueSize < 1 {
		queueSize = 1
	}
	if flush <= 0 {
		flush = 2 * time.Second
	}
	maxSeries := len(manifests) + 1 // + reserved overflow series
	m := &Manager{
		log:       log,
		flush:     flush,
		manifests: manifests,
		m: metrics{
			delivered: meter.CounterVec("aegismesh_extension_delivered_total", "observations delivered to observer extensions", maxSeries),
			dropped:   meter.CounterVec("aegismesh_extension_dropped_total", "observations dropped (queue full, revoked, oversized)", maxSeries),
			errors:    meter.CounterVec("aegismesh_extension_errors_total", "delivery errors before revocation", maxSeries),
			revoked:   meter.CounterVec("aegismesh_extension_revoked_total", "extensions revoked after a protocol violation or crash", maxSeries),
		},
	}
	for _, mf := range manifests {
		m.entries = append(m.entries, &entry{
			name:   mf.Name,
			callMS: mf.Transport.CallTimeoutMS,
			ch:     make(chan event.Envelope, queueSize),
		})
	}
	return m
}

// Start spawns every extension subprocess and performs its handshake.
// Partial failure tears all started processes down before returning, so the
// system either runs with the full configured set or not at all.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return fmt.Errorf("extension manager already started")
	}
	m.started = true

	var started []*entry
	for i, e := range m.entries {
		h, err := ext.Start(ctx, m.manifests[i], func(format string, args ...any) {
			m.log.Warn("extension host: "+fmt.Sprintf(format, args...), "extension", e.name)
		})
		if err != nil {
			for _, s := range started {
				s.host.Stop()
			}
			m.started = false // allow a later retry by the caller if desired
			return fmt.Errorf("start extension %q: %v", e.name, err)
		}
		e.host = h
		started = append(started, e)
		m.wg.Add(1)
		go m.dispatch(e)
	}
	return nil
}

func (m *Manager) dispatch(e *entry) {
	defer m.wg.Done()
	for env := range e.ch {
		raw, err := json.Marshal(observationOf(env))
		if err != nil || len(raw) > maxObservationBytes {
			m.m.errors.Inc(e.name)
			continue
		}
		if e.revoked {
			m.m.dropped.Inc(e.name)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(e.callMS)*time.Millisecond)
		_, err = e.host.Call(ctx, observeMethod, raw)
		cancel()
		switch {
		case err == nil:
			m.m.delivered.Inc(e.name)
		default:
			// Any violation — timeout, crash, bad frame, error frame — revokes
			// the extension for the process lifetime. Deterministic, no restart
			// storms; evidence flow is unaffected because delivery is
			// best-effort by design.
			e.revoked = true
			m.m.revoked.Inc(e.name)
			m.log.Warn("observer extension revoked", "extension", e.name)
		}
	}
}

// Deliver offers one envelope to every healthy extension without blocking.
// Full queues drop (counted); sensors and the evidence bus are never slowed.
func (m *Manager) Deliver(e event.Envelope) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.stopped {
		return
	}
	for _, en := range m.entries {
		if en.host == nil { // not started (Start failed mid-way)
			continue
		}
		select {
		case en.ch <- e:
		default:
			m.m.dropped.Inc(en.name)
		}
	}
}

// Stop stops intake, waits up to the configured flush window for queued
// observations to drain, then shuts each host down cleanly. Idempotent.
func (m *Manager) Stop() {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return
	}
	m.stopped = true
	entries := append([]*entry(nil), m.entries...)
	for _, e := range entries {
		if e.ch != nil && e.host != nil {
			close(e.ch)
		}
	}
	m.mu.Unlock()

	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(m.flush):
		// Flush window exceeded: dispatchers stop with the process teardown.
	}

	for _, e := range entries {
		if e.host != nil {
			e.host.Stop()
		}
	}
}

type observation struct {
	EventID        string          `json:"event_id"`
	Time           time.Time       `json:"time"`
	Classification string          `json:"classification"`
	Sensor         event.SensorRef `json:"sensor"`
	Payload        json.RawMessage `json:"payload,omitempty"`
}

func observationOf(e event.Envelope) observation {
	return observation{
		EventID:        e.ID,
		Time:           e.Time,
		Classification: e.Classification,
		Sensor:         e.Sensor,
		Payload:        e.Observation,
	}
}
