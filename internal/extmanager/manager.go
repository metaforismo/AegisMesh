// Package extmanager supervises verified out-of-process observer extensions:
// bounded delivery queues, drop accounting, revocation on failure, and a
// deterministic bounded shutdown. Extensions are data-only sinks — they
// receive observation envelopes and must return one canonical event-linked
// acknowledgement that cannot influence decoy behavior, evidence, or policy
// (ADR-0006, ADR-0014).
package extmanager

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/ext"
	"github.com/metaforismo/aegismesh/internal/observe"
)

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

	mu        sync.RWMutex
	entries   []*entry
	started   bool
	stopped   bool
	wg        sync.WaitGroup
	force     chan struct{}
	forceOnce sync.Once
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
		force:     make(chan struct{}),
		m: metrics{
			delivered: meter.CounterVec("aegismesh_extension_delivered_total", "observations delivered to observer extensions", maxSeries),
			dropped:   meter.CounterVec("aegismesh_extension_dropped_total", "observations dropped (queue full, revoked, oversized)", maxSeries),
			errors:    meter.CounterVec("aegismesh_extension_errors_total", "observer delivery errors that caused revocation", maxSeries),
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
	if m.stopped {
		return fmt.Errorf("extension manager is stopped")
	}
	m.started = true

	hosts := make([]*ext.Host, 0, len(m.entries))
	for i, e := range m.entries {
		h, err := ext.Start(ctx, m.manifests[i])
		if err != nil {
			stopHosts(hosts)
			m.started = false // allow a later retry by the caller if desired
			return fmt.Errorf("start extension %q: %v", e.name, err)
		}
		hosts = append(hosts, h)
	}
	for i, e := range m.entries {
		e.host = hosts[i]
		m.wg.Add(1)
		go m.dispatch(e)
	}
	return nil
}

func (m *Manager) dispatch(e *entry) {
	defer m.wg.Done()
	for {
		var env event.Envelope
		select {
		case <-m.force:
			return
		case next, ok := <-e.ch:
			if !ok {
				return
			}
			env = next
		}
		if e.revoked {
			m.m.dropped.Inc(e.name)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(e.callMS)*time.Millisecond)
		err := e.host.Observe(ctx, observationOf(env))
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
			m.m.errors.Inc(e.name)
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
		m.forceOnce.Do(func() { close(m.force) })
	}
	hosts := make([]*ext.Host, 0, len(entries))
	for _, e := range entries {
		if e.host != nil {
			hosts = append(hosts, e.host)
		}
	}
	stopHosts(hosts)
	m.forceOnce.Do(func() { close(m.force) })
	m.wg.Wait()
}

func stopHosts(hosts []*ext.Host) {
	var wg sync.WaitGroup
	for _, host := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			host.Stop()
		}()
	}
	wg.Wait()
}

func observationOf(e event.Envelope) ext.Observation {
	return ext.Observation{
		EventID:        e.ID,
		Time:           e.Time,
		Classification: e.Classification,
		Sensor:         e.Sensor,
		Payload:        e.Observation,
	}
}
