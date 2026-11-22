package runtime

import (
	"context"
	"sync"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

// evidenceSink keeps evidence authoritative while offering every envelope to
// optional best-effort consumers (observer extensions, webhook stream). Both
// offers never block and their drops are counted on their own metrics, so the
// store path can neither be slowed nor failed by them.
type evidenceSink struct {
	primary event.Sink
	mgr     interface{ Deliver(event.Envelope) }    // may be nil
	hook    interface{ Offer(event.Envelope) bool } // may be nil
	corr    interface{ observe(event.Envelope) }    // may be nil
}

func (s evidenceSink) Append(ctx context.Context, e event.Envelope) error {
	safe := e
	safe.AuthAttempts = nil
	if err := s.primary.Append(ctx, safe); err != nil {
		return err
	}
	if s.mgr != nil {
		s.mgr.Deliver(safe)
	}
	if s.hook != nil {
		_ = s.hook.Offer(safe)
	}
	if s.corr != nil {
		s.corr.observe(e)
	}
	return nil
}

// Both bus observations and directly persisted correlation signals share this
// append-only tap. Signals never enter the bus or its outbound fan-out.
type indexedSink struct {
	mu      sync.Mutex
	primary event.Sink
	index   *evidenceindex.Index
}

// Append updates the disposable index only after the authoritative evidence append succeeds.
func (s *indexedSink) Append(ctx context.Context, envelope event.Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.primary.Append(ctx, envelope); err != nil {
		return err
	}

	s.index.Add(envelope)
	return nil
}

type fleetSink struct {
	primary event.Sink
	system  *System
}

func (s *fleetSink) Append(ctx context.Context, envelope event.Envelope) error {
	if err := s.primary.Append(ctx, envelope); err != nil {
		s.system.storageFailed.Store(true)
		return err
	}
	switch string(envelope.Classification) {
	case "interaction":
		s.system.fleetCounts.interaction.Add(1)
	case "canary_invocation":
		s.system.fleetCounts.canary.Add(1)
	case "correlation_signal":
		s.system.fleetCounts.correlation.Add(1)
	}
	if s.system.fleetAgent != nil {
		s.system.fleetAgent.Enqueue(envelope)
	}
	return nil
}
