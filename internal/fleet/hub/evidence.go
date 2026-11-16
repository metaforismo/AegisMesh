package hub

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
	"github.com/metaforismo/aegismesh/internal/storage"
)

// NodeEvidenceBytes prevents one enrolled node from filling the aggregate budget.
const NodeEvidenceBytes = 16 << 20

// TotalEvidenceBytes bounds forwarded segment bytes per tenant, including encryption overhead.
const TotalEvidenceBytes = 256 << 20

// EvidenceBytesPerMinute bounds each node's incoming encoded bytes per fixed minute.
const EvidenceBytesPerMinute = 16 << 20

// EvidenceEventsPerSecond is the per-node burst allowance per fixed second.
const EvidenceEventsPerSecond = protocol.MaxBatchEvents

// DedupEvents bounds each node's process-local idempotence window.
const DedupEvents = 4096

// EvidenceStore is the injected append/retention seam; runtime uses storage.Store.
type EvidenceStore interface {
	AppendEncoded([]byte) error
	Flush() error
	ApplyRetention(context.Context) ([]string, error)
	RetainBytes(int64) (int64, error)
	Close() error
}

// EvidenceOptions configures explicit reception, trusted storage and post-append indexing.
type EvidenceOptions struct {
	// Dir is assigned by Hub.New under the tenant state root; standalone receiver tests may inject it.
	Dir string
	// Store contains the hub's evidence encryption and retention policy.
	Store storage.Options
	// Factory injects storage construction; nil uses storage.New.
	Factory func(storage.Options) (EvidenceStore, error)
	// OnAppend receives validated envelopes after successful hub append.
	OnAppend func(string, event.Envelope)
}

type nodeEvidence struct {
	mu       sync.Mutex
	store    EvidenceStore
	failed   bool
	bytes    int64
	second   int64
	events   int
	minute   int64
	incoming int
	last     time.Time
	ids      map[string]bool
	ring     []string
	cursor   int
}

type evidenceReceiver struct {
	options EvidenceOptions
	mu      sync.Mutex
	nodes   map[string]*nodeEvidence
	total   atomic.Int64
}

func newReceiver(options *EvidenceOptions) (*evidenceReceiver, error) {
	if options == nil {
		return nil, nil
	}
	r := &evidenceReceiver{options: *options, nodes: map[string]*nodeEvidence{}}
	if r.options.Factory == nil {
		r.options.Factory = func(opts storage.Options) (EvidenceStore, error) { return storage.New(opts) }
	}
	if err := os.MkdirAll(options.Dir, 0700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(options.Dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !protocol.Hex(entry.Name(), 16) || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil, failure("corrupt_state")
		}
		// Inspect existing copies even with encryption enabled; no read identity is held.
		files, err := os.ReadDir(filepath.Join(options.Dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		n := &nodeEvidence{ids: map[string]bool{}}
		for _, file := range files {
			info, err := file.Info()
			if err != nil || !info.Mode().IsRegular() {
				return nil, failure("corrupt_state")
			}
			n.bytes += info.Size()
		}
		if n.bytes > NodeEvidenceBytes {
			return nil, failure("capacity")
		}
		r.nodes[entry.Name()] = n
		r.total.Add(n.bytes)
	}
	if r.total.Load() > TotalEvidenceBytes {
		return nil, failure("capacity")
	}
	return r, nil
}

func (r *evidenceReceiver) node(id string) *nodeEvidence {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.nodes[id]
	if n == nil {
		n = &nodeEvidence{ids: map[string]bool{}}
		r.nodes[id] = n
	}
	return n
}

func (r *evidenceReceiver) reserve(bytes int64) bool {
	for {
		old := r.total.Load()
		if old+bytes > TotalEvidenceBytes {
			return false
		}
		if r.total.CompareAndSwap(old, old+bytes) {
			return true
		}
	}
}

func (h *Hub) evidence(auth protocol.Authentication, batch protocol.EvidenceBatch, bodyBytes int) (ack protocol.EvidenceAck, result error) {
	ack = protocol.EvidenceAck{NodeID: auth.NodeID}
	// Registry authentication/replay is short and never spans evidence disk IO.
	h.mu.Lock()
	record := h.state.Nodes[auth.NodeID]
	var err error
	switch {
	case h.failed.Load():
		err = failure("unavailable")
	case record.Node.Status == "revoked":
		err = failure("revoked")
	case h.replayed(auth):
		err = failure("replay")
	case h.evidenceReceiver == nil:
		err = failure("evidence_disabled")
	}
	h.mu.Unlock()
	if err != nil {
		return ack, err
	}
	r := h.evidenceReceiver
	n := r.node(auth.NodeID)
	// Do not let concurrent submissions by one compromised identity occupy all handlers.
	if !n.mu.TryLock() {
		return ack, rateLimited(time.Second)
	}
	defer n.mu.Unlock()
	if n.failed {
		return ack, failure("unavailable")
	}
	now := h.now()
	if !n.last.IsZero() && now.Sub(n.last) < 5*time.Second {
		return ack, rateLimited(5*time.Second - now.Sub(n.last))
	}
	if n.second != now.Unix() {
		n.second, n.events = now.Unix(), 0
	}
	if n.minute != now.Unix()/60 {
		n.minute, n.incoming = now.Unix()/60, 0
	}
	if n.events+len(batch.Events) > EvidenceEventsPerSecond || n.incoming+bodyBytes > EvidenceBytesPerMinute {
		return ack, rateLimited(time.Minute)
	}
	h.mu.Lock()
	// Revocation may have raced validation; linearize acceptance before append.
	if h.state.Nodes[auth.NodeID].Node.Status == "revoked" {
		err = failure("revoked")
	} else {
		err = h.remember(auth)
	}
	h.mu.Unlock()
	if err != nil {
		return ack, err
	}
	n.last = now
	n.events += len(batch.Events)
	n.incoming += bodyBytes

	type candidate struct {
		raw      []byte
		envelope event.Envelope
	}
	candidates := make([]candidate, 0, len(batch.Events))
	seen := make(map[string]bool, len(batch.Events))
	encodedBytes := 0
	for _, raw := range batch.Events {
		envelope, err := protocol.DecodeEvidence(raw, now)
		if err != nil || r.options.Store.MaxFileBytes > 0 &&
			int64(len(raw)+1024) > r.options.Store.MaxFileBytes {
			ack.Invalid++
			h.evidenceEvents.Inc("invalid")
			continue
		}
		if n.ids[envelope.ID] || seen[envelope.ID] {
			ack.Duplicates++
			h.evidenceEvents.Inc("duplicate")
			continue
		}
		seen[envelope.ID] = true
		candidates = append(candidates, candidate{raw: raw, envelope: envelope})
		encodedBytes += len(raw)
	}
	if len(candidates) == 0 {
		h.recordEvidenceRange(auth.NodeID, batch)
		return ack, nil
	}
	if n.store == nil {
		if !r.reserve(4096) {
			return ack, rateLimited(time.Minute)
		}
		n.bytes += 4096
		opts := r.options.Store
		opts.Dir = filepath.Join(r.options.Dir, auth.NodeID)
		if opts.MaxFileBytes == 0 {
			opts.MaxFileBytes = 4 << 20
		}
		opts.MaxFileBytes = min(opts.MaxFileBytes, 4<<20)
		opts.MaxEventBytes = event.MaxStoredEnvelopeBytes
		n.store, err = r.options.Factory(opts)
		if err != nil {
			n.failed = true
			return ack, failure("unavailable")
		}
	}
	// Reserve a conservative bound before any append; reconcile actual disk usage after flush.
	allowance := int64(2*encodedBytes + 4096*len(candidates) + 4096)
	retained, err := n.store.RetainBytes(max(0, NodeEvidenceBytes-allowance))
	if err != nil {
		return ack, failure("unavailable")
	}
	r.total.Add(retained - n.bytes)
	n.bytes = retained
	if n.bytes+allowance > NodeEvidenceBytes || !r.reserve(allowance) {
		return ack, rateLimited(time.Minute)
	}
	defer func() {
		actual, flushErr := n.store.RetainBytes(NodeEvidenceBytes)
		if flushErr == nil {
			r.total.Add(actual - n.bytes - allowance)
			n.bytes = actual
		} else {
			// Keep the full reservation on unknown disk state; fail this node closed.
			n.bytes += allowance
			n.failed = true
			result = failure("unavailable")
		}
	}()

	for _, candidate := range candidates {
		raw, envelope := candidate.raw, candidate.envelope
		if err := n.store.AppendEncoded(raw); err != nil {
			return ack, failure("unavailable")
		}
		if len(n.ring) < DedupEvents {
			n.ring = append(n.ring, envelope.ID)
		} else {
			delete(n.ids, n.ring[n.cursor])
			n.ring[n.cursor] = envelope.ID
			n.cursor = (n.cursor + 1) % DedupEvents
		}
		n.ids[envelope.ID] = true
		ack.Accepted++
		h.evidenceEvents.Inc("accepted")
		if r.options.OnAppend != nil {
			r.options.OnAppend(auth.NodeID, envelope)
		}
	}
	if err := n.store.Flush(); err != nil {
		return ack, failure("unavailable")
	}
	if _, err := n.store.ApplyRetention(context.Background()); err != nil {
		return ack, failure("unavailable")
	}
	h.recordEvidenceRange(auth.NodeID, batch)
	return ack, nil
}

func (h *Hub) recordEvidenceRange(id string, batch protocol.EvidenceBatch) {
	h.mu.Lock()
	record := h.state.Nodes[id]
	if record.Node.Forwarding == nil {
		record.Node.Forwarding = &protocol.Forwarding{Enabled: true}
	}
	forwarding := *record.Node.Forwarding
	if record.StreamID != batch.StreamID {
		record.StreamID, record.ForwardSequence = batch.StreamID, 0
	}
	if batch.First > record.ForwardSequence && batch.First-record.ForwardSequence > 1 {
		gap := batch.First - record.ForwardSequence - 1
		forwarding.GapsTotal += min(gap, ^uint64(0)-forwarding.GapsTotal)
	}
	record.ForwardSequence = max(record.ForwardSequence, batch.Last)
	forwarding.LastForwardedAt = h.now().UTC().Format(time.RFC3339Nano)
	record.Node.Forwarding = &forwarding
	h.state.Nodes[id] = record
	h.dirty = true
	h.mu.Unlock()
}

func (r *evidenceReceiver) close() error {
	if r == nil {
		return nil
	}
	var result error
	for _, node := range r.nodes {
		if node.store != nil {
			result = errors.Join(result, node.store.Close())
		}
	}
	return result
}

// EvidenceEnabled reports the trusted reception opt-in without exposing storage paths.
func (h *Hub) EvidenceEnabled() bool { return h.evidenceReceiver != nil }
