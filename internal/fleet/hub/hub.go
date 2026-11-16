// Package hub persists experimental fleet inventory and verifies agent identity.
// It accepts data only: there is no dialer, agent control channel, or execution seam.
package hub

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metaforismo/aegismesh/internal/console/audit"
	"github.com/metaforismo/aegismesh/internal/console/stateio"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
	"github.com/metaforismo/aegismesh/internal/observe"
)

// MaxNodes is the hard per-tenant registry capacity, including revoked identities.
const MaxNodes = 1000

// MaxTokens bounds outstanding enrollment credentials per tenant.
const MaxTokens = 100

// MaxNoncesPerNode isolates each identity's replay budget, including enrollment retries.
const MaxNoncesPerNode = 64

// MaxNonces bounds the persisted replay cache across the whole registry.
const MaxNonces = MaxNodes * MaxNoncesPerNode

// FlushInterval bounds normal heartbeat snapshot frequency and crash loss.
const FlushInterval = 5 * time.Second

// Error reports a fixed safe protocol code, never untrusted input or secrets.
type Error struct {
	// Code is a fixed protocol category suitable for logs and API responses.
	Code       string
	retryAfter int
}

// Error returns the safe code for logs and API errors.
func (e *Error) Error() string {
	if e.Code == "corrupt_state" {
		return "fleet: corrupt_state; inspect registry.json and restore a known-good private snapshot"
	}
	return "fleet: " + e.Code
}

func rateLimited(remaining time.Duration) error {
	seconds := max(1, int((remaining+time.Second-1)/time.Second))
	return &Error{Code: "rate_limited", retryAfter: seconds}
}

func failure(code string) error {
	return &Error{Code: code}
}

// Code extracts the safe error code, hiding filesystem and transport details.
func Code(err error) string {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Code
	}
	return "unavailable"
}

// Options injects trusted state, clock, metrics and an optional additional audit sink.
type Options struct {
	partition string
	// Tenants is the validated process partition set; omitted means default.
	Tenants []string
	// TenantAudit mirrors machine events only into their owning tenant chain.
	TenantAudit func(tenant, action, target, outcome string) error
	// TenantAppend indexes received evidence only inside its immutable registry tenant.
	TenantAppend func(tenant, node string, envelope event.Envelope)
	// Evidence opts into forwarded evidence reception; nil keeps the boundary closed.
	Evidence *EvidenceOptions
	// StateDir is the trusted private snapshot directory.
	StateDir string
	// Now supplies liveness, expiry, abuse and flush decisions; nil uses time.Now.
	// It must support concurrent calls from handlers and the maintenance worker.
	Now func() time.Time
	// Meter receives fixed-cardinality request outcomes.
	Meter observe.Meter
	// Audit optionally mirrors machine audit events into the existing console audit chain.
	Audit func(action, target, outcome string) error
}

type registration struct {
	StreamID        string             `json:"stream_id,omitempty"`
	ForwardSequence uint64             `json:"forward_sequence,omitempty"`
	PublicKey       string             `json:"public_key"`
	IntervalSeconds int                `json:"interval_seconds"`
	Node            protocol.Node      `json:"node"`
	Heartbeat       protocol.Heartbeat `json:"heartbeat"`
}

type tokenRecord struct {
	Token
	Digest string `json:"digest"`
}

type snapshot struct {
	Version int                     `json:"version"`
	Nodes   map[string]registration `json:"nodes"`
	Tokens  map[string]tokenRecord  `json:"tokens"`
	Nonces  map[string]int64        `json:"nonces"`
}

// Hub serializes durable mutations and coalesces soft inventory/replay snapshots.
type Hub struct {
	enrollMu         sync.Mutex
	tenantID         string
	partitions       map[string]*Hub
	evidenceReceiver *evidenceReceiver
	evidenceEvents   observe.LabeledCounter
	mu               sync.Mutex
	root             *os.Root
	state            snapshot
	now              func() time.Time
	audit            *audit.Log
	additionalAudit  func(string, string, string) error
	requests         observe.LabeledCounter
	failed           atomic.Bool
	replay           map[string]map[string]int64
	lastEnrollment   map[string]time.Time
	dirty            bool
	lastFlush        time.Time
	stop             chan struct{}
	done             chan struct{}
	closeOnce        sync.Once
	closeErr         error
	limits           abuseLimits
}

func newSingle(opts Options) (*Hub, error) {
	root, err := stateio.Open(opts.StateDir)
	if err != nil {
		return nil, fmt.Errorf("fleet hub state: %w", err)
	}
	h := &Hub{
		root:            root,
		tenantID:        opts.partition,
		now:             opts.Now,
		additionalAudit: opts.Audit,
		state: snapshot{
			Version: 1,
			Nodes:   map[string]registration{},
			Tokens:  map[string]tokenRecord{},
			Nonces:  map[string]int64{},
		},
	}
	if h.now == nil {
		h.now = time.Now
	}
	meter := opts.Meter
	if meter == nil {
		meter = observe.NewRegistry()
	}
	h.evidenceEvents = meter.CounterVec("aegismesh_fleet_evidence_events_total", "Fixed evidence event outcomes", 3)
	h.requests = meter.CounterVec("aegismesh_fleet_hub_requests_total", "Fleet outcomes by fixed code", 13)
	body, err := stateio.Read(root, "registry.json", stateio.MaxStateBytes)
	if err == nil {
		if decodeState(body, &h.state) != nil || !h.validState() {
			root.Close()
			return nil, failure("corrupt_state")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		root.Close()
		return nil, fmt.Errorf("fleet hub: read registry: %w", err)
	}
	h.audit, err = audit.New(filepath.Join(opts.StateDir, "audit"))
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("fleet hub audit: %w", err)
	}
	h.replay = make(map[string]map[string]int64)
	for key, expiry := range h.state.Nonces {
		if expiry < h.now().Unix() {
			delete(h.state.Nonces, key)
			h.dirty = true
			continue
		}
		id, nonce := key[:32], key[33:]
		if h.replay[id] == nil {
			h.replay[id] = make(map[string]int64)
		}
		h.replay[id][nonce] = expiry
	}
	h.evidenceReceiver, err = newReceiver(opts.Evidence)
	if err != nil {
		_ = h.audit.Close()
		_ = root.Close()
		return nil, err
	}
	h.lastEnrollment = make(map[string]time.Time)
	h.lastFlush = h.now()
	h.limits.init(h.now())
	h.stop, h.done = make(chan struct{}), make(chan struct{})
	go h.runMaintenance()
	return h, nil
}

// Close releases state handles after the listener has stopped serving.
func (h *Hub) Close() error {
	h.closeOnce.Do(func() {
		for _, child := range h.partitions {
			if child != h {
				_ = child.Close()
			}
		}
		close(h.stop)
		<-h.done
		h.flushRejections(true)
		h.mu.Lock()
		defer h.mu.Unlock()
		var flushErr error
		if h.dirty {
			flushErr = h.save()
		}
		var failedErr error
		if h.failed.Load() {
			failedErr = failure("unavailable")
		}
		h.failed.Store(true)
		h.closeErr = errors.Join(flushErr, failedErr, h.evidenceReceiver.close(), h.audit.Close(), h.root.Close())
	})
	return h.closeErr
}

func (h *Hub) record(action, target, outcome string) error {
	if h.audit.Append(audit.Record{
		Actor:   "fleet",
		Role:    "agent",
		Action:  action,
		Target:  target,
		Outcome: outcome,
	}) != nil {
		h.failed.Store(true)
		return failure("unavailable")
	}
	if h.additionalAudit != nil && h.additionalAudit(action, target, outcome) != nil {
		h.failed.Store(true)
		return failure("unavailable")
	}
	return nil
}

func (h *Hub) save() error {
	if h.failed.Load() {
		return failure("unavailable")
	}
	body, err := encodeState(h.state)
	if err != nil || stateio.Atomic(h.root, "registry.json", body) != nil {
		// A failed fsync may follow a successful rename. Refuse further work until restart/inspection.
		h.failed.Store(true)
		return failure("unavailable")
	}
	h.dirty = false
	return nil
}

func (h *Hub) prune() {
	now := h.now().Unix()
	for id, token := range h.state.Tokens {
		if token.ExpiresAt <= now {
			delete(h.state.Tokens, id)
		}
	}
}
