// Package correlate derives bounded temporal signals from observation
// streams — deterministic, local-only, and evidence-safe.
//
// Design invariants:
//   - Signals are derived observations with provenance (source event IDs);
//     they are never incidents and never attribution.
//   - Memory is bounded from day one: per-source event rings are capped,
//     the source table evicts oldest-first past MaxSources, and window
//     pruning drops stale events on every evaluation.
//   - Rule math is purely event-time based, so replaying the same input
//     sequence yields the same signals (deterministic under test/replay).
package correlate

import (
	"fmt"
	"time"
)

// RuleID identifies a correlation rule. Stable across releases; config and
// evidence reference these strings verbatim.
type RuleID string

const (
	// RuleRepeatedInjection fires when a single source accumulates enough
	// prompt-injection findings inside one window.
	RuleRepeatedInjection RuleID = "COR-001"
	// RuleProtocolHopping fires when a source touches several sensor kinds
	// (http/tcp/mcp) within one window.
	RuleProtocolHopping RuleID = "COR-002"
	// RuleToolProbing fires when a source invokes many distinct canary tools
	// within one window.
	RuleToolProbing RuleID = "COR-003"
	// RuleSustainedRecon fires when a source sustains interactions across at
	// least two sensors within one window.
	RuleSustainedRecon RuleID = "COR-004"
)

var ruleSummaries = map[RuleID]string{
	RuleRepeatedInjection: "repeated injection findings from one source",
	RuleProtocolHopping:   "one source probing multiple decoy protocols",
	RuleToolProbing:       "one source invoking many distinct canary tools",
	RuleSustainedRecon:    "sustained interaction across several sensors",
}

// KnownRuleIDs returns all correlation rule IDs in stable order.
func KnownRuleIDs() []string {
	return []string{
		string(RuleRepeatedInjection),
		string(RuleProtocolHopping),
		string(RuleToolProbing),
		string(RuleSustainedRecon),
	}
}

// ValidateRuleIDs reports unknown ids with an actionable message. Empty list
// is valid (nothing disabled).
func ValidateRuleIDs(ids []string) error {
	known := map[string]bool{}
	for _, k := range KnownRuleIDs() {
		known[k] = true
	}
	for _, id := range ids {
		if !known[id] {
			return fmt.Errorf("unknown correlation rule %q (known: %v)", id, KnownRuleIDs())
		}
	}
	return nil
}

// Event is the minimal view the engine needs. The caller maps richer sensor
// payloads onto it; SourceKey must be attacker-controlled but bounded by the
// caller (e.g., a normalized peer host).
type Event struct {
	ID             string    // provenance: source envelope id
	Time           time.Time // event time (drives all windows)
	SourceKey      string
	SensorID       string
	SensorKind     string   // http|tcp|mcp
	Classification string   // interaction|canary_invocation|...
	FindingIDs     []string // detection rule ids fired on this event
	ToolName       string   // canary tool name for mcp calls ("" otherwise)
}

// Signal is a derived observation. It links back to the events that produced
// it and carries only static rule-authored text.
type Signal struct {
	RuleID         RuleID
	Time           time.Time // triggering event's time
	SourceKey      string
	SourceEventIDs []string // provenance into the evidence store
	Summary        string
}

// Options bounds the engine. Zero-value fields take defaults via normalize.
type Options struct {
	// Window is the lookback for every rule (default 10m, max 1h).
	Window time.Duration
	// PerSourceEvents caps each source's ring (default 64, max 512).
	PerSourceEvents int
	// MaxSources caps tracked sources; eviction is FIFO by first-seen order
	// (default 4096, max 65536).
	MaxSources int
	// InjectionThreshold fires COR-001 (default 3).
	InjectionThreshold int
	// ToolProbeThreshold distinct tools fire COR-003 (default 4).
	ToolProbeThreshold int
	// ReconThreshold interactions fire COR-004 (default 6).
	ReconThreshold int
	// Now is injectable for tests; nil means time.Now. Rule math itself is
	// event-time based; Now stamps bookkeeping only.
	Now func() time.Time
}

// Defaults for Options; exported so config wiring (later PR) can reference
// documented numbers without magic constants.
const (
	DefaultWindow          = 10 * time.Minute
	MaxWindow              = time.Hour
	DefaultPerSourceEvents = 64
	MaxPerSourceEvents     = 512
	DefaultMaxSources      = 4096
	MaxMaxSources          = 65536
	DefaultInjectionThresh = 3
	DefaultToolProbeThresh = 4
	DefaultReconThresh     = 6
)

// Normalize applies defaults and clamps to hard bounds. Deterministic.
func (o *Options) Normalize() {
	if o.Window <= 0 {
		o.Window = DefaultWindow
	}
	if o.Window > MaxWindow {
		o.Window = MaxWindow
	}
	if o.PerSourceEvents <= 0 {
		o.PerSourceEvents = DefaultPerSourceEvents
	}
	if o.PerSourceEvents > MaxPerSourceEvents {
		o.PerSourceEvents = MaxPerSourceEvents
	}
	if o.MaxSources <= 0 {
		o.MaxSources = DefaultMaxSources
	}
	if o.MaxSources > MaxMaxSources {
		o.MaxSources = MaxMaxSources
	}
	if o.InjectionThreshold <= 0 {
		o.InjectionThreshold = DefaultInjectionThresh
	}
	if o.ToolProbeThreshold <= 0 {
		o.ToolProbeThreshold = DefaultToolProbeThresh
	}
	if o.ReconThreshold <= 0 {
		o.ReconThreshold = DefaultReconThresh
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

// Validate reports configuration mistakes Normalize cannot repair.
func (o *Options) Validate() error {
	if o.Window < 0 || o.Window > MaxWindow {
		return fmt.Errorf("correlate: window must be within 0..%s", MaxWindow)
	}
	if o.PerSourceEvents < 0 || o.PerSourceEvents > MaxPerSourceEvents {
		return fmt.Errorf("correlate: per_source_events must be within 0..%d", MaxPerSourceEvents)
	}
	if o.MaxSources < 0 || o.MaxSources > MaxMaxSources {
		return fmt.Errorf("correlate: max_sources must be within 0..%d", MaxMaxSources)
	}
	return nil
}

// sourceState is the bounded per-source ring plus cooldown bookkeeping.
type sourceState struct {
	events    []Event // arrival order; trimmed to PerSourceEvents and window
	firstSeen int64   // monotonic arrival counter for deterministic eviction
}

// Engine correlates events into signals under hard memory bounds. Evaluate
// is safe for single-goroutine use; wrap externally if needed (runtime PR).
type Engine struct {
	opts    Options
	sources map[string]*sourceState
	arrival int64 // total ingested; drives deterministic FIFO eviction

	evictedSources uint64
	trimmedEvents  uint64
	prunedEvents   uint64
}

// New constructs an engine. Options are copied after normalization.
func New(opts Options) *Engine {
	opts.Normalize()
	return &Engine{
		opts:    opts,
		sources: make(map[string]*sourceState),
	}
}

// Stats is a point-in-time snapshot of bounded-state accounting.
type Stats struct {
	SourcesTracked int
	EvictedSources uint64
	TrimmedEvents  uint64 // dropped by per-source cap
	PrunedEvents   uint64 // dropped by window expiry
	IngestedTotal  uint64
}

// Stats reports current accounting without mutating anything.
func (e *Engine) Stats() Stats {
	return Stats{
		SourcesTracked: len(e.sources),
		EvictedSources: e.evictedSources,
		TrimmedEvents:  e.trimmedEvents,
		PrunedEvents:   e.prunedEvents,
		IngestedTotal:  uint64(e.arrival),
	}
}

// Ingest adds an event to bounded state and returns any signals that fired.
// In this slice the engine performs ingestion, pruning, capping, and
// eviction only; rule evaluation arrives with the rules slice.
func (e *Engine) Ingest(ev Event) []Signal {
	e.arrival++
	key := ev.SourceKey
	st := e.sources[key]
	if st == nil {
		st = &sourceState{firstSeen: e.arrival}
		e.sources[key] = st
		if len(e.sources) > e.opts.MaxSources {
			e.evictOldest()
		}
	}
	e.prune(st, ev.Time)
	st.events = append(st.events, ev)
	for len(st.events) > e.opts.PerSourceEvents {
		st.events = st.events[1:]
		e.trimmedEvents++
	}
	return nil // rule evaluation lands in the rules slice
}

// prune drops events older than the window relative to the incoming event's
// time. Out-of-order arrivals are kept: pruning uses each stored event's own
// time against the incoming reference, so late-but-in-window events still
// count toward rules.
func (e *Engine) prune(st *sourceState, ref time.Time) {
	cutoff := ref.Add(-e.opts.Window)
	kept := st.events[:0]
	for _, ev := range st.events {
		if ev.Time.Before(cutoff) {
			e.prunedEvents++
			continue
		}
		kept = append(kept, ev)
	}
	st.events = kept // arrival order preserved by construction
}

// evictOldest removes the earliest-arrived source. Called only when the map
// just grew past MaxSources, keeping the loop O(MaxSources) at the bound.
func (e *Engine) evictOldest() {
	oldestKey := ""
	var oldestArrival int64
	for k, st := range e.sources {
		if oldestKey == "" || st.firstSeen < oldestArrival {
			oldestKey, oldestArrival = k, st.firstSeen
		}
	}
	if oldestKey != "" {
		delete(e.sources, oldestKey)
		e.evictedSources++
	}
}
