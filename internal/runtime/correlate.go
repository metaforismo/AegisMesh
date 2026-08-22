package runtime

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/metaforismo/aegismesh/internal/correlate"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
)

// Persistence bounds for correlation-signal evidence. Together they keep
// every serialized observation far below the payload budget: 64 provenance
// IDs (~35 B each) + a 128 B source key + static rule text stays under 3 KiB
// against the 16 KiB cap.
const (
	signalSensorID   = "correlate"
	signalSensorKind = "correlation"

	maxSignalContributors     = 64 // hard cap on provenance IDs per persisted signal
	maxSignalSourceKeyBytes   = 128
	maxSignalObservationBytes = 16 << 10
)

// correlationObservation is the integrity-checked payload of a persisted
// signal. encoding/json emits struct fields in declaration order, so
// identical inputs always serialize to identical bytes.
type correlationObservation struct {
	RuleID         string   `json:"rule_id"`
	Summary        string   `json:"summary"`
	SourceKey      string   `json:"source_key"`
	SourceEventIDs []string `json:"source_event_ids"`
	Truncated      bool     `json:"truncated"`
}

// correlateDeps carries what the adapter needs to persist fired signals as
// evidence. The store is the primary JSONL sink, injected so tests can
// record or fail appends deterministically.
type correlateDeps struct {
	seq      *event.Sequencer
	instance string
	store    event.Sink
}

// correlateAdapter feeds a bounded engine from the evidence stream and turns
// fired signals into operator-facing logs, metrics, and evidence envelopes.
// It is strictly an observer: nothing here can influence decoy behavior,
// policy decisions, or sensor responses. Malformed observations are skipped
// (counted), never fatal; signal persistence failures are counted, never
// propagated.
type correlateAdapter struct {
	engine  *correlate.Engine
	log     *slog.Logger
	signals observe.LabeledCounter // by rule id
	skipped observe.Counter        // unparseable / unusable observations
	dropped observe.Counter        // signals not persisted (build/append errors)
	deps    correlateDeps
}

// obsProbe extracts the few fields correlation needs from any sensor's
// observation JSON. Both http and mcp observations carry remote_host,
// tool_name, and detection.findings[].rule_id with these exact names; absent
// fields simply stay zero.
type obsProbe struct {
	RemoteHost string `json:"remote_host"`
	ToolName   string `json:"tool_name"`
	Detection  *struct {
		Findings []struct {
			RuleID string `json:"rule_id"`
		} `json:"findings"`
	} `json:"detection"`
}

// correlateOptions is the runtime-facing subset of config.Correlation (kept
// separate so this package does not import config).
type correlateOptions struct {
	WindowSeconds   int
	PerSourceEvents int
	MaxSources      int
	DisabledRules   []string
}

func newCorrelateAdapter(cfg correlateOptions, deps correlateDeps, meter observe.Meter, log *slog.Logger) *correlateAdapter {
	opts := correlate.Options{
		Window:          time.Duration(cfg.WindowSeconds) * time.Second,
		PerSourceEvents: cfg.PerSourceEvents,
		MaxSources:      cfg.MaxSources,
	}
	for _, id := range cfg.DisabledRules {
		opts.DisabledRules = append(opts.DisabledRules, correlate.RuleID(id))
	}
	return &correlateAdapter{
		engine:  correlate.New(opts),
		log:     log,
		signals: meter.CounterVec("aegismesh_correlate_signals_total", "Correlation signals fired by rule", 8),
		skipped: meter.Counter("aegismesh_correlate_events_skipped_total", "Observations unusable for correlation"),
		dropped: meter.Counter("aegismesh_correlate_signal_dropped_total", "Correlation signals not persisted to the evidence store"),
		deps:    deps,
	}
}

// observe ingests one envelope. Never blocks on anything but the bounded
// engine; never returns errors to the sink path.
func (a *correlateAdapter) observe(e event.Envelope) {
	ev, ok := envelopeToCorrelateEvent(e)
	if !ok {
		a.skipped.Inc()
		return
	}
	for _, sig := range a.engine.Ingest(ev) {
		a.signals.Inc(string(sig.RuleID))
		a.log.Info("correlation signal",
			"rule_id", string(sig.RuleID),
			"time", sig.Time.UTC().Format(time.RFC3339),
			"source_key", sig.SourceKey,
			"summary", sig.Summary,
			"source_event_ids", sig.SourceEventIDs,
		)
		a.recordSignal(sig)
	}
}

// Stats exposes engine accounting for diagnostics.
func (a *correlateAdapter) Stats() correlate.Stats { return a.engine.Stats() }

// envelopeToCorrelateEvent maps an evidence envelope onto the engine's minimal
// event view. Only raw sensor observations feed the engine: the classification
// gate rejects derived evidence (correlation_signal and any future
// classification) so a persisted signal can never recursively re-enter
// correlation even if it were somehow offered back. The SourceKey is the
// attacker-controlled peer host when the observation carries one; otherwise it
// falls back to a per-sensor key so anonymous peers cannot be merged across
// sensors (conservative: may only under-detect, never fabricate).
func envelopeToCorrelateEvent(e event.Envelope) (correlate.Event, bool) {
	switch e.Classification {
	case event.ClassificationInteraction, event.ClassificationCanaryHit:
	default:
		return correlate.Event{}, false
	}
	if e.ID == "" || e.Time.IsZero() {
		return correlate.Event{}, false
	}
	var probe obsProbe
	if err := json.Unmarshal(e.Observation, &probe); err != nil {
		return correlate.Event{}, false
	}
	var findings []string
	if probe.Detection != nil {
		for _, f := range probe.Detection.Findings {
			if f.RuleID != "" {
				findings = append(findings, f.RuleID)
			}
		}
	}
	key := probe.RemoteHost
	if key == "" {
		key = "sensor:" + e.Sensor.ID
	}
	return correlate.Event{
		ID:             e.ID,
		Time:           e.Time,
		SourceKey:      key,
		SensorID:       e.Sensor.ID,
		SensorKind:     e.Sensor.Kind,
		Classification: e.Classification,
		FindingIDs:     findings,
		ToolName:       probe.ToolName,
	}, true
}

// signalObservation renders the persisted view of a fired signal: only the
// rule-authored summary, the engine-normalized source key, and provenance IDs
// are copied — never raw attacker-controlled payloads. Identical inputs yield
// byte-identical output (fixed field order, deterministic bounds). Truncated
// reports that provenance was cut to the most recent maxSignalContributors
// IDs; an oversized source key is additionally normalized to
// maxSignalSourceKeyBytes (the full value always remains in the originating
// sensor evidence). ok is false only if serialization could still exceed the
// payload budget — unreachable given the bounds above, kept as a hard guard.
func signalObservation(sig correlate.Signal) (raw []byte, ok bool) {
	key := sig.SourceKey
	if len(key) > maxSignalSourceKeyBytes {
		key = strings.ToValidUTF8(key[:maxSignalSourceKeyBytes], "")
	}
	ids := sig.SourceEventIDs
	truncated := len(ids) > maxSignalContributors
	if truncated {
		ids = ids[len(ids)-maxSignalContributors:] // most recent wins
	}
	b, err := json.Marshal(correlationObservation{
		RuleID:         string(sig.RuleID),
		Summary:        sig.Summary,
		SourceKey:      key,
		SourceEventIDs: ids,
		Truncated:      truncated,
	})
	if err != nil || len(b) >= maxSignalObservationBytes {
		return nil, false
	}
	return b, true
}

// recordSignal persists a fired signal as an integrity-checked evidence
// envelope appended straight to the primary store — deliberately not onto the
// event bus, so derived signals cannot re-enter correlation through the sink
// path and the raw sensor evidence flow is untouched. Append failures are
// counted on aegismesh_correlate_signal_dropped_total and logged; they never
// propagate to the caller and never panic.
func (a *correlateAdapter) recordSignal(sig correlate.Signal) {
	if a.deps.store == nil || a.deps.seq == nil {
		a.dropSignal(sig, "persistence not wired")
		return
	}
	raw, ok := signalObservation(sig)
	if !ok {
		a.dropSignal(sig, "observation budget guard tripped")
		return
	}
	env, err := event.New(a.deps.seq, a.deps.instance,
		event.SensorRef{ID: signalSensorID, Kind: signalSensorKind},
		event.ClassificationCorrelationSignal, raw, nil)
	if err != nil {
		a.dropSignal(sig, "envelope build failed")
		return
	}
	if err := a.deps.store.Append(context.Background(), env); err != nil {
		a.dropped.Inc()
		a.log.Warn("correlation signal evidence write failed",
			"rule_id", string(sig.RuleID), "event_id", env.ID, "err", err)
	}
}

func (a *correlateAdapter) dropSignal(sig correlate.Signal, reason string) {
	a.dropped.Inc()
	a.log.Warn("correlation signal not persisted",
		"rule_id", string(sig.RuleID), "reason", reason)
}
