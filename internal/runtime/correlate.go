package runtime

import (
	"encoding/json"
	"log/slog"
	"time"

	"github.com/metaforismo/aegismesh/internal/correlate"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
)

// correlateAdapter feeds a bounded engine from the evidence stream and turns
// fired signals into operator-facing logs and metrics. It is strictly an
// observer: nothing here can influence decoy behavior, policy decisions, or
// sensor responses. Malformed observations are skipped (counted), never fatal.
type correlateAdapter struct {
	engine  *correlate.Engine
	log     *slog.Logger
	signals observe.LabeledCounter // by rule id
	skipped observe.Counter        // unparseable / unusable observations
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

func newCorrelateAdapter(cfg correlateOptions, meter observe.Meter, log *slog.Logger) *correlateAdapter {
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
	}
}

// Stats exposes engine accounting for diagnostics.
func (a *correlateAdapter) Stats() correlate.Stats { return a.engine.Stats() }

// envelopeToCorrelateEvent maps an evidence envelope onto the engine's minimal
// event view. The SourceKey is the attacker-controlled peer host when the
// observation carries one; otherwise it falls back to a per-sensor key so
// anonymous peers cannot be merged across sensors (conservative: may only
// under-detect, never fabricate).
func envelopeToCorrelateEvent(e event.Envelope) (correlate.Event, bool) {
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
