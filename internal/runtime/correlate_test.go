package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/correlate"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
)

func testEnvelope(t *testing.T, id, sensorID, kind, class string, obs map[string]any) event.Envelope {
	t.Helper()
	raw, err := json.Marshal(obs)
	if err != nil {
		t.Fatalf("marshal obs: %v", err)
	}
	return event.Envelope{
		Schema:         "aegismesh.io/v1alpha1",
		ID:             id,
		Time:           time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC).Add(time.Duration(len(id)) * time.Second),
		Sensor:         event.SensorRef{ID: sensorID, Kind: kind},
		Classification: class,
		Observation:    raw,
	}
}

func mcpObs(tool, remote string, findings ...string) map[string]any {
	det := map[string]any{}
	if len(findings) > 0 {
		fs := make([]map[string]any, 0, len(findings))
		for _, f := range findings {
			fs = append(fs, map[string]any{"rule_id": f})
		}
		det["findings"] = fs
	}
	obs := map[string]any{"remote_host": remote}
	if len(det) > 0 {
		obs["detection"] = det
	}
	if tool != "" {
		obs["tool_name"] = tool
	}
	return obs
}

func TestEnvelopeToCorrelateEventExtraction(t *testing.T) {
	env := testEnvelope(t, "e1", "mcp-one", "mcp", "canary_invocation",
		mcpObs("fs_read", "10.1.2.3", "PI-001", ""))
	ev, ok := envelopeToCorrelateEvent(env)
	if !ok {
		t.Fatal("well-formed envelope must convert")
	}
	if ev.SourceKey != "10.1.2.3" || ev.ToolName != "fs_read" {
		t.Fatalf("extraction wrong: %+v", ev)
	}
	if len(ev.FindingIDs) != 1 || ev.FindingIDs[0] != "PI-001" {
		t.Fatalf("empty rule ids must be dropped: %v", ev.FindingIDs)
	}
}

func TestEnvelopeWithoutPeerFallsBackToSensorKey(t *testing.T) {
	obs := map[string]any{"method": "GET"} // http shape, no remote_host here
	ev, ok := envelopeToCorrelateEvent(testEnvelope(t, "e2", "http-one", "http", "interaction", obs))
	if !ok || ev.SourceKey != "sensor:http-one" {
		t.Fatalf("fallback key wrong: ok=%v ev=%+v", ok, ev)
	}
}

func TestMalformedObservationIsSkippedNotFatal(t *testing.T) {
	reg := observe.NewRegistry()
	sink := &recordSink{}
	a := newCorrelateAdapter(correlateOptions{}, testDeps(sink), reg, quietLoggerT(t))
	a.observe(event.Envelope{ID: "bad", Time: time.Now(), Observation: []byte("{not json")})
	if !strings.Contains(reg.WritePrometheus(), "aegismesh_correlate_events_skipped_total 1") {
		t.Fatalf("malformed observation must be counted as skipped:\n%s", reg.WritePrometheus())
	}
	if a.Stats().IngestedTotal != 0 {
		t.Fatalf("nothing should reach the engine: %+v", a.Stats())
	}
	if len(sink.collected()) != 0 {
		t.Fatalf("unusable observations must not produce evidence: %v", sink.collected())
	}
}

func TestDisabledByDefaultAndConfigGate(t *testing.T) {
	if (config.Correlation{}).IsEnabled() {
		t.Fatal("zero correlation section must be off")
	}
	on := true
	if !(config.Correlation{Enabled: &on}).IsEnabled() {
		t.Fatal("explicit enabled must be on")
	}
}

func TestSignalFiresAcrossKindsThroughAdapter(t *testing.T) {
	for _, kinds := range [][]string{
		{"http", "tcp", "mcp"},
		{"http", "tcp", "ssh"},
	} {
		t.Run(strings.Join(kinds, "-"), func(t *testing.T) {
			reg := observe.NewRegistry()
			logs := newCaptureLogger()
			sink := &recordSink{}
			a := newCorrelateAdapter(correlateOptions{
				WindowSeconds:   600,
				PerSourceEvents: 64,
				MaxSources:      1024,
			}, testDeps(sink), reg, logs.logger)

			peer := "203.0.113.9"
			for i, kind := range kinds {
				id := "ev-" + string(rune('a'+i))
				a.observe(testEnvelope(t, id, kind+"-one", kind, "interaction",
					map[string]any{"remote_host": peer}))
			}
			found := false
			for _, line := range logs.lines {
				if strings.Contains(line, `"rule_id":"COR-002"`) || strings.Contains(line, "COR-002") {
					found = true
				}
			}
			if !found {
				t.Fatalf("protocol hopping signal not logged: %v", logs.lines)
			}
			if a.Stats().FiredSignals != 1 {
				t.Fatalf("engine accounting mismatch: %+v", a.Stats())
			}
			stored := sink.collected()
			if len(stored) != 1 {
				t.Fatalf("fired signal must be persisted exactly once, got %d", len(stored))
			}
			var obs correlationObservation
			if err := json.Unmarshal(stored[0].Observation, &obs); err != nil {
				t.Fatalf("stored observation unmarshal: %v", err)
			}
			if stored[0].Classification != event.ClassificationCorrelationSignal || obs.RuleID != string(correlate.RuleProtocolHopping) {
				t.Fatalf("wrong persisted signal: class=%q obs=%+v", stored[0].Classification, obs)
			}
		})
	}
}

func TestCorrelationSignalNotReingested(t *testing.T) {
	reg := observe.NewRegistry()
	sink := &recordSink{}
	a := newCorrelateAdapter(correlateOptions{WindowSeconds: 600}, testDeps(sink), reg, quietLoggerT(t))
	before := a.Stats().IngestedTotal
	a.observe(testEnvelope(t, "x", "s", "http", "interaction", mcpObs("", "198.51.100.5")))
	if a.Stats().IngestedTotal != before+1 {
		t.Fatalf("each observe must ingest exactly once: %+v", a.Stats())
	}
	if len(sink.collected()) != 0 {
		t.Fatalf("plain interactions must never be recorded as signals: %v", sink.collected())
	}
}

// --- signal evidence persistence -----------------------------------------

// piEnvs builds n interaction envelopes from one peer, each carrying a
// prompt-injection finding — the minimum shape for COR-001.
func piEnvs(t *testing.T, peer string, n int) []event.Envelope {
	t.Helper()
	out := make([]event.Envelope, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, testEnvelope(t, fmt.Sprintf("pi-%03d", i), "mcp-one", "mcp",
			"interaction", mcpObs("fs_read", peer, "PI-101")))
	}
	return out
}

func TestCOR001StoredAsSingleEvidenceEnvelope(t *testing.T) {
	reg := observe.NewRegistry()
	sink := &recordSink{}
	a := newCorrelateAdapter(correlateOptions{WindowSeconds: 600}, testDeps(sink), reg, quietLoggerT(t))

	for _, env := range piEnvs(t, "203.0.113.50", 3) {
		a.observe(env)
	}

	stored := sink.collected()
	if len(stored) != 1 {
		t.Fatalf("exactly one stored envelope expected after minimum COR-001 events, got %d", len(stored))
	}
	env := stored[0]
	if env.Schema != event.SchemaV1 {
		t.Fatalf("schema must stay %q, got %q", event.SchemaV1, env.Schema)
	}
	if env.Classification != event.ClassificationCorrelationSignal {
		t.Fatalf("classification: got %q", env.Classification)
	}
	if env.Sensor.ID != signalSensorID || env.Sensor.Kind != signalSensorKind || env.Sensor.Listen != "" {
		t.Fatalf("sensor ref: %+v", env.Sensor)
	}
	if env.Instance != "test-instance" {
		t.Fatalf("instance: got %q", env.Instance)
	}
	if err := env.Validate(); err != nil {
		t.Fatalf("stored envelope must Validate: %v", err)
	}
	if err := env.VerifyIntegrity(); err != nil {
		t.Fatalf("stored envelope must VerifyIntegrity: %v", err)
	}
	var obs correlationObservation
	if err := json.Unmarshal(env.Observation, &obs); err != nil {
		t.Fatalf("observation unmarshal: %v", err)
	}
	wantIDs := []string{"pi-000", "pi-001", "pi-002"} // deterministic contributor order
	if obs.RuleID != string(correlate.RuleRepeatedInjection) ||
		obs.Summary != "repeated injection findings from one source" ||
		obs.SourceKey != "203.0.113.50" ||
		!slices.Equal(obs.SourceEventIDs, wantIDs) ||
		obs.Truncated {
		t.Fatalf("observation mismatch: %+v", obs)
	}
	if len(env.Observation) >= maxSignalObservationBytes {
		t.Fatalf("observation %d bytes exceeds budget %d", len(env.Observation), maxSignalObservationBytes)
	}
	if a.Stats().FiredSignals != 1 {
		t.Fatalf("engine accounting: %+v", a.Stats())
	}
	if want := `aegismesh_correlate_signals_total{label="COR-001"} 1`; !strings.Contains(reg.WritePrometheus(), want) {
		t.Fatalf("missing metric %s in:\n%s", want, reg.WritePrometheus())
	}
}

func TestCooldownPreventsSecondStoredSignal(t *testing.T) {
	sink := &recordSink{}
	a := newCorrelateAdapter(correlateOptions{WindowSeconds: 600}, testDeps(sink), observe.NewRegistry(), quietLoggerT(t))

	for _, env := range piEnvs(t, "203.0.113.51", 6) { // far beyond the threshold of 3
		a.observe(env)
	}
	if got := len(sink.collected()); got != 1 {
		t.Fatalf("cooldown must keep storage at exactly one envelope, got %d", got)
	}
	if a.Stats().FiredSignals != 1 {
		t.Fatalf("engine accounting: %+v", a.Stats())
	}
}

func TestDisabledRuleNeverFiresOrStores(t *testing.T) {
	sink := &recordSink{}
	a := newCorrelateAdapter(correlateOptions{
		WindowSeconds: 600,
		DisabledRules: []string{"COR-001"},
	}, testDeps(sink), observe.NewRegistry(), quietLoggerT(t))

	for _, env := range piEnvs(t, "203.0.113.52", 5) {
		a.observe(env)
	}
	if len(sink.collected()) != 0 {
		t.Fatalf("disabled rule must store nothing: %v", sink.collected())
	}
	if a.Stats().FiredSignals != 0 {
		t.Fatalf("disabled rule must not fire: %+v", a.Stats())
	}
}

func makeIDs(n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("ev-%03d", i)
	}
	return ids
}

func TestSignalObservationCapAndBudget(t *testing.T) {
	t.Run("at cap provenance stays verbatim", func(t *testing.T) {
		raw, ok := signalObservation(correlate.Signal{
			RuleID:         correlate.RuleSustainedRecon,
			SourceKey:      "198.51.100.7",
			SourceEventIDs: makeIDs(maxSignalContributors),
		})
		if !ok {
			t.Fatal("must serialize")
		}
		obs := mustDecodeObservation(t, raw)
		if obs.Truncated || !slices.Equal(obs.SourceEventIDs, makeIDs(maxSignalContributors)) {
			t.Fatalf("cap boundary must not truncate: %+v", obs)
		}
	})
	t.Run("over cap keeps the most recent 64 and flags truncation", func(t *testing.T) {
		ids := makeIDs(70)
		raw, ok := signalObservation(correlate.Signal{
			RuleID:         correlate.RuleSustainedRecon,
			SourceKey:      "198.51.100.8",
			SourceEventIDs: ids,
		})
		if !ok {
			t.Fatal("must serialize")
		}
		obs := mustDecodeObservation(t, raw)
		want := ids[len(ids)-maxSignalContributors:] // most recent wins
		if !obs.Truncated {
			t.Fatal("truncated flag missing")
		}
		if !slices.Equal(obs.SourceEventIDs, want) || obs.SourceEventIDs[0] != "ev-006" || obs.SourceEventIDs[63] != "ev-069" {
			t.Fatalf("cap must keep the most recent 64 in order: %+v", obs.SourceEventIDs)
		}
	})
	t.Run("oversized source key is normalized", func(t *testing.T) {
		raw, ok := signalObservation(correlate.Signal{
			RuleID:    correlate.RuleSustainedRecon,
			SourceKey: strings.Repeat("a", 500),
		})
		if !ok {
			t.Fatal("must serialize")
		}
		if got := mustDecodeObservation(t, raw).SourceKey; len(got) != maxSignalSourceKeyBytes {
			t.Fatalf("source key bound not applied: %d bytes", len(got))
		}
	})
	t.Run("serialized observation stays under budget at every bound", func(t *testing.T) {
		raw, ok := signalObservation(correlate.Signal{
			RuleID:         correlate.RuleSustainedRecon,
			Summary:        "sustained interaction across several sensors",
			SourceKey:      strings.Repeat("x", maxSignalSourceKeyBytes),
			SourceEventIDs: makeIDs(maxSignalContributors),
		})
		if !ok {
			t.Fatal("bounds composition must serialize")
		}
		if len(raw) >= maxSignalObservationBytes {
			t.Fatalf("worst-case observation %d bytes must stay under %d", len(raw), maxSignalObservationBytes)
		}
	})
}

func TestSinkFailureIsCountedAndNeverPropagates(t *testing.T) {
	reg := observe.NewRegistry()
	logs := newCaptureLogger()
	sink := &recordSink{failErr: errors.New("disk on fire")}
	a := newCorrelateAdapter(correlateOptions{WindowSeconds: 600}, testDeps(sink), reg, logs.logger)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("store failure must never panic: %v", r)
		}
	}()
	for _, env := range piEnvs(t, "203.0.113.53", 3) {
		a.observe(env)
	}

	if want := "aegismesh_correlate_signal_dropped_total 1"; !strings.Contains(reg.WritePrometheus(), want) {
		t.Fatalf("drop counter must read %s:\n%s", want, reg.WritePrometheus())
	}
	if len(sink.collected()) != 0 {
		t.Fatalf("failed appends must not be recorded: %v", sink.collected())
	}
	if a.Stats().FiredSignals != 1 {
		t.Fatalf("storage failures must not disturb the engine: %+v", a.Stats())
	}
	warned := false
	for _, line := range logs.lines {
		if strings.Contains(line, "evidence write failed") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("store failure must warn once: %v", logs.lines)
	}
}

func TestClassificationGateAcceptsOnlyRawObservations(t *testing.T) {
	cases := []struct {
		class string
		want  bool
	}{
		{event.ClassificationInteraction, true},
		{event.ClassificationCanaryHit, true},
		{event.ClassificationCorrelationSignal, false},
		{"future_classification", false},
	}
	for _, tc := range cases {
		_, ok := envelopeToCorrelateEvent(testEnvelope(t, "g1", "s", "http", tc.class,
			map[string]any{"remote_host": "192.0.2.1"}))
		if ok != tc.want {
			t.Errorf("classification %q: accepted=%v, want %v", tc.class, ok, tc.want)
		}
	}
}

func TestDerivedSignalEnvelopeIsSkippedNotIngested(t *testing.T) {
	reg := observe.NewRegistry()
	sink := &recordSink{}
	a := newCorrelateAdapter(correlateOptions{WindowSeconds: 600}, testDeps(sink), reg, quietLoggerT(t))

	a.observe(testEnvelope(t, "d1", signalSensorID, signalSensorKind,
		event.ClassificationCorrelationSignal, map[string]any{"rule_id": "COR-001"}))

	if a.Stats().IngestedTotal != 0 {
		t.Fatalf("derived signals must never re-enter the engine: %+v", a.Stats())
	}
	if want := "aegismesh_correlate_events_skipped_total 1"; !strings.Contains(reg.WritePrometheus(), want) {
		t.Fatalf("gate rejection must use existing skipped accounting:\n%s", reg.WritePrometheus())
	}
	if len(sink.collected()) != 0 {
		t.Fatalf("derived signals must not duplicate evidence: %v", sink.collected())
	}
}

func TestIdenticalInputsProduceIdenticalObservationBytes(t *testing.T) {
	run := func() []byte {
		sink := &recordSink{}
		a := newCorrelateAdapter(correlateOptions{WindowSeconds: 600}, testDeps(sink),
			observe.NewRegistry(), quietLoggerT(t))
		for _, env := range piEnvs(t, "203.0.113.54", 3) {
			a.observe(env)
		}
		stored := sink.collected()
		if len(stored) != 1 {
			t.Fatalf("expected one stored signal, got %d", len(stored))
		}
		return stored[0].Observation
	}
	first, second := run(), run() // fresh sequencer/instance each run; payload must not vary
	if !slices.Equal(first, second) {
		t.Fatalf("identical inputs must produce byte-identical observations:\nfirst:  %s\nsecond: %s", first, second)
	}
}

// --- small helpers -------------------------------------------------------

type recordSink struct {
	mu      sync.Mutex
	envs    []event.Envelope
	failErr error
}

func (s *recordSink) Append(_ context.Context, e event.Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failErr != nil {
		return s.failErr
	}
	s.envs = append(s.envs, e)
	return nil
}

func (s *recordSink) collected() []event.Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]event.Envelope(nil), s.envs...)
}

func testDeps(store event.Sink) correlateDeps {
	return correlateDeps{seq: &event.Sequencer{}, instance: "test-instance", store: store}
}

func mustDecodeObservation(t *testing.T, raw []byte) correlationObservation {
	t.Helper()
	var obs correlationObservation
	if err := json.Unmarshal(raw, &obs); err != nil {
		t.Fatalf("decode observation: %v", err)
	}
	return obs
}

func quietLoggerT(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type captureLogger struct {
	logger *slog.Logger
	mu     sync.Mutex
	lines  []string
}

func newCaptureLogger() *captureLogger {
	c := &captureLogger{}
	c.logger = slog.New(slog.NewTextHandler(&capWriter{c}, nil))
	return c
}

type capWriter struct{ c *captureLogger }

func (w *capWriter) Write(p []byte) (int, error) {
	w.c.mu.Lock()
	defer w.c.mu.Unlock()
	w.c.lines = append(w.c.lines, string(p))
	return len(p), nil
}
