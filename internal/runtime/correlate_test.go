package runtime

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
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
	a := newCorrelateAdapter(correlateOptions{}, reg, quietLoggerT(t))
	a.observe(event.Envelope{ID: "bad", Time: time.Now(), Observation: []byte("{not json")})
	if !strings.Contains(reg.WritePrometheus(), "aegismesh_correlate_events_skipped_total 1") {
		t.Fatalf("malformed observation must be counted as skipped:\n%s", reg.WritePrometheus())
	}
	if a.Stats().IngestedTotal != 0 {
		t.Fatalf("nothing should reach the engine: %+v", a.Stats())
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
	reg := observe.NewRegistry()
	logs := newCaptureLogger()
	a := newCorrelateAdapter(correlateOptions{
		WindowSeconds:   600,
		PerSourceEvents: 64,
		MaxSources:      1024,
	}, reg, logs.logger)

	peer := "203.0.113.9"
	for i, kind := range []string{"http", "tcp", "mcp"} {
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
}

func TestCorrelationSignalNotReingested(t *testing.T) {
	reg := observe.NewRegistry()
	a := newCorrelateAdapter(correlateOptions{WindowSeconds: 600}, reg, quietLoggerT(t))
	before := a.Stats().IngestedTotal
	a.observe(testEnvelope(t, "x", "s", "http", "interaction", mcpObs("", "198.51.100.5")))
	if a.Stats().IngestedTotal != before+1 {
		t.Fatalf("each observe must ingest exactly once: %+v", a.Stats())
	}
}

// --- small helpers -------------------------------------------------------

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

var _ context.Context // silence if unused after edits
