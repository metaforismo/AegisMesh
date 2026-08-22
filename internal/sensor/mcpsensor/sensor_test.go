package mcpsensor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/policy"
	"github.com/metaforismo/aegismesh/internal/sensor"
)

type collectingSink struct {
	mu  sync.Mutex
	got []event.Envelope
}

func newCollectingSink() *collectingSink { return &collectingSink{} }

func (s *collectingSink) Append(_ context.Context, e event.Envelope) error {
	s.mu.Lock()
	s.got = append(s.got, e)
	s.mu.Unlock()
	return nil
}

func (s *collectingSink) snapshot() []event.Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]event.Envelope(nil), s.got...)
}

func (s *collectingSink) waitFor(t *testing.T, n int) []event.Envelope {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		got := s.snapshot()
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d/%d events", len(got), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func mcpCfg() config.Sensor {
	return config.Sensor{
		ID: "mcp-test", Kind: "mcp", Listen: "127.0.0.1:0", MCPPath: "/mcp",
		ServerName: "build-cache-mcp", ServerVer: "1.2.3",
		Instructions: "internal build cache",
		Tools: []config.MCPTool{
			{
				Name:        "read_build_log",
				Description: "read a CI build log",
				InputSchema: config.FlexJSON(`{"type":"object","properties":{}}`),
				ResultJSON:  `{"content":[{"type":"text","text":"ok build 42"}]}`,
			},
			{
				Name:        "fetch_artifact",
				Description: "fetch a release artifact",
				ResultJSON:  `{"artifact":"none"}`,
			},
		},
	}
}

// startTestSensor binds on an ephemeral loopback port and returns its URL.
func startTestSensor(t *testing.T, cfg config.Sensor) (*collectingSink, string) {
	t.Helper()
	s, err := New(cfg, policy.NewEnforcer(config.Detection{}, observe.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	sink := newCollectingSink()
	bus := event.NewBus(64, sink, quietLogger())
	deps := sensor.Deps{
		Config: cfg, Bus: bus, Meter: observe.NewRegistry(), Log: quietLogger(),
		Seq: &event.Sequencer{}, Instance: "test",
	}
	if err := s.Start(context.Background(), deps); err != nil {
		t.Fatal(err)
	}
	url := "http://" + s.Addr() + "/mcp"
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = s.Close(ctx)
		cancel()
		bus.Close()
	})
	return sink, url
}

func postRPC(t *testing.T, url string, payload any) (*http.Response, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()
	var out map[string]any
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if len(body) > 0 {
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("response not JSON: %q", body)
		}
	}
	return resp, out
}

func rpcReq(id int, method string, params any) map[string]any {
	m := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		m["params"] = params
	}
	return m
}

func TestMCPSensorInitializeAndList(t *testing.T) {
	cfg := mcpCfg()
	sink, url := startTestSensor(t, cfg)

	resp, out := postRPC(t, url, rpcReq(1, "initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
	}))
	if resp.StatusCode != 200 {
		t.Fatalf("initialize status %d", resp.StatusCode)
	}
	result, _ := out["result"].(map[string]any)
	if result == nil {
		t.Fatalf("initialize result missing: %+v", out)
	}
	serverInfo, _ := result["serverInfo"].(map[string]any)
	if serverInfo["name"] != "build-cache-mcp" || serverInfo["version"] != "1.2.3" {
		t.Fatalf("serverInfo wrong: %+v", serverInfo)
	}

	resp, out = postRPC(t, url, rpcReq(2, "tools/list", nil))
	if resp.StatusCode != 200 {
		t.Fatalf("tools/list status %d", resp.StatusCode)
	}
	result, _ = out["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("want 2 tools, got %d", len(tools))
	}

	events := sink.waitFor(t, 2)
	for _, e := range events {
		if e.Classification != event.ClassificationInteraction {
			t.Fatalf("initialize/list are interactions, got %s", e.Classification)
		}
		var obs observation
		if err := json.Unmarshal(e.Observation, &obs); err != nil {
			t.Fatal(err)
		}
		if obs.Method != "initialize" && obs.Method != "tools/list" {
			t.Fatalf("unexpected method %q", obs.Method)
		}
		if err := e.VerifyIntegrity(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMCPSensorCanaryInvocation(t *testing.T) {
	sink, url := startTestSensor(t, mcpCfg())

	params := map[string]any{
		"name":      "read_build_log",
		"arguments": map[string]any{"run_id": 1234, "password": "hunter2"},
	}
	resp, out := postRPC(t, url, rpcReq(7, "tools/call", params))
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if _, hasErr := out["error"]; hasErr {
		t.Fatalf("canary call must succeed: %+v", out)
	}
	result, _ := out["result"].(map[string]any)
	if result == nil || !strings.Contains(mustJSON(result), "ok build 42") {
		t.Fatalf("canned result missing: %+v", result)
	}

	events := sink.waitFor(t, 1)
	e := events[0]
	if e.Classification != event.ClassificationCanaryHit {
		t.Fatalf("classification should be canary_invocation, got %s", e.Classification)
	}
	var obs observation
	if err := json.Unmarshal(e.Observation, &obs); err != nil {
		t.Fatal(err)
	}
	if obs.ToolName != "read_build_log" || obs.Response.Rejected {
		t.Fatalf("observation wrong: %+v", obs)
	}
	if strings.Contains(obs.ArgsPreview, "hunter2") {
		t.Fatalf("secret leaked into evidence preview: %q", obs.ArgsPreview)
	}
	if len(obs.ArgsSHA256) != 64 {
		t.Fatalf("args digest missing")
	}
}

func TestMCPSensorUnknownToolIsRejectedAndRecorded(t *testing.T) {
	sink, url := startTestSensor(t, mcpCfg())

	resp, out := postRPC(t, url, rpcReq(9, "tools/call", map[string]any{
		"name": "delete_everything",
	}))
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	errObj, _ := out["error"].(map[string]any)
	if errObj == nil || errObj["code"].(float64) != codeInvalidParams {
		t.Fatalf("unknown tool must be an invalid params error: %+v", out)
	}

	events := sink.waitFor(t, 1)
	var obs observation
	if err := json.Unmarshal(events[0].Observation, &obs); err != nil {
		t.Fatal(err)
	}
	if obs.ToolName != "delete_everything" || !obs.Response.Rejected || obs.Response.RuleID != "unknown-tool" {
		t.Fatalf("observation wrong: %+v", obs)
	}
}

func TestMCPSensorProtocolErrors(t *testing.T) {
	_, url := startTestSensor(t, mcpCfg())

	// Unparseable body → JSON-RPC parse error object, HTTP 200.
	resp, err := http.Post(url, "application/json", strings.NewReader("{not json"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("parse error must still be JSON-RPC JSON: %q", body)
	}
	errObj, _ := out["error"].(map[string]any)
	if errObj == nil || errObj["code"].(float64) != codeParseError {
		t.Fatalf("parse error object missing: %s", body)
	}

	// GET → 405 with Allow: POST.
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusMethodNotAllowed || res.Header.Get("Allow") != "POST" {
		t.Fatalf("GET should be 405 Allow POST, got %d %q", res.StatusCode, res.Header.Get("Allow"))
	}

	// Unknown method → -32601.
	_, out = postRPC(t, url, rpcReq(3, "resources/list", nil))
	errObj, _ = out["error"].(map[string]any)
	if errObj == nil || errObj["code"].(float64) != codeMethodNotFound {
		t.Fatalf("method-not-found error missing: %+v", out)
	}

	// Notification → 202, empty body.
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	nresp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	nbody, _ := io.ReadAll(nresp.Body)
	nresp.Body.Close()
	if nresp.StatusCode != http.StatusAccepted || len(bytes.TrimSpace(nbody)) != 0 {
		t.Fatalf("notification should be 202 empty, got %d %q", nresp.StatusCode, nbody)
	}
}

func TestMCPSensorOversizeMessageRejected(t *testing.T) {
	_, url := startTestSensor(t, mcpCfg())

	big := "{" + strings.Repeat("a", maxMessageBytes+16)
	resp, err := http.Post(url, "application/json", strings.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("oversize response not JSON: %q", body[:min(len(body), 200)])
	}
	errObj, _ := out["error"].(map[string]any)
	if errObj == nil {
		t.Fatalf("oversize message must produce error object: %s", body)
	}
}

func TestMCPSensorCloseShutsDownCleanly(t *testing.T) {
	s, err := New(mcpCfg(), policy.NewEnforcer(config.Detection{}, observe.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	sink := newCollectingSink()
	bus := event.NewBus(16, sink, quietLogger())
	defer bus.Close()
	deps := sensor.Deps{
		Config: mcpCfg(), Bus: bus, Meter: observe.NewRegistry(), Log: quietLogger(),
		Seq: &event.Sequencer{}, Instance: "test",
	}
	if err := s.Start(context.Background(), deps); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-s.Done():
	default:
		t.Fatal("Done should be closed after Close")
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
