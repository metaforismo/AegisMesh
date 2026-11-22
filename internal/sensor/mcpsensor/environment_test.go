package mcpsensor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/detect"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/honeytoken"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/policy"
	"github.com/metaforismo/aegismesh/internal/sensor"
)

func workspace() *config.MCPEnvironment {
	return &config.MCPEnvironment{
		DepthThreshold: 3,
		Files: []config.MCPEntry{{
			Name:    "readme",
			Content: "static workspace",
		}, {
			Name:    ".env",
			Content: "API_KEY=synthetic-workspace-token",
			TokenID: "plant",
		}},
		Env: []config.MCPEntry{{
			Name:    "API_KEY",
			Content: "synthetic-workspace-token",
			TokenID: "plant",
		}},
		Queries: map[string]string{"select workspace": "static row"},
	}
}

func TestEnvironmentExactLookupAndNoHostAccess(t *testing.T) {
	t.Setenv("HOST_CANARY", "real-environment-must-not-be-returned")
	realPath := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(realPath, []byte("real-file-must-not-be-returned"), 0600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		args   map[string]string
		want   string
		secret bool
		write  bool
	}{
		{"list_files", map[string]string{}, ".env\nreadme", false, false},
		{"read_file", map[string]string{"path": "readme"}, "static workspace", false, false},
		{"read_file", map[string]string{"path": ".env"}, "API_KEY=synthetic-workspace-token", true, false},
		{"read_file", map[string]string{"path": "./.env"}, "Not found", false, false},
		{"read_file", map[string]string{"path": "../.env"}, "Not found", false, false},
		{"read_file", map[string]string{"path": realPath}, "Not found", false, false},
		{"get_env", map[string]string{"name": "API_KEY"}, "synthetic-workspace-token", true, false},
		{"get_env", map[string]string{"name": "HOST_CANARY"}, "Not found", false, false},
		{"search", map[string]string{"query": "static"}, "readme", false, false},
		{"run_query", map[string]string{"query": "select workspace"}, "static row", false, false},
		{"run_query", map[string]string{"query": "select workspace; delete all"}, "Not found", false, false},
		{"read_file", map[string]string{"path": ".env", "extra": "value"}, "Not found", false, false},
		{"exec_shell", map[string]string{"command": "echo ignored"}, "", false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name+tc.want, func(t *testing.T) {
			raw, _ := json.Marshal(map[string]any{"name": tc.name, "arguments": tc.args})
			result, handled, secret, write := environmentResult(compileEnvironment(workspace()), raw)
			if secret != tc.secret || write != tc.write || handled != config.IsMCPEnvironmentTool(tc.name) {
				t.Fatal(handled, secret, write)
			}
			if handled {
				var decoded struct {
					Content []struct {
						Text string `json:"text"`
					} `json:"content"`
				}
				if json.Unmarshal(result, &decoded) != nil || len(decoded.Content) != 1 || decoded.Content[0].Text != tc.want {
					t.Fatal(string(result))
				}
			}
		})
	}
}

func TestEnvironmentConnectionExplorationAndRedaction(t *testing.T) {
	cfg := mcpCfg()
	cfg.Environment = workspace()
	token := honeytoken.Token{
		ID:    "plant",
		Value: "synthetic-workspace-token",
		Kind:  honeytoken.Credential,
	}
	enf := policy.NewEnforcer(config.Detection{}, observe.NewRegistry(), token)
	s, err := New(cfg, enf)
	if err != nil {
		t.Fatal(err)
	}
	sink := newCollectingSink()
	bus := event.NewBus(512, sink, quietLogger())
	if err := s.Start(context.Background(), sensor.Deps{
		Config:   cfg,
		Bus:      bus,
		Meter:    observe.NewRegistry(),
		Log:      quietLogger(),
		Seq:      &event.Sequencer{},
		Instance: "test",
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close(context.Background()); bus.Close() })
	transport := &http.Transport{
		Proxy:           nil,
		MaxConnsPerHost: 1,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
	}
	post := func(method string, params any) []byte {
		t.Helper()
		raw, _ := json.Marshal(rpcReq(1, method, params))
		resp, err := client.Post("http://"+s.Addr()+"/mcp", "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	if body := post("tools/list", nil); !bytes.Contains(body, []byte(`"run_query"`)) {
		t.Fatal(string(body))
	}
	post("tools/call", map[string]any{"name": "list_files", "arguments": map[string]string{}})
	if body := post("tools/call", map[string]any{"name": "read_file", "arguments": map[string]string{"path": ".env"}}); !bytes.Contains(body, []byte(token.Value)) {
		t.Fatal("declared fake content not returned")
	}
	post("tools/call", map[string]any{"name": "exec_shell", "arguments": map[string]string{"command": "ignored"}})
	post("tools/call", map[string]any{"name": "get_env", "arguments": map[string]string{"name": "API_KEY", "presented": token.Value}})
	events := sink.waitFor(t, 5)
	seen := map[detect.RuleID]bool{}
	for i, e := range events[:5] {
		if bytes.Contains(e.Observation, []byte(token.Value)) {
			t.Fatal("planted value reached storage")
		}
		var obs observation
		if json.Unmarshal(e.Observation, &obs) != nil || obs.Step != i+1 || len(obs.ToolSequence) != i {
			t.Fatalf("sequence: %s", e.Observation)
		}
		for _, f := range obs.Detection.Findings {
			seen[f.RuleID] = true
		}
	}
	for _, id := range []detect.RuleID{detect.RuleMCPSecret, detect.RuleMCPDepth, detect.RuleMCPWrite, detect.RuleHoneytoken} {
		if !seen[id] {
			t.Fatal("missing finding", id)
		}
	}
	transport.CloseIdleConnections()
	post("ping", nil)
	events = sink.waitFor(t, 6)
	var obs observation
	_ = json.Unmarshal(events[5].Observation, &obs)
	if obs.Step != 1 || len(obs.ToolSequence) != 0 {
		t.Fatal("connection state leaked")
	}
	for i := 1; i < 256; i++ {
		post("ping", nil)
	}
	if body := post("ping", nil); !bytes.Contains(body, []byte("connection request limit")) {
		t.Fatal(string(body))
	}
}

func FuzzEnvironmentLookup(f *testing.F) {
	for _, seed := range []string{`{"name":"read_file","arguments":{"path":"../.env"}}`, `{"name":"get_env","arguments":{"name":"PATH"}}`, `{"name":"exec_shell","arguments":{}}`, `{"name":"search","arguments":{"query":""}}`, `{"name":"run_query","arguments":{"query":"select workspace"}}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > maxMessageBytes {
			return
		}
		body, _, _, _ := environmentResult(compileEnvironment(workspace()), json.RawMessage(input))
		if len(body) > config.MaxMCPResultBytes || len(body) > 0 && !json.Valid(body) || strings.Contains(string(body), "real-file-must-not-be-returned") {
			t.Fatal("invalid or unbounded static response")
		}
	})
}

func TestEnvironmentRejectsAmbiguousArgumentsAndCapsEncodedContent(t *testing.T) {
	for _, args := range []string{`{"path":"readme","path":".env"}`, `null`, `{"path":{"nested":".env"}}`} {
		raw := json.RawMessage(`{"name":"read_file","arguments":` + args + `}`)
		body, _, secret, _ := environmentResult(compileEnvironment(workspace()), raw)
		if secret || bytes.Contains(body, []byte("synthetic-workspace-token")) {
			t.Fatal(string(body))
		}
	}
	cfg := workspace()
	cfg.Files[0].Content = strings.Repeat("\x00", 4096)
	body, handled, _, _ := environmentResult(compileEnvironment(cfg), json.RawMessage(`{"name":"read_file","arguments":{"path":"readme"}}`))
	if !handled || len(body) > config.MaxMCPResultBytes || !bytes.Contains(body, []byte("Result unavailable")) {
		t.Fatal("encoded result cap not applied")
	}
}
