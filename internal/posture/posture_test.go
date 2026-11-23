package posture

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

func baseline() (*Facts, Evidence) {
	return &Facts{
		Sensors: []Sensor{
			{ID: "ai-api", Kind: "http", Listen: "127.0.0.1:8080", SurfaceFamilies: []string{"openai"}},
			{ID: "ai-workspace", Kind: "mcp", Listen: "127.0.0.1:8002", SurfaceFamilies: []string{"mcp_environment"}, MCPEnvironment: true},
		},
		Honeytokens:        []Token{{ID: "decoy-key", Kind: "credential", Planted: true}, {ID: "agent-diagnostic", Kind: "agent_canary", Planted: true}},
		ConsoleEnabled:     true,
		ConsoleListen:      "127.0.0.1:9120",
		TokenLogin:         true,
		OperatorRoles:      map[string]int{"admin": 1, "viewer": 1},
		LLMProvider:        "local",
		DetectionEnabled:   true,
		Actions:            map[string]string{"info": "observe", "low": "tag", "medium": "tag", "high": "observe"},
		CorrelationEnabled: true,
		EncryptionAtRest:   true,
	}, Evidence{
		Available: true, Scanned: 40, Limit: 8192,
		SensorEvents: map[string]int{"ai-api": 30, "ai-workspace": 10},
		TokenHits:    map[string]int{"decoy-key": 1},
	}
}

func TestBaselineIsAllOKOrExpectedInfo(t *testing.T) {
	facts, evidence := baseline()
	r := Evaluate(facts, evidence, time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC))
	if len(r.Checks) != 18 || r.Summary.Attention != 0 || r.Summary.OK+r.Summary.Info != 18 || r.Scope != "configuration_and_evidence" {
		t.Fatalf("%+v", r.Summary)
	}
	for i, c := range r.Checks {
		if c.ID != fmt.Sprintf("POS-%03d", i+1) {
			t.Fatalf("order: %s at %d", c.ID, i)
		}
		if c.Status == StatusOK && c.Recommendation != "" {
			t.Fatalf("%s ok with recommendation", c.ID)
		}
		if c.Title == "" || c.Detail == "" || !strings.HasPrefix(c.Doc, "docs/") || !regexp.MustCompile(`^(exposure|deception|detection|evidence|access)$`).MatchString(c.Area) {
			t.Fatalf("%+v", c)
		}
	}
	if again := Evaluate(facts, evidence, time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)); fmt.Sprint(again) != fmt.Sprint(r) {
		t.Fatal("nondeterministic")
	}
}

func TestChecks(t *testing.T) {
	for _, tc := range []struct {
		id, name string
		mutate   func(*Facts, *Evidence)
		status   string
		contains string
	}{
		{"POS-001", "loopback", func(*Facts, *Evidence) {}, StatusOK, "loopback"},
		{"POS-001", "public decoy", func(f *Facts, _ *Evidence) { f.Sensors[0].Listen = "0.0.0.0:8080" }, StatusInfo, "ai-api (0.0.0.0:8080)"},
		{"POS-001", "unspecified host", func(f *Facts, _ *Evidence) { f.Sensors[0].Listen = ":8080" }, StatusInfo, "ai-api"},
		{"POS-002", "none", func(*Facts, *Evidence) {}, StatusOK, "No safety opt-in"},
		{"POS-002", "public bind", func(f *Facts, _ *Evidence) { f.AllowPublicBind = true }, StatusInfo, "security.allow_public_bind"},
		{"POS-003", "disabled", func(f *Facts, _ *Evidence) { f.ConsoleEnabled = false }, StatusOK, "disabled"},
		{"POS-003", "public tls", func(f *Facts, _ *Evidence) { f.ConsoleListen, f.ConsoleTLS = "192.0.2.5:9120", true }, StatusInfo, "with TLS"},
		{"POS-003", "public cleartext", func(f *Facts, _ *Evidence) { f.ConsoleListen = "192.0.2.5:9120" }, StatusAttention, "without TLS"},
		{"POS-004", "local provider", func(f *Facts, _ *Evidence) { f.Sensors[0].LLMFallback = true }, StatusOK, "provider: local"},
		{"POS-004", "loopback model", func(f *Facts, _ *Evidence) {
			f.Sensors[0].LLMFallback, f.LLMProvider, f.LLMEndpointLoopback = true, "ollama", true
		}, StatusInfo, "loopback ollama"},
		{"POS-004", "remote model", func(f *Facts, _ *Evidence) { f.Sensors[0].LLMFallback, f.LLMProvider = true, "openai" }, StatusAttention, "beyond loopback"},
		{"POS-004", "remote provider without fallback", func(f *Facts, _ *Evidence) { f.LLMProvider = "openai" }, StatusOK, "fallback sensors: 0"},
		{"POS-005", "local only", func(*Facts, *Evidence) {}, StatusOK, "stays on this host"},
		{"POS-005", "fleet unpinned", func(f *Facts, _ *Evidence) { f.FleetForwarding = true }, StatusInfo, "system trust roots"},
		{"POS-005", "webhook", func(f *Facts, _ *Evidence) { f.Webhook = true }, StatusInfo, "webhook delivery"},
		{"POS-006", "separated", func(*Facts, *Evidence) {}, StatusOK, "1 viewer"},
		{"POS-006", "all admin", func(f *Facts, _ *Evidence) { f.OperatorRoles = map[string]int{"admin": 3} }, StatusAttention, "Every token operator"},
		{"POS-006", "single viewer", func(f *Facts, _ *Evidence) { f.OperatorRoles = map[string]int{"viewer": 1} }, StatusAttention, "single shared token"},
		{"POS-006", "single viewer with oidc", func(f *Facts, _ *Evidence) { f.OperatorRoles, f.OIDC = map[string]int{"viewer": 1}, true }, StatusOK, "OIDC enabled"},
		{"POS-006", "console off", func(f *Facts, _ *Evidence) { f.ConsoleEnabled = false }, StatusInfo, "not evaluated"},
		{"POS-007", "none", func(f *Facts, _ *Evidence) { f.Honeytokens = nil }, StatusAttention, "No honeytokens"},
		{"POS-008", "no canary", func(f *Facts, _ *Evidence) { f.Honeytokens = f.Honeytokens[:1] }, StatusAttention, "none has kind agent_canary"},
		{"POS-008", "no tokens", func(f *Facts, _ *Evidence) { f.Honeytokens = nil }, StatusInfo, "POS-007"},
		{"POS-009", "unplanted with body files", func(f *Facts, _ *Evidence) {
			f.Honeytokens[1].Planted, f.Sensors[0].BodyFiles = false, true
		}, StatusAttention, "agent-diagnostic"},
		{"POS-009", "planted", func(*Facts, *Evidence) {}, StatusOK, "Every honeytoken"},
		{"POS-010", "seen", func(*Facts, *Evidence) {}, StatusOK, "decoy-key"},
		{"POS-010", "never seen", func(_ *Facts, e *Evidence) { e.TokenHits = map[string]int{} }, StatusInfo, "normal on a quiet deployment"},
		{"POS-010", "unavailable", func(_ *Facts, e *Evidence) { *e = Unavailable("evidence is encrypted") }, StatusInfo, "Not evaluated: evidence is encrypted"},
		{"POS-011", "none", func(f *Facts, _ *Evidence) {
			f.Sensors = []Sensor{{ID: "web", Kind: "http", Listen: "127.0.0.1:1", SurfaceFamilies: []string{"http"}}}
		}, StatusAttention, "No sensor presents"},
		{"POS-012", "bare mcp", func(f *Facts, _ *Evidence) { f.Sensors[1].MCPEnvironment = false }, StatusInfo, "ai-workspace"},
		{"POS-012", "no mcp", func(f *Facts, _ *Evidence) { f.Sensors = f.Sensors[:1] }, StatusInfo, "No MCP sensor"},
		{"POS-013", "disabled", func(f *Facts, _ *Evidence) { f.DetectionEnabled = false }, StatusAttention, "disabled"},
		{"POS-013", "rules off", func(f *Facts, _ *Evidence) { f.DetectionDisabled = []string{"PI-002", "AGT-001"} }, StatusInfo, "AGT-001, PI-002"},
		{"POS-014", "disabled", func(f *Facts, _ *Evidence) { f.CorrelationEnabled = false }, StatusAttention, "never produced"},
		{"POS-014", "rules off", func(f *Facts, _ *Evidence) { f.CorrelationDisabled = []string{"COR-004"} }, StatusInfo, "COR-004"},
		{"POS-015", "observe only", func(*Facts, *Evidence) {}, StatusOK, "observe or tag"},
		{"POS-015", "defaults", func(f *Facts, _ *Evidence) {
			f.Actions = map[string]string{"info": "observe", "low": "tag", "medium": "isolate", "high": "refuse"}
		}, StatusInfo, "medium=isolate, high=refuse"},
		{"POS-016", "silent", func(_ *Facts, e *Evidence) { delete(e.SensorEvents, "ai-workspace") }, StatusInfo, "ai-workspace"},
		{"POS-016", "all active", func(*Facts, *Evidence) {}, StatusOK, "Every configured sensor"},
		{"POS-017", "saturated", func(_ *Facts, e *Evidence) { e.Truncated, e.Scanned = true, 8192 }, StatusAttention, "8192-event analysis sample"},
		{"POS-017", "fits", func(*Facts, *Evidence) {}, StatusOK, "40 retained"},
		{"POS-018", "plaintext", func(f *Facts, _ *Evidence) { f.EncryptionAtRest = false }, StatusInfo, "unencrypted"},
	} {
		t.Run(tc.id+"/"+tc.name, func(t *testing.T) {
			facts, evidence := baseline()
			tc.mutate(facts, &evidence)
			r := Evaluate(facts, evidence, time.Unix(0, 0))
			for _, c := range r.Checks {
				if c.ID != tc.id {
					continue
				}
				if c.Status != tc.status || !strings.Contains(c.Detail, tc.contains) {
					t.Fatalf("%+v", c)
				}
				if c.Status != StatusOK && c.Status != StatusInfo && c.Recommendation == "" {
					t.Fatal("attention without recommendation")
				}
				return
			}
			t.Fatal("check missing")
		})
	}
}

func TestEvidenceOnlyScope(t *testing.T) {
	r := Evaluate(nil, Evidence{Available: true, Scanned: 3, Limit: 8192}, time.Unix(0, 0))
	if r.Scope != "evidence_only" || len(r.Checks) != 1 || r.Checks[0].ID != "POS-017" || r.Summary.OK != 1 {
		t.Fatalf("%+v", r)
	}
	body, _ := json.Marshal(r)
	if !strings.Contains(string(body), `"checks":[`) {
		t.Fatal(string(body))
	}
}

func TestFromSnapshotSkipsForwardedEvents(t *testing.T) {
	snapshot := evidenceindex.Snapshot{Limit: 8192, Events: []evidenceindex.Summary{
		{Sensor: sensorRef("web"), TokenIDs: []string{"decoy-key"}},
		{Sensor: sensorRef("web"), Node: &evidenceindex.Node{ID: "n"}, TokenIDs: []string{"decoy-key"}},
		{Sensor: sensorRef("remote-only"), Node: &evidenceindex.Node{ID: "n"}},
	}}
	e := FromSnapshot(snapshot)
	if !e.Available || e.Scanned != 3 || e.SensorEvents["web"] != 1 || e.SensorEvents["remote-only"] != 0 || e.TokenHits["decoy-key"] != 1 {
		t.Fatalf("%+v", e)
	}
}

func sensorRef(id string) event.SensorRef { return event.SensorRef{ID: id, Kind: "http"} }
