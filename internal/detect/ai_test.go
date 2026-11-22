package detect

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/honeytoken"
)

func hasRule(hits []Finding, id RuleID) bool {
	for _, f := range hits {
		if f.RuleID == id {
			return true
		}
	}
	return false
}
func TestAIRules(t *testing.T) {
	cases := []struct {
		name string
		in   Input
		want RuleID
		fire bool
	}{
		{"ollama", Input{Method: "GET", Path: "/api/tags?x=y"}, RuleAISurface, true},
		{"mention", Input{Text: "Documentation mentions /api/tags and sk-example"}, RuleAISurface, false},
		{"chat", Input{Method: "POST", Path: "/v1/chat/completions", Body: `{"max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`}, RuleMinimalProbe, true},
		{"ollama tiny", Input{Method: "POST", Path: "/api/generate", Body: `{"prompt":"hi","options":{"num_predict":5}}`}, RuleMinimalProbe, true},
		{"larger budget", Input{Method: "POST", Path: "/v1/completions", Body: `{"prompt":"hi","max_tokens":6}`}, RuleMinimalProbe, false},
		{"zero budget", Input{Method: "POST", Path: "/v1/completions", Body: `{"prompt":"hi","max_tokens":0}`}, RuleMinimalProbe, true},
		{"key JSON", Input{Method: "POST", Path: "/auth", Body: `{"api_key":"sk-synthetic-example"}`}, RuleProviderKey, true},
		{"key query", Input{Path: "/auth?api_key=EMPTY"}, RuleProviderKey, true},
		{"TCP AUTH", Input{Protocol: "tcp", Text: "AUTH sk-synthetic-example"}, RuleProviderKey, true},
		{"negative", Input{Method: "POST", Path: "/v1/completions", Body: `{"prompt":"hi","max_tokens":-1}`}, RuleMinimalProbe, false},
		{"long prompt", Input{Method: "POST", Path: "/v1/completions", Body: `{"prompt":"` + strings.Repeat("x", 33) + `","max_tokens":1}`}, RuleMinimalProbe, false},
		{"empty prompt", Input{Method: "POST", Path: "/v1/completions", Body: `{"prompt":"","max_tokens":1}`}, RuleMinimalProbe, false},
		{"missing budget", Input{Method: "POST", Path: "/v1/completions", Body: `{"prompt":"hi"}`}, RuleMinimalProbe, false},
		{"unrelated", Input{Method: "POST", Path: "/orders", Body: `{"prompt":"hi","max_tokens":1}`}, RuleMinimalProbe, false},
		{"bad json", Input{Method: "POST", Path: "/v1/completions", Body: `{"prompt":"hi","max_tokens":`}, RuleMinimalProbe, false},
		{"pull", Input{Method: "POST", Path: "/api/pull"}, RuleAIManagement, true},
		{"key generation", Input{Method: "POST", Path: "/key/generate"}, RuleAIManagement, true},
		{"read only", Input{Method: "GET", Path: "/key/info"}, RuleAIManagement, false},
		{"key header", Input{Headers: map[string][]string{"authorization": {"Bearer sk-synthetic-example"}}}, RuleProviderKey, true},
		{"placeholder", Input{Headers: map[string][]string{"x-api-key": {"EMPTY"}}}, RuleProviderKey, true},
		{"key in prose", Input{Text: "The manual calls the placeholder EMPTY"}, RuleProviderKey, false},
		{"credential", Input{TokenMatches: []honeytoken.Match{{ID: "plant", Kind: honeytoken.Credential}}}, RuleHoneytoken, true},
		{"canary", Input{TokenMatches: []honeytoken.Match{{ID: "marker", Kind: honeytoken.AgentCanary}}}, RuleAgentCanary, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits := New(Options{}).Evaluate(tc.in)
			if hasRule(hits, tc.want) != tc.fire {
				t.Fatalf("got %+v", hits)
			}
			if !reflect.DeepEqual(hits, New(Options{}).Evaluate(tc.in)) {
				t.Fatal("nondeterministic")
			}
		})
	}
}

func TestMetadataAndRegistryAppendOnly(t *testing.T) {
	want := []string{"PI-001", "PI-002", "EXF-001", "ESC-001", "OBS-001", "RES-001", "LLM-001", "LLM-002", "LLM-003", "LLM-004", "HT-001", "AGT-001", "MCP-001", "MCP-002", "MCP-003"}
	if !reflect.DeepEqual(KnownRuleIDs(), want) {
		t.Fatal(KnownRuleIDs())
	}
	for _, tc := range []struct {
		path   string
		family AIFamily
	}{{"/api/chat", FamilyOllama}, {"/v1/models", FamilyOpenAI}, {"/model/info", FamilyLiteLLM}, {"/tokenize", FamilyVLLM}, {"/detokenize", FamilyVLLM}, {"/v1/score", FamilyVLLM}, {"/rerank", FamilyVLLM}, {"/invocations", FamilyVLLM}, {"/version", ""}, {"/metrics", ""}, {"/sse", ""}, {"/mcp", FamilyMCP}} {
		if SurfaceFamily(Input{Path: tc.path}) != tc.family {
			t.Fatal(tc)
		}
	}
	in := Input{Path: "/v1/models", Headers: map[string][]string{"authorization": {"Bearer sk-synthetic-example"}}, TokenMatches: []honeytoken.Match{{ID: "test-marker", Kind: honeytoken.Credential}}}
	hits := New(Options{}).Evaluate(in)
	b, _ := json.Marshal(hits)
	if strings.Contains(string(b), "sk-synthetic-example") || !strings.Contains(string(b), "test-marker") || !hasRule(hits, RuleHoneytoken) {
		t.Fatal(string(b))
	}
	for _, id := range want[6:] {
		if !ObserveOnly(RuleID(id)) {
			t.Fatal(id)
		}
	}
	for _, f := range hits {
		if f.RuleID == RuleHoneytoken && f.Severity != SevCritical {
			t.Fatal(f)
		}
	}
}

func FuzzMinimalProbe(f *testing.F) {
	f.Add(`{"prompt":"hi","max_tokens":1}`)
	f.Add(`{"options":{"num_predict":5},"messages":[{"role":"user","content":"hi"}]}`)
	f.Add(`[]`)
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > hardMaxScanBytes+1 {
			return
		}
		in := Input{Method: "POST", Path: "/v1/completions", Body: body}
		hits := New(Options{}).Evaluate(in)
		if hasRule(hits, RuleMinimalProbe) && (!json.Valid([]byte(body)) || len(body) > hardMaxScanBytes) {
			t.Fatal("invalid or oversized JSON classified as a minimal probe")
		}
	})
}
