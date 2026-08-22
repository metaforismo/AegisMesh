package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/llm"
	"github.com/metaforismo/aegismesh/internal/observe"
)

func testEnforcer() *Enforcer {
	return NewEnforcer(config.Detection{}, observe.NewRegistry())
}

func httpSensorCfg(rules ...config.HTTPRule) config.Sensor {
	return config.Sensor{
		ID: "h1", Kind: "http", Listen: "127.0.0.1:0",
		Persona: &config.HTTPPersona{ServerHeader: "TestPersona"},
		Rules:   rules,
	}
}

func TestHTTPGateRulePrecedence(t *testing.T) {
	g, err := NewHTTPGate(httpSensorCfg(
		config.HTTPRule{Name: "admin", PathRegex: "^/admin.*", Methods: []string{"GET"}, Status: 200, Body: "admin-ok"},
		config.HTTPRule{Name: "catchall", PathRegex: "^/.*$", Status: 404, Body: "nope"},
	), nil, nil, testEnforcer())
	if err != nil {
		t.Fatal(err)
	}
	d, err := g.Resolve(context.Background(), "GET", "/admin/login", nil)
	if err != nil || d.RuleID != "admin" || d.Status != 200 {
		t.Fatalf("first matching rule must win: %+v err=%v", d, err)
	}
	if d.Headers["Server"] != "TestPersona" {
		t.Fatalf("persona header missing: %v", d.Headers)
	}
}

func TestHTTPGateMethodMismatch405(t *testing.T) {
	g, _ := NewHTTPGate(httpSensorCfg(
		config.HTTPRule{Name: "post-only", PathRegex: "^/login$", Methods: []string{"POST"}, Status: 200, Body: "x"},
	), nil, nil, testEnforcer())
	d, err := g.Resolve(context.Background(), "DELETE", "/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != 405 || d.Headers["Allow"] != "POST" {
		t.Fatalf("want 405+Allow, got %+v", d)
	}
}

func TestHTTPGateFallbackOnUnmatchedPath(t *testing.T) {
	cfg := httpSensorCfg(config.HTTPRule{Name: "root", PathRegex: "^/$", Status: 200, Body: "/"})
	cfg.Fallback = &config.LLMFallback{Enabled: true, SystemPrompt: "be boring", MaxReplyChars: 512}
	g, err := NewHTTPGate(cfg, nil, llm.Local{}, testEnforcer())
	if err != nil {
		t.Fatal(err)
	}
	d, err := g.Resolve(context.Background(), "GET", "/deep/unknown/path?q=1", []byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	if d.From != SourceProvider || len(d.Body) == 0 || len(d.Body) > 512+64 {
		t.Fatalf("fallback decision wrong: from=%s len=%d err=%v", d.From, len(d.Body), err)
	}
	if !strings.HasPrefix(d.RuleID, "llm:") {
		t.Fatalf("rule id should record provider provenance: %q", d.RuleID)
	}
}

// TestFallbackOutputIsScrubbed proves provider output passes the untrusted
// pipeline: even a hostile "provider" cannot smuggle credentials through.
type hostileProvider struct{}

func (hostileProvider) Name() string { return "hostile" }
func (hostileProvider) Complete(_ context.Context, _ llm.Request) (llm.Response, error) {
	return llm.Response{Text: "<html>password=supersecret9 token=abcdef123456</html>"}, nil
}

func TestFallbackOutputIsScrubbed(t *testing.T) {
	cfg := httpSensorCfg(config.HTTPRule{Name: "root", PathRegex: "^/$", Status: 200})
	cfg.Fallback = &config.LLMFallback{Enabled: true, SystemPrompt: "p", MaxReplyChars: 4096}
	g, _ := NewHTTPGate(cfg, nil, hostileProvider{}, testEnforcer())
	d, _ := g.Resolve(context.Background(), "GET", "/anything", nil)
	body := string(d.Body)
	if strings.Contains(body, "supersecret9") || strings.Contains(body, "abcdef123456") {
		t.Fatalf("provider output bypassed scrubbing: %q", body)
	}
}

func TestTCPGateMatchingAndSuffix(t *testing.T) {
	s := config.Sensor{
		ID: "t1", Kind: "tcp", Listen: "127.0.0.1:0",
		TCPResponseRule: []config.TCPRule{
			{Name: "ping", LineRegex: "^PING$", Response: "+OK PONG"},
			{Name: "other", LineRegex: "^.*$", Response: "-ERR"},
		},
	}
	g, err := NewTCPGate(s, testEnforcer())
	if err != nil {
		t.Fatal(err)
	}
	if got := string(g.Resolve("PING").Response); got != "+OK PONG\n" {
		t.Fatalf("CRLF normalization missing: %q", got)
	}
	d := g.Resolve("whatever")
	if d.RuleID != "other" {
		t.Fatalf("second rule should match: %+v", d)
	}
}

func TestGatesRejectBadRegex(t *testing.T) {
	bad := config.HTTPRule{Name: "b", PathRegex: "([unclosed", Status: 200}
	if _, err := NewHTTPGate(httpSensorCfg(bad), nil, nil, testEnforcer()); err == nil {
		t.Fatal("bad path regex must fail at gate construction")
	}
	if _, err := NewTCPGate(config.Sensor{
		ID: "t", Kind: "tcp",
		TCPResponseRule: []config.TCPRule{{LineRegex: "*", Response: "x"}},
	}, testEnforcer()); err == nil {
		t.Fatal("bad line regex must fail at gate construction")
	}
}
