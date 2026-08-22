package httpsensor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/metaforismo/aegismesh/internal/llm"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/policy"
	"github.com/metaforismo/aegismesh/internal/sensor"
)

type collectingSink struct {
	mu   sync.Mutex
	got  []event.Envelope
	cond *sync.Cond
}

func newCollectingSink() *collectingSink {
	s := &collectingSink{}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *collectingSink) Append(_ context.Context, e event.Envelope) error {
	s.mu.Lock()
	s.got = append(s.got, e)
	s.cond.Broadcast()
	s.mu.Unlock()
	return nil
}

func (s *collectingSink) snapshot() []event.Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]event.Envelope(nil), s.got...)
}

func (s *collectingSink) waitFor(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if len(s.snapshot()) >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d/%d events after deadline", len(s.snapshot()), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// startTestSensor binds on an ephemeral loopback port and returns its base URL.
func startTestSensor(t *testing.T, cfg config.Sensor) (*collectingSink, string) {
	t.Helper()
	gate, err := policy.NewHTTPGate(cfg, nil, llm.Local{}, policy.NewEnforcer(config.Detection{}, observe.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, gate)
	if err != nil {
		t.Fatal(err)
	}
	sink := newCollectingSink()
	bus := event.NewBus(64, sink, quietLogger())
	reg := observe.NewRegistry()
	deps := sensor.Deps{
		Config: cfg, Bus: bus, Meter: reg, Log: quietLogger(),
		Seq: &event.Sequencer{}, Instance: "test",
	}
	if err := s.Start(context.Background(), deps); err != nil {
		t.Fatal(err)
	}
	base := "http://" + s.Addr()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = s.Close(ctx)
		cancel()
		bus.Close()
	})
	return sink, base
}

func sensorCfg(rules []config.HTTPRule, fallback *config.LLMFallback) config.Sensor {
	return config.Sensor{
		ID: "http-test", Kind: "http", Listen: "127.0.0.1:0",
		Persona:      &config.HTTPPersona{ServerHeader: "TestPersona/1"},
		Rules:        rules,
		Fallback:     fallback,
		MaxBodyBytes: 64 << 10,
	}
}

func TestHTTPSensorEndToEnd(t *testing.T) {
	cfg := sensorCfg([]config.HTTPRule{
		{Name: "admin", PathRegex: "^/admin(/.*)?$", Methods: []string{"GET", "POST"}, Status: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: "<h1>decoy</h1>"},
	}, &config.LLMFallback{Enabled: true, SystemPrompt: "boring persona", MaxReplyChars: 1024})
	sink, base := startTestSensor(t, cfg)

	// 1) Rule hit.
	resp, err := http.Get(base + "/admin/login")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Server") != "TestPersona/1" || string(body) != "<h1>decoy</h1>" {
		t.Fatalf("rule response wrong: %d %q %v", resp.StatusCode, body, resp.Header)
	}

	// 2) Method mismatch → 405 with Allow when no rule fully matches.
	cfgNoCatchAll := sensorCfg([]config.HTTPRule{
		{Name: "post-only", PathRegex: "^/login$", Methods: []string{"POST"}, Status: 200, Body: "x"},
	}, nil)
	sink2, base2 := startTestSensor(t, cfgNoCatchAll)
	req, _ := http.NewRequest(http.MethodDelete, base2+"/login", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 405 || resp.Header.Get("Allow") != "POST" {
		t.Fatalf("want 405 Allow POST, got %d %v", resp.StatusCode, resp.Header.Get("Allow"))
	}
	_ = sink2

	// 3) Path matching no rule → provider fallback (deterministic local).
	resp, err = http.Get(base + "/deep/link?secret=abc")
	if err != nil {
		t.Fatal(err)
	}
	fbBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || len(fbBody) == 0 || resp.Header.Get("Server") == "" {
		t.Fatalf("fallback response wrong: %d %q", resp.StatusCode, fbBody)
	}

	sink.waitFor(t, 2) // rule hit + fallback

	events := sink.snapshot()
	byPath := map[string]event.Envelope{}
	for _, e := range events {
		var obs struct {
			Path     string `json:"path"`
			Response struct {
				RuleID string `json:"rule_id"`
				Status int    `json:"status"`
			} `json:"response"`
		}
		if err := json.Unmarshal(e.Observation, &obs); err != nil {
			t.Fatalf("observation decode: %v", err)
		}
		byPath[obs.Response.RuleID] = e
		if e.Classification != event.ClassificationInteraction {
			t.Fatalf("classification should be interaction, got %s", e.Classification)
		}
		if err := e.VerifyIntegrity(); err != nil {
			t.Fatalf("integrity: %v", err)
		}
	}
	if _, ok := byPath["admin"]; !ok {
		t.Fatalf("rule-hit event missing: %+v", events)
	}

	// Redaction invariants: query strings never persisted.
	for _, e := range events {
		if strings.Contains(string(e.Observation), "secret=abc") {
			t.Fatalf("query string leaked into evidence: %s", e.Observation)
		}
	}
}

func TestHTTPSensorBodyRedactionAndBounds(t *testing.T) {
	cfg := sensorCfg([]config.HTTPRule{
		{Name: "post", PathRegex: "^/upload$", Methods: []string{"POST"}, Status: 200, Body: "ok"},
	}, nil)
	sink, base := startTestSensor(t, cfg)

	payload := "user=bob password=hunter2 token=abcdef123456 padding-padding-padding"
	resp, err := http.Post(base+"/upload", "text/plain", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	sink.waitFor(t, 1)
	e := sink.snapshot()[0]
	raw := string(e.Observation)
	if strings.Contains(raw, "hunter2") || strings.Contains(raw, "abcdef123456") {
		t.Fatalf("credentials leaked into evidence: %s", raw)
	}
	sum := sha256.Sum256([]byte(payload))
	var obs struct {
		BodySHA256 string `json:"body_sha256"`
	}
	if err := json.Unmarshal(e.Observation, &obs); err != nil {
		t.Fatal(err)
	}
	if obs.BodySHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("payload hash mismatch: %s vs %x", obs.BodySHA256, sum)
	}
}

func TestHTTPSensorHeadAndLargeBodyCap(t *testing.T) {
	cfg := sensorCfg([]config.HTTPRule{
		{Name: "root", PathRegex: "^/$", Methods: []string{"GET", "HEAD", "POST"}, Status: 200, Body: "<b>x</b>"},
	}, nil)
	sink, base := startTestSensor(t, cfg)

	resp, err := http.Head(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.ContentLength <= 0 {
		t.Fatalf("HEAD should carry status+length: %d %d", resp.StatusCode, resp.ContentLength)
	}

	// Oversize POST: server must still answer like the decoy (200), and the
	// event must mark truncation rather than storing unbounded bytes.
	big := strings.Repeat("Z", int(cfg.MaxBodyBytes)+1024)
	resp, err = http.Post(base+"/", "text/plain", strings.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("oversize body should not break decoy behavior: %d", resp.StatusCode)
	}
	sink.waitFor(t, 2)
	foundTruncation := false
	for _, e := range sink.snapshot() {
		var obs struct {
			BodyTruncated bool `json:"body_truncated"`
		}
		if json.Unmarshal(e.Observation, &obs) == nil && obs.BodyTruncated {
			foundTruncation = true
		}
	}
	if !foundTruncation {
		t.Fatal("truncation not recorded for oversize body")
	}
}
