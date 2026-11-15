package hub_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/fleet/agent"
	"github.com/metaforismo/aegismesh/internal/fleet/hub"
	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
)

type testClock struct{ seconds atomic.Int64 }

func (c *testClock) now() time.Time {
	return time.Unix(c.seconds.Load(), 0)
}

type harness struct {
	hub    *hub.Hub
	server *httptest.Server
	dir    string
	clock  *testClock
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		dir:   filepath.Join(t.TempDir(), "hub"),
		clock: &testClock{},
	}
	h.clock.seconds.Store(time.Now().Unix())
	h.open(t)
	t.Cleanup(func() {
		h.server.Close()
		if err := h.hub.Close(); err != nil {
			t.Error(err)
		}
	})
	return h
}

func (h *harness) open(t *testing.T) {
	t.Helper()
	registry, err := hub.New(hub.Options{
		StateDir: h.dir,
		Now:      h.clock.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.hub = registry
	h.server = httptest.NewServer(registry)
}

func makeKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func (h *harness) mint(t *testing.T, ttl int) hub.Minted {
	t.Helper()
	token, err := h.hub.Mint(ttl, "synthetic fixture")
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func enrollment(key ed25519.PrivateKey, token string) protocol.Enrollment {
	return protocol.Enrollment{
		Token:           token,
		PublicKey:       hex.EncodeToString(key.Public().(ed25519.PublicKey)),
		Name:            "test-node",
		IntervalSeconds: 10,
	}
}

func heartbeat() protocol.Heartbeat {
	return protocol.Heartbeat{
		Name: "test-node",
		Version: protocol.Version{
			Version: "synthetic",
			Commit:  "test",
			Go:      "go1.27.4",
		},
		Sensors: []protocol.Sensor{
			{
				ID:    "web",
				Kind:  "http",
				State: "running",
			},
		},
		SensorsWanted:  1,
		SensorsStarted: 1,
		StorageHealthy: true,
	}
}

func (h *harness) request(t *testing.T, path string, body []byte, key ed25519.PrivateKey) *http.Request {
	t.Helper()
	request, err := http.NewRequest("POST", h.server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if err := protocol.Sign(request, body, key, h.clock.now()); err != nil {
		t.Fatal(err)
	}
	return request
}

func encoded(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func send(t *testing.T, request *http.Request, want int) {
	t.Helper()
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != want {
		t.Fatalf("status = %d, want %d; %s", response.StatusCode, want, body)
	}
}

func TestRealAgentLifecycleAndRestart(t *testing.T) {
	h := newHarness(t)
	token := h.mint(t, 0)
	opts := agent.Options{
		HubURL:   h.server.URL,
		StateDir: filepath.Join(t.TempDir(), "agent"),
		Name:     "test-node",
		Token:    token.Token,
		Interval: 10 * time.Second,
		Now:      h.clock.now,
		Snapshot: heartbeat,
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	reporter, err := agent.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := reporter.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	id := reporter.Status().NodeID
	requireNode := func(status string) {
		t.Helper()
		node, err := h.hub.Node(id)
		if err != nil || node.Status != status || len(node.Sensors) != 1 || !node.StorageHealthy {
			t.Fatalf("node = %+v, %v; want %s", node, err, status)
		}
	}
	requireNode("online")
	h.clock.seconds.Add(30)
	requireNode("stale")
	h.clock.seconds.Add(70)
	requireNode("offline")
	reporter.Close()
	h.server.Close()
	if err := h.hub.Close(); err != nil {
		t.Fatal(err)
	}
	h.open(t)
	requireNode("offline")
	opts.HubURL = h.server.URL
	opts.Token = ""
	restarted, err := agent.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if restarted.Status().NodeID != id {
		t.Fatal("agent restart changed identity")
	}
	if err := restarted.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireNode("online")
	if _, err := h.hub.Revoke(id); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Step(context.Background()); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked heartbeat: %v", err)
	}
	requireNode("revoked")
	opts.Token = token.Token
	revoked, err := agent.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer revoked.Close()
	if err := revoked.Step(context.Background()); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked re-enrollment: %v", err)
	}
	tokens, err := h.hub.Tokens()
	if err != nil || len(tokens) != 0 {
		t.Fatalf("consumed token persisted: %v", err)
	}
	persisted, err := os.ReadFile(filepath.Join(h.dir, "tenants", "default", "registry.json"))
	if err != nil || bytes.Contains(persisted, []byte(token.Token)) {
		t.Fatal("raw token persisted")
	}
}

func TestTokenAndProofFailures(t *testing.T) {
	for _, mode := range []string{"reuse", "expired", "wrong", "proof", "concurrent"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t)
			ttl := 1
			if mode == "reuse" {
				ttl = 60
			} // Keep the consumed token unexpired across retry spacing.
			token := h.mint(t, ttl)
			key := makeKey(t)
			input := enrollment(key, token.Token)
			switch mode {
			case "reuse":
				send(t, h.request(t, protocol.EnrollPath, encoded(t, input), key), 200)
				// A retry by the same key is idempotent after spacing; a different key cannot reuse the token.
				h.clock.seconds.Add(10)
				send(t, h.request(t, protocol.EnrollPath, encoded(t, input), key), 200)
				key = makeKey(t)
				input = enrollment(key, token.Token)
			case "expired":
				h.clock.seconds.Add(1)
			case "wrong":
				input.Token = strings.Repeat("0", 64)
			case "proof":
				body := encoded(t, input)
				request := h.request(t, protocol.EnrollPath, body, key)
				request.Header.Set("X-AegisMesh-Signature", strings.Repeat("0", 128))
				send(t, request, 401)
				tokens, _ := h.hub.Tokens()
				if len(tokens) != 1 {
					t.Fatal("invalid proof consumed token")
				}
				send(t, h.request(t, protocol.EnrollPath, body, key), 200)
				return
			case "concurrent":
				// Two independently generated identities race for the same one-use token.
				requests := make([]*http.Request, 2)
				for i := range requests {
					candidate := makeKey(t)
					requests[i] = h.request(t, protocol.EnrollPath, encoded(t, enrollment(candidate, token.Token)), candidate)
				}
				statuses := make(chan int, 2)
				var workers sync.WaitGroup
				for _, request := range requests {
					workers.Add(1)
					go func() {
						defer workers.Done()
						response, err := http.DefaultClient.Do(request)
						if err != nil {
							statuses <- 0
							return
						}
						_, _ = io.Copy(io.Discard, response.Body)
						response.Body.Close()
						statuses <- response.StatusCode
					}()
				}
				workers.Wait()
				first, second := <-statuses, <-statuses
				if first+second != 601 || first == second {
					t.Fatalf("single use race: %d %d", first, second)
				}
				return
			}
			send(t, h.request(t, protocol.EnrollPath, encoded(t, input), key), 401)
		})
	}
}

func TestAuthenticatedRequestFailuresAndReplayAcrossRestart(t *testing.T) {
	h := newHarness(t)
	key := makeKey(t)
	token := h.mint(t, 0)
	send(t, h.request(t, protocol.EnrollPath, encoded(t, enrollment(key, token.Token)), key), 200)
	body := encoded(t, heartbeat())
	for _, mode := range []string{"body", "path", "timestamp", "past", "future", "nonce", "oversized", "query"} {
		t.Run(mode, func(t *testing.T) {
			request := h.request(t, protocol.HeartbeatPath, body, key)
			want := 401
			switch mode {
			case "body":
				request.Body = io.NopCloser(strings.NewReader(strings.Replace(string(body), "synthetic", "tampered!", 1)))
			case "path":
				request.URL.Path = protocol.EnrollPath
				want = 400
			case "timestamp":
				request.Header.Set("X-AegisMesh-Time", strconv.FormatInt(h.clock.now().Unix()+1, 10))
			case "past", "future":
				shift := -121 * time.Second
				if mode == "future" {
					shift = 121 * time.Second
				}
				if err := protocol.Sign(request, body, key, h.clock.now().Add(shift)); err != nil {
					t.Fatal(err)
				}
			case "nonce":
				request.Header.Set("X-AegisMesh-Nonce", strings.Repeat("f", 32))
			case "oversized":
				request.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", protocol.MaxBodyBytes+1)))
				request.ContentLength = protocol.MaxBodyBytes + 1
				want = 413
			case "query":
				request.URL.RawQuery = "x=y"
			}
			send(t, request, want)
		})
	}
	request := h.request(t, protocol.HeartbeatPath, body, key)
	savedHeaders := request.Header.Clone()
	send(t, request, 200)
	repeated := h.request(t, protocol.HeartbeatPath, body, key)
	repeated.Header = savedHeaders.Clone()
	send(t, repeated, 401)
	h.server.Close()
	if err := h.hub.Close(); err != nil {
		t.Fatal(err)
	}
	h.open(t)
	replay := h.request(t, protocol.HeartbeatPath, body, key)
	replay.Header = savedHeaders.Clone()
	send(t, replay, 401)
}

func TestCapsAndCorruptState(t *testing.T) {
	h := newHarness(t)
	for range hub.MaxTokens {
		h.mint(t, 0)
	}
	if _, err := h.hub.Mint(0, ""); hub.Code(err) != "capacity" {
		t.Fatalf("token cap: %v", err)
	}
	for _, ttl := range []int{-1, 86401} {
		if _, err := h.hub.Mint(ttl, ""); hub.Code(err) != "invalid_argument" {
			t.Fatalf("TTL %d: %v", ttl, err)
		}
	}
	for _, invalid := range []string{`{`, `{"version":1,"version":1}`, `null`} {
		dir := filepath.Join(t.TempDir(), "corrupt")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "registry.json"), []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		if registry, err := hub.New(hub.Options{StateDir: dir}); err == nil {
			registry.Close()
			t.Fatal("accepted corrupt state")
		}
	}
}
