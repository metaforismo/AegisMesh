package console_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console"
	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/runtime"
)

type testClock struct{ nanos atomic.Int64 }

func (clock *testClock) now() time.Time {
	return time.Unix(0, clock.nanos.Load())
}

func (clock *testClock) advance(duration time.Duration) {
	clock.nanos.Add(int64(duration))
}

type consoleHarness struct {
	server  *console.Server
	client  *http.Client
	base    string
	clock   *testClock
	eventID string
}

type apiRequest struct {
	method        string
	path          string
	token         string
	body          string
	cookie        *http.Cookie
	csrf          string
	origin        string
	host          string
	authorization string
	contentType   string
}

type apiResponse struct {
	status  int
	body    []byte
	header  http.Header
	cookies []*http.Cookie
}

func newConsoleHarness(t *testing.T, configure func(*console.Options)) *consoleHarness {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "mesh.yaml")
	const configuration = `api_version: aegismesh.io/v1alpha1
runtime:
  data_dir: data
admin:
  enabled: false
sensors:
  - id: web
    kind: http
    listen: 127.0.0.1:0
    rules:
      - name: root
        path_regex: ^/$
        status: 200
        body: synthetic
`
	if err := os.WriteFile(configPath, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	system, err := runtime.Build(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		system.Stop(context.Background())
	})
	if err := system.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	meter := observe.NewRegistry()
	index, err := evidenceindex.New(1000, meter)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := event.New(
		&event.Sequencer{}, "synthetic", event.SensorRef{
			ID:   "web",
			Kind: "http",
		}, "interaction",
		json.RawMessage(`{"method":"GET","path":"/","remote_host":"127.0.0.1","response":{"status":200}}`), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	index.Add(envelope)
	clock := &testClock{}
	clock.nanos.Store(time.Now().UnixNano())
	opts := console.Options{
		Config: config.Console{
			Enabled:           true,
			Listen:            "127.0.0.1:0",
			SessionTTLSeconds: 60,
			IndexMaxEvents:    1000,
		},
		StateDir: filepath.Join(dir, "console"),
		Index:    index,
		Runtime:  system,
		Meter:    meter,
		Now:      clock.now,
		UI: fstest.MapFS{
			"index.html":        {Data: []byte("<!doctype html><title>Console</title>")},
			"assets/app.js":     {Data: []byte("'use strict';")},
			"assets/style.css":  {Data: []byte("body {}")},
			"nested/index.html": {Data: []byte("not served")},
		},
	}
	for _, role := range []string{
		"viewer",
		"analyst",
		"admin",
	} {
		opts.Config.Operators = append(opts.Config.Operators, config.Operator{
			Name:        role,
			Role:        role,
			TokenSHA256: auth.Digest("synthetic-" + role),
		})
	}
	if configure != nil {
		configure(&opts)
	}
	server, err := console.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	server.Start()
	t.Cleanup(func() {
		_ = server.Close(context.Background())
	})
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &consoleHarness{
		server:  server,
		client:  client,
		base:    "http://" + server.Addr(),
		clock:   clock,
		eventID: envelope.ID,
	}
}

func (harness *consoleHarness) request(t *testing.T, input apiRequest) apiResponse {
	t.Helper()
	req, err := http.NewRequest(input.method, harness.base+input.path, strings.NewReader(input.body))
	if err != nil {
		t.Fatal(err)
	}
	if input.token != "" {
		req.Header.Set("Authorization", "Bearer "+input.token)
	}
	if input.authorization != "" {
		req.Header.Set("Authorization", input.authorization)
	}
	if input.cookie != nil {
		req.AddCookie(input.cookie)
	}
	if input.csrf != "" {
		req.Header.Set("X-AegisMesh-CSRF", input.csrf)
	}
	if input.origin != "" {
		req.Header.Set("Origin", input.origin)
	}
	if input.host != "" {
		req.Host = input.host
		req.Header.Set("X-Forwarded-Host", strings.TrimPrefix(harness.base, "http://"))
	}
	contentType := input.contentType
	if contentType == "" && input.body != "" {
		contentType = "application/json"
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	response, err := harness.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body []byte
	// SSE status is flushed before the stream blocks; closing the body cancels it.
	if response.Header.Get("Content-Type") != "text/event-stream" {
		body, err = io.ReadAll(io.LimitReader(response.Body, 2<<20))
		if err != nil {
			t.Fatal(err)
		}
	}
	return apiResponse{
		status:  response.StatusCode,
		body:    body,
		header:  response.Header,
		cookies: response.Cookies(),
	}
}

func requireStatus(t *testing.T, response apiResponse, want int) {
	t.Helper()
	if response.status != want {
		t.Fatalf("status = %d; want %d; body = %s", response.status, want, response.body)
	}
}

func (harness *consoleHarness) login(t *testing.T, previous *http.Cookie) (*http.Cookie, auth.Session) {
	t.Helper()
	response := harness.request(t, apiRequest{
		method: "POST",
		path:   "/api/v1/session",
		body:   `{"token":"synthetic-admin"}`,
		cookie: previous,
	})
	requireStatus(t, response, 200)
	if len(response.cookies) != 1 {
		t.Fatalf("login cookies: %v", response.cookies)
	}
	var session auth.Session
	if err := json.Unmarshal(response.body, &session); err != nil {
		t.Fatal(err)
	}
	return response.cookies[0], session
}
