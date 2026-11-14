package runtime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console"
	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/storage"
)

func consoleConfig(t *testing.T) *config.Config {
	cfg := testConfig(t)
	cfg.Sensors = cfg.Sensors[:1]
	cfg.Console.Enabled = true
	cfg.Console.Listen = "127.0.0.1:0"
	cfg.Console.SessionTTLSeconds = 60
	for _, role := range []string{
		"viewer",
		"analyst",
		"admin",
	} {
		cfg.Console.Operators = append(cfg.Console.Operators, config.Operator{
			Name:        role,
			Role:        role,
			TokenSHA256: auth.Digest("synthetic-" + role),
		})
	}

	return cfg
}

func consoleSystem(t *testing.T, cfg *config.Config) (*System, string) {
	t.Helper()
	system, err := Build(cfg, quietLogger())
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		system.Stop(context.Background())
	})
	if err = system.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	addr, err := system.ConsoleAddr()
	if err != nil {
		t.Fatal(err)
	}

	return system, "http://" + addr
}

type apiResponse struct {
	status  int
	body    []byte
	header  http.Header
	cookies []*http.Cookie
}

func callAPI(t *testing.T, base, method, path, token, body string, cookie *http.Cookie, csrf string) apiResponse {
	t.Helper()
	request, err := http.NewRequest(method, base+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	if cookie != nil {
		request.AddCookie(cookie)
	}

	if csrf != "" {
		request.Header.Set("X-AegisMesh-CSRF", csrf)
	}

	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}

	defer response.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		t.Fatal(err)
	}

	return apiResponse{
		status:  response.StatusCode,
		body:    responseBody,
		header:  response.Header,
		cookies: response.Cookies(),
	}
}

func loginAPI(t *testing.T, base string) (*http.Cookie, string) {
	t.Helper()
	response := callAPI(t, base, "POST", "/api/v1/session", "", `{"token":"synthetic-admin"}`, nil, "")
	if response.status != 200 || len(response.cookies) != 1 {
		t.Fatalf("login: %d %s", response.status, response.body)
	}

	var session auth.Session
	if err := json.Unmarshal(response.body, &session); err != nil {
		t.Fatal(err)
	}

	return response.cookies[0], session.CSRFToken
}

func TestConsoleRuntimeHTTPFlow(t *testing.T) {
	cfg := consoleConfig(t)
	system, base := consoleSystem(t, cfg)
	cookie, csrf := loginAPI(t, base)
	response := callAPI(t, base, "POST", "/api/v1/investigations", "", `{"title":"Operator review"}`, cookie, csrf)
	if response.status != 201 {
		t.Fatalf("create: %d %s", response.status, response.body)
	}

	var investigation struct {
		ID string `json:"id"`
	}

	if err := json.Unmarshal(response.body, &investigation); err != nil {
		t.Fatal(err)
	}
	endpoints, err := system.Endpoints()
	if err != nil {
		t.Fatal(err)
	}

	streamCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	request, _ := http.NewRequestWithContext(streamCtx, "GET", base+"/api/v1/events/stream", nil)
	request.Header.Set("Authorization", "Bearer synthetic-admin")
	stream, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}

	defer stream.Body.Close()

	if stream.StatusCode != 200 {
		t.Fatal(stream.StatusCode)
	}

	sensorResponse, err := http.Get("http://" + endpoints[0].Addr + "/")
	if err != nil {
		t.Fatal(err)
	}

	sensorResponse.Body.Close()
	got := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stream.Body)
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), "data: ") {
				got <- strings.TrimPrefix(scanner.Text(), "data: ")
				return
			}
		}
		got <- ""
	}()
	var summary struct {
		ID string `json:"id"`
	}

	select {
	case data := <-got:
		if json.Unmarshal([]byte(data), &summary) != nil || len(summary.ID) != 32 {
			t.Fatalf("SSE: %s", data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SSE did not receive stored sensor event")
	}

	cancel()
	for _, testCase := range []struct {
		method, path, body string
		status             int
	}{
		{
			method: "GET",
			path:   "/api/v1/events?source=127.0.0.1&kind=http&limit=1",
			body:   "",
			status: 200,
		},
		{
			method: "GET",
			path:   "/api/v1/events/" + summary.ID,
			body:   "",
			status: 200,
		},
		{
			method: "GET",
			path:   "/api/v1/overview",
			body:   "",
			status: 200,
		},
		{
			method: "GET",
			path:   "/api/v1/node",
			body:   "",
			status: 200,
		},
		{
			method: "GET",
			path:   "/api/v1/sources/127.0.0.1",
			body:   "",
			status: 200,
		},
		{
			method: "GET",
			path:   "/api/v1/sensors",
			body:   "",
			status: 200,
		},
		{
			method: "GET",
			path:   "/api/v1/rules",
			body:   "",
			status: 200,
		},
		{
			method: "GET",
			path:   "/api/v1/recommendations",
			body:   "",
			status: 200,
		},
		{
			method: "PATCH",
			path:   "/api/v1/investigations/" + investigation.ID,
			body:   `{"status":"monitoring","priority":"high"}`,
			status: 200,
		},
		{
			method: "POST",
			path:   "/api/v1/investigations/" + investigation.ID + "/notes",
			body:   `{"text":"Synthetic operator note"}`,
			status: 201,
		},
		{
			method: "PUT",
			path:   "/api/v1/investigations/" + investigation.ID + "/events/" + summary.ID,
			body:   "",
			status: 200,
		},
		{
			method: "GET",
			path:   "/api/v1/investigations/" + investigation.ID,
			body:   "",
			status: 200,
		},
		{
			method: "DELETE",
			path:   "/api/v1/investigations/" + investigation.ID + "/events/" + summary.ID,
			body:   "",
			status: 200,
		},
		{
			method: "GET",
			path:   "/api/v1/audit?limit=2",
			body:   "",
			status: 200,
		},
		{
			method: "GET",
			path:   "/api/v1/audit/verify",
			body:   "",
			status: 200,
		},
	} {
		response := callAPI(t, base, testCase.method, testCase.path, "", testCase.body, cookie, csrf)
		if response.status != testCase.status {
			t.Errorf("%s %s: %d %s", testCase.method, testCase.path, response.status, response.body)
		}
		if testCase.path == "/api/v1/audit/verify" && !bytes.Contains(response.body, []byte(`"verified":true`)) {
			t.Fatal("chain invalid", string(response.body))
		}
		if testCase.path == "/api/v1/events/"+summary.ID && !bytes.Contains(response.body, []byte(`"verified":true`)) {
			t.Fatal("integrity invalid")
		}
	}

	auditBytes, err := os.ReadFile(filepath.Join(cfg.ConsoleStateDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}

	for _, secret := range []string{
		cookie.Value,
		csrf,
		"synthetic-admin",
		"Synthetic operator note",
	} {
		if bytes.Contains(auditBytes, []byte(secret)) {
			t.Fatal("secret or note body in audit")
		}
	}

	system.Stop(context.Background())
	if _, err = http.Get(base + "/api/v1/meta"); err == nil {
		t.Fatal("listener survived stop")
	}
}

func TestConsoleServesEmbeddedUI(t *testing.T) {
	_, base := consoleSystem(t, consoleConfig(t))

	index := callAPI(t, base, "GET", "/", "", "", nil, "")
	if index.status != http.StatusOK {
		t.Fatalf("GET /: status %d: %s", index.status, index.body)
	}

	if got := index.header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("GET / content type = %q", got)
	}

	if got := index.header.Get("Content-Security-Policy"); got != console.CSP {
		t.Fatalf("GET / CSP = %q", got)
	}

	if got := index.header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("GET / Cache-Control = %q, want no-store", got)
	}

	if !bytes.Contains(index.body, []byte(`<div id="app"`)) {
		t.Fatalf("GET / does not contain the app root: %s", index.body)
	}

	// The entry script comes from the page itself, so a rename cannot leave this stale.
	const marker = `<script type="module" src="`
	start := bytes.Index(index.body, []byte(marker))
	if start < 0 {
		t.Fatalf("index.html references no module script: %s", index.body)
	}

	rest := index.body[start+len(marker):]
	end := bytes.IndexByte(rest, '"')
	if end < 0 {
		t.Fatalf("unterminated script reference: %s", rest)
	}

	script := callAPI(t, base, "GET", "/"+string(rest[:end]), "", "", nil, "")
	if script.status != http.StatusOK {
		t.Fatalf("GET %s: status %d", rest[:end], script.status)
	}

	if got := script.header.Get("Content-Type"); !strings.Contains(got, "javascript") {
		t.Fatalf("script content type = %q", got)
	}

	if got := script.header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("script nosniff = %q", got)
	}

	// Serving the UI must not make the API public.
	overview := callAPI(t, base, "GET", "/api/v1/overview", "", "", nil, "")
	if overview.status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated overview status = %d", overview.status)
	}
}

func TestConsoleEncryptedLiveOnlyAndBackfill(t *testing.T) {
	for _, encrypted := range []bool{
		false,
		true,
	} {
		t.Run(fmt.Sprint(encrypted), func(t *testing.T) {
			cfg := consoleConfig(t)
			if encrypted {
				id, err := age.GenerateX25519Identity()
				if err != nil {
					t.Fatal(err)
				}
				cfg.Storage.Encryption = &config.StorageEncryption{
					Enabled:   true,
					Recipient: id.Recipient().String(),
				}
			}
			opts := storage.Options{
				Dir:           cfg.Runtime.DataDir,
				MaxFileBytes:  cfg.Storage.MaxFileBytes,
				MaxEventBytes: cfg.Storage.MaxEventBytes,
			}
			if encrypted {
				opts.Encryption = &storage.EncryptionOptions{Recipient: cfg.Storage.Encryption.Recipient}
			}
			store, err := storage.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := event.New(&event.Sequencer{}, "test", event.SensorRef{
				ID:   "web",
				Kind: "http",
			}, "interaction", json.RawMessage(`{"remote_host":"2001:db8::1/key"}`), nil)
			if err != nil {
				t.Fatal(err)
			}
			if err = store.Append(context.Background(), envelope); err != nil {
				t.Fatal(err)
			}
			store.Close()
			system, base := consoleSystem(t, cfg)
			response := callAPI(t, base, "GET", "/api/v1/node", "synthetic-admin", "", nil, "")
			var node struct {
				Storage struct {
					Encrypted bool `json:"encrypted"`
				} `json:"storage"`
				Index struct {
					History string `json:"history"`
					Events  int    `json:"events"`
				} `json:"index"`
			}
			if err := json.Unmarshal(response.body, &node); err != nil {
				t.Fatal(err)
			}
			want := "complete"
			count := 1
			if encrypted {
				want = "unavailable"
				count = 0
			}
			if node.Index.History != want || node.Index.Events != count || node.Storage.Encrypted != encrypted {
				t.Fatalf("node: %s", response.body)
			}
			if !encrypted {
				response := callAPI(t, base, "GET", "/api/v1/sources/"+url.PathEscape("2001:db8::1/key"), "synthetic-admin", "", nil, "")
				if response.status != 200 {
					t.Fatalf("encoded source: %d %s", response.status, response.body)
				}
			}
			// A direct correlation append uses the shared tap and does not feed the bus.
			signal, err := event.New(system.seq, "test", event.SensorRef{
				ID:   "correlate",
				Kind: "correlation",
			}, "correlation_signal", json.RawMessage(`{"rule_id":"COR-001","source_key":"synthetic","source_event_ids":[]}`), nil)
			if err != nil {
				t.Fatal(err)
			}
			sink := &indexedSink{
				primary: system.store,
				index:   system.index,
			}
			if err = sink.Append(context.Background(), signal); err != nil {
				t.Fatal(err)
			}
			if _, _, _, _, ok := system.index.Get(signal.ID); !ok {
				t.Fatal("direct signal not indexed")
			}
			system.store.Close()
			failed, _ := event.New(system.seq, "test", event.SensorRef{
				ID:   "web",
				Kind: "http",
			}, "interaction", json.RawMessage(`{}`), nil)
			if err = sink.Append(context.Background(), failed); err == nil {
				t.Fatal("closed store accepted append")
			}
			if _, _, _, _, ok := system.index.Get(failed.ID); ok {
				t.Fatal("failed append reached index")
			}
		})
	}
}

func TestConsoleFailsClosedBeforeSensors(t *testing.T) {
	for _, bad := range []string{
		"operators",
		"state",
		"tls",
		"bind",
	} {
		t.Run(bad, func(t *testing.T) {
			cfg := consoleConfig(t)
			switch bad {
			case "operators":
				cfg.Console.Operators = nil
			case "state":
				cfg.Console.StateDir = filepath.Join(t.TempDir(), "file")
				os.WriteFile(cfg.Console.StateDir, []byte("data"), 0600)
			case "tls":
				cfg.Console.TLSCertFile = "missing"
				cfg.Console.TLSKeyFile = "missing"
			case "bind":
				cfg.Console.Listen = "invalid"
			}
			if system, err := Build(cfg, quietLogger()); err == nil {
				system.Stop(context.Background())
				t.Fatal("unsafe console started")
			}
		})
	}
}

func TestConsoleCorrelationSignalsUseSharedTap(t *testing.T) {
	cfg := consoleConfig(t)
	yes := true
	cfg.Correlation.Enabled = &yes
	system, base := consoleSystem(t, cfg)
	for range 3 {
		envelope, err := event.New(system.seq, "test", event.SensorRef{
			ID:   "http-decoy",
			Kind: "http",
		}, "interaction", json.RawMessage(`{"remote_host":"203.0.113.50","detection":{"findings":[{"rule_id":"PI-001"}]}}`), nil)
		if err != nil {
			t.Fatal(err)
		}
		if !system.bus.Submit(envelope) {
			t.Fatal("submit failed")
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		response := callAPI(t, base, "GET", "/api/v1/events?classification=correlation_signal", "synthetic-admin", "", nil, "")
		var page struct {
			Events []struct {
				ID string `json:"id"`
			} `json:"events"`
		}
		if err := json.Unmarshal(response.body, &page); err != nil {
			t.Fatal(err)
		}
		if len(page.Events) > 0 {
			detail := callAPI(t, base, "GET", "/api/v1/events/"+page.Events[0].ID, "synthetic-admin", "", nil, "")
			var detailBody struct {
				Related []json.RawMessage `json:"related"`
			}
			if err := json.Unmarshal(detail.body, &detailBody); err != nil {
				t.Fatal(err)
			}
			if len(detailBody.Related) != 3 {
				t.Fatalf("signal provenance: %s", detail.body)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("correlation bypassed index")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if system.corr.Stats().FiredSignals != 1 {
		t.Fatal("signal recursively re-entered correlation")
	}
}
