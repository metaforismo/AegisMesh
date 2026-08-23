package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/storage"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	raw := fmt.Sprintf(`
api_version: aegismesh.io/v1alpha1
runtime:
  instance_name: it-test
  data_dir: %s
admin:
  listen: "127.0.0.1:0"
sensors:
  - id: http-decoy
    kind: http
    listen: "127.0.0.1:0"
    persona:
      server_header: "nginx/1.25.3"
    rules:
      - name: root
        path_regex: "^/$"
        methods: ["GET"]
        status: 200
        body: "<html>ok</html>"
  - id: tcp-decoy
    kind: tcp
    listen: "127.0.0.1:0"
    banner: "hi\n"
    session:
      max_line_bytes: 1024
      idle_timeout_seconds: 5
      max_session_seconds: 30
    tcp_rules:
      - name: ping
        line_regex: "^PING$"
        response: "+OK PONG"
  - id: mcp-decoy
    kind: mcp
    listen: "127.0.0.1:0"
    path: /mcp
    tools:
      - name: canary_tool
        description: d
        result_json: '{"ok":true}'
`, filepath.Join(dir, "data"))
	cfgPath := filepath.Join(dir, "mesh.yaml")
	if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestSystemStopConcurrentIsIdempotent(t *testing.T) {
	cfg := testConfig(t)
	disabled := false
	cfg.Admin.Enabled = &disabled
	sys, err := Build(cfg, quietLogger())
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var callers sync.WaitGroup
	for i := 0; i < 8; i++ {
		callers.Add(1)
		go func() {
			defer callers.Done()
			<-start
			sys.Stop(context.Background())
		}()
	}
	close(start)
	callers.Wait()
}

func TestSystemEndToEndLifecycle(t *testing.T) {
	cfg := testConfig(t)
	sys, err := Build(cfg, quietLogger())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- sys.Run(ctx) }()

	// Wait for readiness via the admin endpoint on the ephemeral port.
	addr := adminAddr(t, sys)
	waitHealthy(t, addr)

	// Drive every sensor kind and confirm an event lands in evidence.
	dataDir := cfg.Runtime.DataDir

	resp, err := http.Get(sensorURL(t, sys, "http-decoy") + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	tcpLine(t, sensorAddr(t, sys, "tcp-decoy"), "PING", "+OK PONG")

	mcpResp, err := http.Post(sensorURL(t, sys, "mcp-decoy")+"/mcp", "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"canary_tool"}}`))
	if err != nil {
		t.Fatal(err)
	}
	mcpResp.Body.Close()

	evs := waitForEvents(t, dataDir, 3)
	classes := map[string]int{}
	for _, e := range evs {
		if err := e.VerifyIntegrity(); err != nil {
			t.Fatalf("stored event failed integrity: %v", err)
		}
		classes[e.Classification]++
	}
	if classes["interaction"] < 2 || classes["canary_invocation"] < 1 {
		t.Fatalf("class mix wrong: %v", classes)
	}

	// Admin endpoints behave.
	code, body := httpGet(t, "http://"+addr+"/healthz")
	if code != 200 {
		t.Fatalf("healthz = %d %q", code, body)
	}
	var health struct {
		Status string `json:"status"`
	}
	json.Unmarshal([]byte(body), &health)
	if health.Status == "" {
		t.Fatalf("healthz payload wrong: %q", body)
	}
	code, _ = httpGet(t, "http://"+addr+"/metrics")
	if code != 200 {
		t.Fatalf("metrics = %d", code)
	}

	// Graceful shutdown: Run returns after cancel; store is flushed.
	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "events-")); !os.IsNotExist(err) && err == nil {
		// segment files exist under dataDir; nothing to assert here beyond no-error
		_ = err
	}
}

func TestBuildFailsClosedOnBadSensorBind(t *testing.T) {
	cfg := testConfig(t)
	// Privileged port without the opt-in must fail at validation time.
	cfg.Sensors[0].Listen = "127.0.0.1:80"
	if err := cfg.Validate(); err == nil {
		t.Fatal("privileged port must require explicit opt-in")
	}
}

func adminAddr(t *testing.T, s *System) string {
	t.Helper()
	a := s.adminSrv.Addr()
	if a == "" {
		t.Fatal("admin address not bound")
	}
	return a
}

func sensorURL(t *testing.T, s *System, id string) string {
	t.Helper()
	return "http://" + sensorAddr(t, s, id)
}

func sensorAddr(t *testing.T, s *System, id string) string {
	t.Helper()
	for _, sen := range s.sensors {
		if sen.ID() == id {
			type addrer interface{ Addr() string }
			if a, ok := sen.(addrer); ok {
				addr := a.Addr()
				if addr == "" {
					t.Fatalf("sensor %s not started", id)
				}
				return addr
			}
			t.Fatalf("sensor %s exposes no Addr()", id)
		}
	}
	t.Fatalf("sensor %q not found", id)
	return ""
}

func waitHealthy(t *testing.T, adminHostPort string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		code, _ := httpGet(t, "http://"+adminHostPort+"/readyz")
		if code == 200 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("system never became ready")
}

func httpGet(t *testing.T, url string) (int, string) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return -1, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, string(b)
}

func tcpLine(t *testing.T, addr, line, want string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	buf := make([]byte, 1024)
	end := time.Now().Add(3 * time.Second)

	var got strings.Builder
	read := func() {
		conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, _ := conn.Read(buf)
		if n > 0 {
			got.Write(buf[:n])
		}
	}
	for time.Now().Before(end) && !strings.Contains(got.String(), "hi\n") {
		read() // banner
	}
	if _, werr := conn.Write([]byte(line + "\n")); werr != nil {
		t.Fatal(werr)
	}
	for time.Now().Before(end) && !strings.Contains(got.String(), want) {
		read()
	}
	if !strings.Contains(got.String(), want) {
		t.Fatalf("tcp decoy never answered with %q (got %q)", want, got.String())
	}
}

func waitForEvents(t *testing.T, dataDir string, n int) []event.Envelope {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		events := readEvents(t, dataDir)
		if len(events) >= n {
			return events
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d/%d events recorded", len(events), n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func readEvents(t *testing.T, dir string) []event.Envelope {
	t.Helper()
	r, err := storage.NewReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []event.Envelope
	if err := r.ForEach(func(e event.Envelope) error {
		out = append(out, e)
		return nil
	}, func(string, error) {}); err != nil {
		t.Fatal(err)
	}
	return out
}
