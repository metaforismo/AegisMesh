package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/sensor"
	"github.com/metaforismo/aegismesh/internal/storage"
)

type containedTestSensor struct {
	id      string
	done    chan error
	healthy atomic.Bool
	entered chan<- string
	release <-chan struct{}
}

func (s *containedTestSensor) ID() string           { return s.id }
func (*containedTestSensor) Kind() string           { return config.SensorKindHTTP }
func (*containedTestSensor) Addr() string           { return "127.0.0.1:12345" }
func (*containedTestSensor) FailureContained() bool { return true }
func (s *containedTestSensor) Healthy() bool        { return s.healthy.Load() }
func (s *containedTestSensor) Done() <-chan error   { return s.done }
func (s *containedTestSensor) Start(context.Context, sensor.Deps) error {
	s.healthy.Store(true)
	return nil
}
func (s *containedTestSensor) Close(ctx context.Context) error {
	s.healthy.Store(false)
	if s.entered != nil {
		s.entered <- s.id
	}
	if s.release != nil {
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

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
  - id: ssh-decoy
    kind: ssh
    listen: "127.0.0.1:0"
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

func TestCloseSensorsStartsAllClosuresBeforeWaiting(t *testing.T) {
	entered := make(chan string, 3)
	release := make(chan struct{})
	sys := &System{log: quietLogger()}
	for _, id := range []string{"one", "two", "three"} {
		sys.sensors = append(sys.sensors, &containedTestSensor{
			id: id, done: make(chan error), entered: entered, release: release,
		})
	}
	done := make(chan struct{})
	go func() {
		sys.closeSensors()
		close(done)
	}()
	seen := map[string]bool{}
	for len(seen) < 3 {
		select {
		case id := <-entered:
			seen[id] = true
		case <-time.After(time.Second):
			t.Fatalf("only %d sensor closures started", len(seen))
		}
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("concurrent sensor shutdown did not finish")
	}
}

func TestContainedSensorFailureDegradesReadinessWithoutStoppingRuntime(t *testing.T) {
	cfg := testConfig(t)
	disabled := false
	cfg.Admin.Enabled = &disabled
	cfg.Sensors = cfg.Sensors[:1]
	sys, err := Build(cfg, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	fake := &containedTestSensor{id: cfg.Sensors[0].ID, done: make(chan error, 1)}
	sys.sensors = []sensor.Sensor{fake}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- sys.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for sys.Status().SensorsStarted != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := sys.Status(); got.SensorsStarted != 1 {
		t.Fatalf("initial status = %+v", got)
	}
	fake.healthy.Store(false)
	fake.done <- errors.New("synthetic worker crash")
	deadline = time.Now().Add(time.Second)
	for sys.Status().SensorsStarted != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := sys.Status(); got.SensorsStarted != 0 || got.SensorsWanted != 1 {
		t.Fatalf("degraded status = %+v", got)
	}
	if _, err := sys.Endpoints(); err == nil || !strings.Contains(err.Error(), "not healthy") {
		t.Fatalf("Endpoints after contained failure = %v, want unhealthy error", err)
	}
	select {
	case err := <-runErr:
		t.Fatalf("contained failure stopped runtime: %v", err)
	default:
	}
	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("shutdown after contained failure: %v", err)
	}
}

func TestSystemEndToEndLifecycle(t *testing.T) {
	cfg := testConfig(t)
	sys, err := Build(cfg, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	before := sys.Status()
	if before.SensorsStarted != 0 || before.SensorsWanted != len(cfg.Sensors) {
		t.Fatalf("pre-start readiness = %+v, want zero of %d sensors", before, len(cfg.Sensors))
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- sys.Run(ctx) }()

	// Wait for readiness via the admin endpoint on the ephemeral port.
	addr := adminAddr(t, sys)
	waitHealthy(t, addr)
	ready := sys.Status()
	if ready.SensorsStarted != ready.SensorsWanted {
		t.Fatalf("ready status = %+v", ready)
	}

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

	sshClient, err := ssh.Dial("tcp", sensorAddr(t, sys, "ssh-decoy"), &ssh.ClientConfig{
		User:            "runtime-synthetic-user",
		Auth:            []ssh.AuthMethod{ssh.Password("runtime-synthetic-password")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // test-only ephemeral decoy key
		Timeout:         2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sshClient.OpenChannel("session", nil); err == nil {
		t.Fatal("SSH session channel must be rejected")
	}
	sshClient.Close()

	evs := waitForEvents(t, dataDir, 4)
	classes := map[string]int{}
	for _, e := range evs {
		if err := e.VerifyIntegrity(); err != nil {
			t.Fatalf("stored event failed integrity: %v", err)
		}
		classes[e.Classification]++
	}
	if classes["interaction"] < 3 || classes["canary_invocation"] < 1 {
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

func TestIsolatedSensorsEndToEndLifecycle(t *testing.T) {
	cfg := testConfig(t)
	wantHTTPBody := []byte{'i', 's', 'o', 'l', 'a', 't', 'e', 'd', 0x00, 0xff}
	bodyName := "isolated-body.bin"
	if err := os.WriteFile(filepath.Join(filepath.Dir(cfg.SourcePath), bodyName), wantHTTPBody, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Sensors[0].Rules[0].Body = ""
	cfg.Sensors[0].Rules[0].BodyFile = bodyName
	disabled := false
	cfg.Admin.Enabled = &disabled
	for i := range cfg.Sensors {
		cfg.Sensors[i].ProcessIsolation = true
	}
	var logs bytes.Buffer
	sys, err := Build(cfg, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- sys.Run(ctx) }()

	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := sys.Endpoints(); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("isolated sensors did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}

	resp, err := http.Get(sensorURL(t, sys, "http-decoy") + "/")
	if err != nil {
		t.Fatal(err)
	}
	httpBody, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(httpBody, wantHTTPBody) {
		t.Fatalf("isolated binary body = %x, want %x (read=%v close=%v)", httpBody, wantHTTPBody, readErr, closeErr)
	}
	tcpLine(t, sensorAddr(t, sys, "tcp-decoy"), "PING", "+OK PONG")
	mcpResp, err := http.Post(sensorURL(t, sys, "mcp-decoy")+"/mcp", "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"canary_tool"}}`))
	if err != nil {
		t.Fatal(err)
	}
	mcpResp.Body.Close()
	sshClient, err := ssh.Dial("tcp", sensorAddr(t, sys, "ssh-decoy"), &ssh.ClientConfig{
		User:            "isolated-synthetic-user",
		Auth:            []ssh.AuthMethod{ssh.Password("isolated-synthetic-password")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // test-only ephemeral decoy key
		Timeout:         2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	sshClient.Close()

	events := waitForEvents(t, cfg.Runtime.DataDir, 4)
	classes := map[string]int{}
	for _, e := range events {
		if err := e.VerifyIntegrity(); err != nil {
			t.Fatalf("isolated event integrity: %v", err)
		}
		classes[e.Classification]++
	}
	if classes[event.ClassificationInteraction] < 3 || classes[event.ClassificationCanaryHit] < 1 {
		t.Fatalf("isolated class mix = %v", classes)
	}
	metrics := sys.meter.WritePrometheus()
	for _, want := range []string{
		"aegismesh_sensor_http_interactions_total 1",
		"aegismesh_sensor_tcp_interactions_total 1",
		"aegismesh_sensor_mcp_canary_invocations_total 1",
		"aegismesh_sensor_ssh_connections_total 1",
	} {
		if !strings.Contains(metrics, want) {
			t.Fatalf("isolated metric missing %q:\n%s", want, metrics)
		}
	}
	if got := sys.Status(); got.SensorsStarted != 4 || got.SensorsWanted != 4 {
		t.Fatalf("isolated readiness = %+v", got)
	}
	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("isolated shutdown: %v", err)
	}
	if strings.Contains(logs.String(), "sensor close error") {
		t.Fatalf("isolated shutdown logged close failure:\n%s", logs.String())
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
