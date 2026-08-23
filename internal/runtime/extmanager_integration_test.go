package runtime

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/ext"
)

// buildAckerExtension compiles the acker fixture and writes a manifest next
// to it. Returns the manifest path.
func buildAckerExtension(t *testing.T, callTimeoutMS int) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping go build in -short mode")
	}
	dir := t.TempDir()
	exePath := filepath.Join(dir, "observer")
	cmd := exec.Command("go", "build", "-o", exePath, ".") //nolint:gosec // fixed test fixture path
	cmd.Dir = filepath.Join("..", "extmanager", "testdata", "observer-acker")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build observer fixture: %v\n%s", err, b)
	}
	bin, err := os.ReadFile(exePath)
	if err != nil {
		t.Fatal(err)
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(bin))
	m := &ext.Manifest{
		APIVersion:  "ext.aegismesh.io/v1alpha1",
		Name:        "obs-acker",
		Version:     "1.0.0",
		Description: "synthetic acking observer",
		Permissions: []string{"observe"},
		Transport: ext.Transport{
			Kind:               "subprocess-ndjson",
			Command:            []string{"./observer"},
			HandshakeTimeoutMS: 5000,
			CallTimeoutMS:      callTimeoutMS,
			MaxOutputBytes:     1 << 20,
		},
		Digest: ext.Digest{Algorithm: "sha256", Value: sum},
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	mp := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(mp, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return mp
}

func TestSystemDeliversObservationsToExtension(t *testing.T) {
	manifestPath := buildAckerExtension(t, 2000)
	extDir := filepath.Dir(manifestPath)

	cfg := testConfigWithExtensions(t, manifestPath)
	sys, err := Build(cfg, quietLogger())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- sys.Run(ctx) }()

	addr := adminAddr(t, sys)
	waitHealthy(t, addr)

	// Extensions start before sensors, so admin health precedes decoy
	// readiness by design; poll for the listener rather than assume.
	var url string
	waitForCondition(t, startTimeout+2*time.Second, func() bool {
		for _, sen := range sys.sensors {
			if sen.ID() != "http-decoy" {
				continue
			}
			type addrer interface{ Addr() string }
			if a, ok := sen.(addrer); ok && a.Addr() != "" {
				url = "http://" + a.Addr() + "/"
				return true
			}
		}
		return false
	}, "http decoy listener")
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	select {
	case err := <-runErr:
		t.Fatalf("Run exited early: %v", err)
	default:
	}

	// The extension records every delivered observation in its cwd.
	received := filepath.Join(extDir, "received.ndjson")
	waitForCondition(t, 8*time.Second, func() bool {
		b, err := os.ReadFile(received)
		return err == nil && len(strings.TrimSpace(string(b))) > 0
	}, "observation delivery to extension")

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return after cancel with extensions enabled")
	}
}

func TestBuildFailsClosedOnMissingExtensionManifest(t *testing.T) {
	cfg := testConfigWithExtensions(t, filepath.Join(t.TempDir(), "missing.json"))
	if _, err := Build(cfg, quietLogger()); err == nil || !strings.Contains(err.Error(), "missing.json") {
		t.Fatalf("Build must fail closed on a missing manifest, got: %v", err)
	}
}

func TestBuildFailsClosedOnRespondOnlyExtension(t *testing.T) {
	mp := buildAckerExtension(t, 2000)
	raw, _ := os.ReadFile(mp)
	var m ext.Manifest
	json.Unmarshal(raw, &m)
	m.Permissions = []string{"respond"}
	out, _ := json.Marshal(m)
	p2 := filepath.Join(filepath.Dir(mp), "respond-only.json")
	os.WriteFile(p2, out, 0o600)

	cfg := testConfigWithExtensions(t, p2)
	if _, err := Build(cfg, quietLogger()); err == nil || !strings.Contains(err.Error(), "observe permission") {
		t.Fatalf("respond-only manifests must be refused, got: %v", err)
	}
}

func testConfigWithExtensions(t *testing.T, manifestPath string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	_ = dataDir
	base := testConfig(t)
	base.Extensions = config.Extensions{
		Enabled:              boolPtr(true),
		Manifests:            []string{manifestPath},
		QueueSize:            config.DefaultExtensionQueueSize,
		ShutdownFlushSeconds: config.DefaultExtensionFlushSecs,
	}
	return base
}

func boolPtr(b bool) *bool { return &b }

func waitForCondition(t *testing.T, d time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestSystemStreamsEvidenceToWebhook proves the full fan-out path: decoy hit
// → bus → evidence store AND HMAC-signed batch to an httptest collector.
func TestSystemStreamsEvidenceToWebhook(t *testing.T) {
	if testing.Short() {
		t.Skip("uses subprocess-free httptest but full system; keep in short suites")
	}
	var mu sync.Mutex
	received := 0
	var lastSig string
	secret := "e2e-webhook-secret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = io.ReadFull(r.Body, body)
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(r.Header.Get("X-AegisMesh-Signature")), []byte(want)) {
			t.Errorf("bad signature")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		lastSig = r.Header.Get("X-AegisMesh-Signature")
		mu.Lock()
		received++
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	dir := t.TempDir()
	raw := fmt.Sprintf(`
api_version: aegismesh.io/v1alpha1
runtime:
  instance_name: webhook-e2e
  data_dir: %s
admin:
  listen: "127.0.0.1:0"
webhook:
  enabled: true
  url: %q
  hmac_secret_file: ./wh.key
  allow_loopback_http: true
  queue_size: 16
  batch_size: 2
  flush_interval_seconds: 1
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
`, filepath.Join(dir, "data"), srv.URL)
	os.WriteFile(filepath.Join(dir, "wh.key"), []byte(secret), 0o600)
	cfgPath := filepath.Join(dir, "mesh.yaml")
	os.WriteFile(cfgPath, []byte(raw), 0o600)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	sys, err := Build(cfg, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- sys.Run(ctx) }()

	addr := adminAddr(t, sys)
	waitHealthy(t, addr)

	var url string
	waitForCondition(t, startTimeout+2*time.Second, func() bool {
		for _, sen := range sys.sensors {
			if sen.ID() != "http-decoy" {
				continue
			}
			type addrer interface{ Addr() string }
			if a, ok := sen.(addrer); ok && a.Addr() != "" {
				url = "http://" + a.Addr() + "/"
				return true
			}
		}
		return false
	}, "http decoy listener")
	resp, err := http.Get(url) //nolint:noctx // test-local loopback probe
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := received
		mu.Unlock()
		if n >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if received < 1 {
		t.Fatal("collector never received the evidence batch")
	}
	if lastSig == "" {
		t.Fatal("signature header missing on delivered batch")
	}

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return after cancel (webhook shutdown bound?)")
	}
}

func TestBuildFailsClosedOnUnresolvableWebhookSecret(t *testing.T) {
	dir := t.TempDir()
	raw := fmt.Sprintf(`
api_version: aegismesh.io/v1alpha1
runtime:
  instance_name: wh-fail
  data_dir: %s
webhook:
  enabled: true
  url: "https://collector.example.com/e"
  hmac_secret_env: AEGISMESH_DEFINITELY_UNSET_VAR_42
sensors:
  - id: http-one
    kind: http
    listen: "127.0.0.1:0"
    rules:
      - name: catch-all
        path_regex: "^/.*$"
        status: 200
        body: "ok"
`, filepath.Join(dir, "data"))
	cfgPath := filepath.Join(dir, "mesh.yaml")
	os.WriteFile(cfgPath, []byte(raw), 0o600)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Build(cfg, quietLogger()); err == nil || !strings.Contains(err.Error(), "empty or unset") {
		t.Fatalf("unresolvable secret must fail startup: %v", err)
	}
}
