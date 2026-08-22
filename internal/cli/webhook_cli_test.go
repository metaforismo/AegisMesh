package cli

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// webhookConfig writes a config file with the webhook section enabled against
// the given loopback collector URL (env-referenced HMAC) and returns its path.
func webhookConfig(t *testing.T, collectorURL string) string {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "mesh.yaml")
	body := fmt.Sprintf(`api_version: aegismesh.io/v1alpha1
webhook:
  enabled: true
  url: %q
  hmac_secret_env: AEGISMESH_TEST_WEBHOOK_HMAC
  allow_loopback_http: true
  queue_size: 32
  batch_size: 2
sensors:
  - id: http-one
    kind: http
    listen: "127.0.0.1:0"
    rules:
      - name: catch-all
        path_regex: "^/.*$"
        status: 200
        body: "ok"
`, collectorURL)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

func TestValidateEffectiveShowsWebhook(t *testing.T) {
	os.Setenv("AEGISMESH_TEST_WEBHOOK_HMAC", "k")
	defer os.Unsetenv("AEGISMESH_TEST_WEBHOOK_HMAC")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfgPath := webhookConfig(t, srv.URL)
	code, out, stderr := run(t, "validate", "--config", cfgPath, "--effective")
	if code != 0 {
		t.Fatalf("effective validation failed: %s%s", out, stderr)
	}
	if !strings.Contains(out, "webhook: ") || !strings.Contains(out, "loopback endpoint (dev mode)") ||
		strings.Contains(out, "UNSIGNED") {
		t.Fatalf("webhook block wrong:\n%s", out)
	}

	var ob, eb strings.Builder
	env := &Env{Out: &ob, Err: &eb}
	app := NewApp("aegismesh", "s", &ob, &eb)
	must(app.Register(NewValidateCmd(env)))
	code = app.Run(context.Background(), []string{"validate", "--config", cfgPath, "--effective", "--json"})
	if code != 0 {
		t.Fatal(eb.String())
	}
	var rep struct {
		Webhook *struct {
			Host   string `json:"host"`
			Signed bool   `json:"signed"`
		} `json:"webhook"`
	}
	if err := json.Unmarshal([]byte(ob.String()), &rep); err != nil {
		t.Fatalf("not pure JSON: %q", ob.String())
	}
	if rep.Webhook == nil || !rep.Webhook.Signed {
		t.Fatalf("webhook summary missing or unsigned: %+v", rep.Webhook)
	}
}

func TestDoctorWebhookReadinessStatesWithoutProbing(t *testing.T) {
	os.Setenv("AEGISMESH_TEST_WEBHOOK_HMAC", "k")
	defer os.Unsetenv("AEGISMESH_TEST_WEBHOOK_HMAC")

	hits := 0
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfgPath := webhookConfig(t, srv.URL)
	code, out, _ := run(t, "doctor", "--config", cfgPath)
	if code != 0 {
		t.Fatal(out)
	}
	if !strings.Contains(out, "[ ok ] webhook") {
		t.Fatalf("expected ready webhook check:\n%s", out)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Fatal("doctor must not contact the collector without --probe-webhook")
	}
}

func TestDoctorWebhookProbeOptIn(t *testing.T) {
	var gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-AegisMesh-Signature")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "wh.key")
	os.WriteFile(keyPath, []byte("file-secret-123"), 0o600)
	cfgPath := webhookConfigNoProbeEnv(t, srv.URL, keyPath)

	code, out, _ := run(t, "doctor", "--config", cfgPath, "--probe-webhook")
	if code != 0 {
		t.Fatal(out)
	}
	if !strings.Contains(out, "[ ok ] webhook-probe") || !strings.Contains(out, "status 204") {
		t.Fatalf("probe result missing:\n%s", out)
	}
	mac := hmac.New(sha256.New, []byte("file-secret-123"))
	mac.Write([]byte(`{"events":[]}`))
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Fatalf("probe signature mismatch: %q", gotSig)
	}

	// Unreachable collector degrades to warn with a redacted URL, never the key.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	badURL := bad.URL
	bad.Close()
	cfgBad := webhookConfigNoProbeEnv(t, badURL+"/blocked", keyPath)
	code, out, _ = run(t, "doctor", "--config", cfgBad, "--probe-webhook")
	if code != 0 || !strings.Contains(out, "[warn] webhook-probe") {
		t.Fatalf("unreachable probe must warn: code=%d\n%s", code, out)
	}
	if strings.Contains(out, "file-secret-123") {
		t.Fatal("probe output leaked key material")
	}
}

func TestDoctorWarnsOnUnsignedWebhook(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "mesh.yaml")
	body := fmt.Sprintf(`api_version: aegismesh.io/v1alpha1
webhook:
  enabled: true
  url: %q
  allow_loopback_http: true
sensors:
  - id: http-one
    kind: http
    listen: "127.0.0.1:0"
    rules:
      - name: catch-all
        path_regex: "^/.*$"
        status: 200
        body: "ok"
`, "http://127.0.0.1:9/events")
	os.WriteFile(cfgPath, []byte(body), 0o600)
	code, out, _ := run(t, "doctor", "--config", cfgPath)
	if code != 0 || !strings.Contains(out, "UNSIGNED batches") {
		t.Fatalf("unsigned webhook must warn:\ncode=%d\n%s", code, out)
	}
}

// webhookConfigNoProbeEnv builds a webhook config whose HMAC comes from a
// file reference (so no env var is involved).
func webhookConfigNoProbeEnv(t *testing.T, collectorURL, keyPath string) string {
	t.Helper()
	dir := filepath.Dir(keyPath)
	cfgPath := filepath.Join(dir, "mesh.yaml")
	body := fmt.Sprintf(`api_version: aegismesh.io/v1alpha1
webhook:
  enabled: true
  url: %q
  hmac_secret_file: ./wh.key
  allow_loopback_http: true
sensors:
  - id: http-one
    kind: http
    listen: "127.0.0.1:0"
    rules:
      - name: catch-all
        path_regex: "^/.*$"
        status: 200
        body: "ok"
`, collectorURL)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}
