package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// runHealthcheck invokes the command through the dispatcher exactly like
// production wiring, but with captured output buffers.
func runHealthcheck(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errB bytes.Buffer
	env := &Env{Out: &out, Err: &errB}
	app := NewApp("aegismesh", "local-first deception, detection, and evidence", &out, &errB)
	must(app.Register(NewHealthcheckCmd(env)))
	code := app.Run(context.Background(), append([]string{"healthcheck"}, args...))
	return code, out.String(), errB.String()
}

// writeProbeConfig writes a minimal valid config whose admin listener is
// `listen`. Sensors never run during probes; they exist to satisfy validation.
func writeProbeConfig(t *testing.T, listen string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mesh.yaml")
	if err := os.WriteFile(path, []byte(probeConfigYAML(listen)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func probeConfigYAML(listen string) string {
	return fmt.Sprintf(`
api_version: aegismesh.io/v1alpha1
admin:
  listen: %q
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
`, listen)
}

func startStubAdmin(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func TestHealthcheckLiveAndReadySucceed(t *testing.T) {
	var liveHits, readyHits atomic.Int32
	addr := startStubAdmin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/healthz":
			liveHits.Add(1)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"ok","detail":"SECRET-DETAIL-BODY"}`)
		case "/readyz":
			readyHits.Add(1)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"ready","note":"SECRET-READY-BODY"}`)
		default:
			http.NotFound(w, r)
		}
	})
	cfg := writeProbeConfig(t, addr)

	for _, tc := range []struct{ modeFlag, wantMode, wantPath string }{
		{"--live", "live", "/healthz"},
		{"--ready", "ready", "/readyz"},
	} {
		code, out, stderr := runHealthcheck(t, "--config", cfg, tc.modeFlag)
		if code != 0 {
			t.Fatalf("%s: exit = %d, stderr = %q", tc.modeFlag, code, stderr)
		}
		if lines := strings.Count(out, "\n"); lines != 1 {
			t.Fatalf("%s: stdout must be exactly one line, got %d: %q", tc.modeFlag, lines, out)
		}
		if !strings.Contains(out, "mode="+tc.wantMode) || !strings.Contains(out, "path="+tc.wantPath) {
			t.Fatalf("%s: output missing mode/path: %q", tc.modeFlag, out)
		}
		if strings.Contains(out+stderr, "SECRET") {
			t.Fatalf("%s: response body leaked into output: %q %q", tc.modeFlag, out, stderr)
		}
	}
	if liveHits.Load() != 1 || readyHits.Load() != 1 {
		t.Fatalf("each endpoint must be hit exactly once: live=%d ready=%d",
			liveHits.Load(), readyHits.Load())
	}
}

func TestHealthcheckUnhealthyStatusWithoutLeak(t *testing.T) {
	bigBody := strings.Repeat("A", 128<<10) + "UNHEALTHY-BODY-MARKER"
	addr := startStubAdmin(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, bigBody)
	})
	cfg := writeProbeConfig(t, addr)

	code, out, stderr := runHealthcheck(t, "--config", cfg, "--live")
	if code != 1 {
		t.Fatalf("503 must exit 1, got %d", code)
	}
	if !strings.Contains(stderr, "unhealthy") || !strings.Contains(stderr, "503") {
		t.Fatalf("stderr must name the category and status: %q", stderr)
	}
	if strings.Contains(out+stderr, "UNHEALTHY-BODY-MARKER") {
		t.Fatal("response body must never be echoed")
	}
	if out != "" {
		t.Fatalf("stdout must stay empty on failure: %q", out)
	}
}

func TestHealthcheckReportsTimeout(t *testing.T) {
	addr := startStubAdmin(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
	cfg := writeProbeConfig(t, addr)

	started := time.Now()
	code, _, stderr := runHealthcheck(t, "--config", cfg, "--ready", "--timeout", "50ms")
	if code != 1 {
		t.Fatalf("timeout must exit 1, got %d", code)
	}
	if !strings.Contains(stderr, "timeout") {
		t.Fatalf("stderr must say timeout: %q", stderr)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("probe ran %v; timeout not honored", elapsed)
	}
}

func TestHealthcheckRefusesRedirects(t *testing.T) {
	var readyHits atomic.Int32
	addr := startStubAdmin(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			http.Redirect(w, r, "/readyz", http.StatusFound)
		case "/readyz":
			readyHits.Add(1)
			w.WriteHeader(http.StatusOK)
		}
	})
	cfg := writeProbeConfig(t, addr)

	code, out, stderr := runHealthcheck(t, "--config", cfg, "--live")
	if code != 1 {
		t.Fatalf("redirect must fail the probe, got exit %d", code)
	}
	if !strings.Contains(stderr, "redirect refused") {
		t.Fatalf("stderr must refuse redirects explicitly: %q", stderr)
	}
	if readyHits.Load() != 0 {
		t.Fatalf("redirect target must never be contacted, hits=%d", readyHits.Load())
	}
	if out != "" {
		t.Fatalf("stdout must stay empty on failure: %q", out)
	}
}

func TestHealthcheckIgnoresProxyEnvironment(t *testing.T) {
	addr := startStubAdmin(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	cfg := writeProbeConfig(t, addr)
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(k, "http://127.0.0.1:1")
	}

	code, out, stderr := runHealthcheck(t, "--config", cfg, "--live")
	if code != 0 {
		t.Fatalf("proxy env must be ignored, got exit %d: %q", code, stderr)
	}
	if !strings.Contains(out, "mode=live") {
		t.Fatalf("unexpected success output: %q", out)
	}
}

func TestHealthcheckUsageErrorsExitTwo(t *testing.T) {
	cfg := writeProbeConfig(t, "127.0.0.1:9110")
	cases := []struct {
		name string
		args []string
	}{
		{"no flags", nil},
		{"config only", []string{"--config", cfg}},
		{"missing config value", []string{"--config"}},
		{"both modes", []string{"--config", cfg, "--live", "--ready"}},
		{"zero timeout", []string{"--config", cfg, "--live", "--timeout", "0s"}},
		{"negative timeout", []string{"--config", cfg, "--live", "--timeout", "-1s"}},
		{"over max timeout", []string{"--config", cfg, "--live", "--timeout", "11s"}},
		{"bad timeout", []string{"--config", cfg, "--live", "--timeout", "soon"}},
		{"positional junk", []string{"--config", cfg, "--live", "extra"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, stderr := runHealthcheck(t, tc.args...)
			if code != 2 {
				t.Fatalf("args %v: exit = %d, want 2", tc.args, code)
			}
			if !strings.Contains(out+stderr, "usage") {
				t.Fatalf("usage error must render usage line: out=%q err=%q", out, stderr)
			}
		})
	}
}

func TestHealthcheckConfigFailures(t *testing.T) {
	t.Run("nonexistent file", func(t *testing.T) {
		code, _, stderr := runHealthcheck(t, "--config", "/nonexistent/mesh.yaml", "--live")
		if code != 1 || !strings.Contains(stderr, "config invalid") {
			t.Fatalf("exit=%d stderr=%q", code, stderr)
		}
	})
	t.Run("unknown field", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "bad.yaml")
		os.WriteFile(bad, []byte("api_version: aegismesh.io/v1alpha1\nnope: true\n"), 0o600)
		code, _, stderr := runHealthcheck(t, "--config", bad, "--ready")
		if code != 1 || !strings.Contains(stderr, "config invalid") {
			t.Fatalf("exit=%d stderr=%q", code, stderr)
		}
	})
	t.Run("admin disabled", func(t *testing.T) {
		raw := strings.Replace(probeConfigYAML("127.0.0.1:9110"),
			"admin:\n", "admin:\n  enabled: false\n", 1)
		cfg := filepath.Join(t.TempDir(), "mesh.yaml")
		if err := os.WriteFile(cfg, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		code, _, stderr := runHealthcheck(t, "--config", cfg, "--live")
		if code != 1 || !strings.Contains(stderr, "disabled") {
			t.Fatalf("exit=%d stderr=%q", code, stderr)
		}
	})
	t.Run("non-loopback listener refused by validation", func(t *testing.T) {
		cfg := writeProbeConfig(t, "0.0.0.0:9110")
		code, _, stderr := runHealthcheck(t, "--config", cfg, "--live")
		if code != 1 || !strings.Contains(stderr, "loopback") {
			t.Fatalf("exit=%d stderr=%q", code, stderr)
		}
	})
	t.Run("unsafe listener survives validation bypass", func(t *testing.T) {
		if _, err := loopbackAdminTarget("example.com:443"); err == nil {
			t.Fatal("hostname must be refused")
		}
		if _, err := loopbackAdminTarget("unix:///tmp/a.sock"); err == nil {
			t.Fatal("unix socket path must be refused")
		}
	})
}

func TestLoopbackAdminTarget(t *testing.T) {
	valid := map[string]string{
		"127.0.0.1:9110": "127.0.0.1:9110",
		":9110":          "127.0.0.1:9110",
		"localhost:8080": "localhost:8080",
		"[::1]:9110":     "[::1]:9110",
	}
	for in, want := range valid {
		got, err := loopbackAdminTarget(in)
		if err != nil || got != want {
			t.Fatalf("loopbackAdminTarget(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"", "127.0.0.1", ":0", "127.0.0.1:0", "127.0.0.1:http",
		"127.0.0.1:99999", "0.0.0.0:9110", "[::]:9110", "::1:9110",
		"example.com:443", "unix:///tmp/a.sock", "0.0.0.0:0",
	} {
		if got, err := loopbackAdminTarget(bad); err == nil {
			t.Fatalf("loopbackAdminTarget(%q) = %q; want refusal", bad, got)
		}
	}
}

func TestHealthcheckIPv6EndToEnd(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)

	cfg := writeProbeConfig(t, ln.Addr().String())
	code, out, stderr := runHealthcheck(t, "--config", cfg, "--ready")
	if code != 0 || !strings.Contains(out, "target=[::1]:") {
		t.Fatalf("IPv6 loopback probe failed: code=%d out=%q err=%q", code, out, stderr)
	}
}

func TestHealthcheckWiredIntoRootUsage(t *testing.T) {
	env := &Env{Out: io.Discard, Err: io.Discard}
	app := NewApp("aegismesh", "test", io.Discard, io.Discard)
	must(app.Register(
		NewInitCmd(env), NewDoctorCmd(env), NewHealthcheckCmd(env),
		NewValidateCmd(env), NewRunCmd(env), NewInspectCmd(env),
		NewMigrateCmd(env), NewRulesCmd(env), NewExtCmd(env),
		NewVersionCmd(env), NewCompletionCmd(env),
	))
	var buf bytes.Buffer
	app.PrintUsage(&buf)
	usage := buf.String()
	if !strings.Contains(usage, "\n  healthcheck  ") && !strings.Contains(usage, " healthcheck ") {
		t.Fatalf("root usage must list healthcheck:\n%s", usage)
	}
	if !strings.Contains(NewHealthcheckCmd(env).Help(), "--live") {
		t.Fatal("help must document --live/--ready modes")
	}
}
