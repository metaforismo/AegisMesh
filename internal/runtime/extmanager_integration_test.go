package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
			HandshakeTimeoutMS: 2000,
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
	waitForCondition(t, 10*time.Second, func() bool {
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
