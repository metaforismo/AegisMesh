package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
)

func indicatorFixture(t *testing.T) string {
	t.Helper()
	fixture, err := os.ReadFile(filepath.Join("testdata", "recommend.event.json"))
	if err != nil {
		t.Fatal(err)
	}
	var e event.Envelope
	if err := json.Unmarshal(fixture, &e); err != nil {
		t.Fatal(err)
	}
	e.Time = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	e.Observation = json.RawMessage(`{"method":"GET","path":"/v1/models","remote_host":"192.0.2.8","detection":{"action":"observe","findings":[{"rule_id":"LLM-001"}]}}`)
	// Only observation payload consistency is asserted by the native hash.
	e.Integrity.PayloadSHA256 = event.SHA256Hex(e.Observation)
	line, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "events-fixture.jsonl"), append(line, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestIndicatorExportCLIGolden(t *testing.T) {
	dir := indicatorFixture(t)
	for _, format := range []string{"csv", "txt", "stix"} {
		t.Run(format, func(t *testing.T) {
			code, output, stderr := run(t, "export", "indicators", "--data-dir", dir, "--format", format)
			if code != 0 || !strings.Contains(stderr, "scanned 1 event(s); selected 1; skipped non-IP source keys: 0") {
				t.Fatal(code, stderr)
			}
			path := filepath.Join("testdata", "indicators.golden."+format)
			if os.Getenv("AEGISMESH_UPDATE_INDICATOR_GOLDENS") == "1" {
				if err := os.WriteFile(path, []byte(output), 0600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil || output != string(want) {
				t.Fatalf("golden drift %s: %v\n%s", path, err, output)
			}
		})
	}
}

func TestIndicatorCLIArgumentsAndSince(t *testing.T) {
	dir := indicatorFixture(t)
	for _, args := range [][]string{
		{}, {"other"}, {"indicators"}, {"indicators", "--format", "csv"},
		{"indicators", "--data-dir", dir, "--format", "json"},
		{"indicators", "--data-dir", dir, "--format", "txt", "--since", "bad"},
		{"indicators", "--data-dir", dir, "--format", "txt", "--format", "csv"},
		{"indicators", "--data-dir", dir, "--format", "txt", "--since", "2026-01-01T00:00:00Z", "--since", "2026-01-02T00:00:00Z"},
		{"indicators", "--data-dir", dir, "--format", "txt", "extra"},
	} {
		if code, _, _ := run(t, append([]string{"export"}, args...)...); code != 2 {
			t.Errorf("args=%v code=%d", args, code)
		}
	}
	code, out, stderr := run(t, "export", "indicators", "--data-dir", dir, "--format", "txt", "--since", "2026-01-03T00:00:00Z")
	if code != 0 || strings.Contains(out, "192.0.2.8") || !strings.Contains(stderr, "selected 0") {
		t.Fatal(code, out, stderr)
	}
	code, out, _ = run(t, "export", "indicators", "--data-dir", dir, "--format", "txt", "--since", "2026-01-02T03:04:05Z")
	if code != 0 || !strings.Contains(out, "192.0.2.8") {
		t.Fatal("inclusive since", code, out)
	}
}

func TestIndicatorCLIReadFailsClosed(t *testing.T) {
	for _, mode := range []string{"corrupt", "tampered", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			dir := indicatorFixture(t)
			path := filepath.Join(dir, "events-fixture.jsonl")
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "corrupt":
				body = append(body, []byte("{not JSON}\n")...)
			case "tampered":
				body = bytes.ReplaceAll(body, []byte("192.0.2.8"), []byte("192.0.2.9"))
			case "oversized":
				body = bytes.Repeat(body, 8193)
			}
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			code, out, stderr := run(t, "export", "indicators", "--data-dir", dir, "--format", "txt")
			if code != 1 || out != "" || stderr == "" {
				t.Fatal("partial export", code, len(out), stderr)
			}
		})
	}
}
