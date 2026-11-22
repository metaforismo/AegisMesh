package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/digest"
)

func TestEventExportCLIAndStaging(t *testing.T) {
	dir := indicatorFixture(t)
	for _, format := range []string{"cef", "syslog-rfc5424", "otlp-json", "ecs"} {
		code, body, stderr := run(t, "export", "events", "--data-dir", dir, "--format", format)
		if code != 0 || !strings.Contains(stderr, "scanned 1 event(s); selected 1") || len(body) == 0 {
			t.Fatal(format, code, stderr)
		}
		path := filepath.Join(t.TempDir(), "export")
		code, output, stderr := run(t, "export", "events", "--data-dir", dir, "--format", format, "--out", path)
		saved, err := os.ReadFile(path)
		if code != 0 || output != "" || err != nil || string(saved) != body {
			t.Fatal(code, stderr, err)
		}
		code, _, _ = run(t, "export", "events", "--data-dir", dir, "--format", format, "--out", path)
		if code != 1 {
			t.Fatal("overwrote output")
		}
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0600 {
			t.Fatal("nonprivate output")
		}
	}
	for _, args := range [][]string{
		{"--data-dir", dir, "--format", "bad"}, {"--data-dir", dir, "--format", "cef", "--format", "ecs"},
		{"--data-dir", dir, "--format", "cef", "--out", ""}, {"--data-dir", dir, "--format", "cef", "--since", "bad"},
		{"--format", "ecs"}, {"--data-dir", dir, "--format", "cef", "positional"},
	} {
		if code, _, _ := run(t, append([]string{"export", "events"}, args...)...); code != 2 {
			t.Fatal(args, code)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "events-bad.jsonl"), []byte("broken\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "must-not-exist")
	code, body, _ := run(t, "export", "events", "--data-dir", dir, "--format", "cef", "--out", out)
	if code != 1 || body != "" {
		t.Fatal("partial corrupt export")
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatal("output created before validation")
	}
}

func TestDigestCLIArgumentsAndAvailability(t *testing.T) {
	dir := indicatorFixture(t)
	for _, format := range []string{"json", "md"} {
		code, body, stderr := run(t, "digest", "--since", "24h", "--format", format, "--data-dir", dir)
		if code != 0 {
			t.Fatal(code, stderr)
		}
		if format == "json" {
			var report digest.Report
			if json.Unmarshal([]byte(body), &report) != nil || report.Window != "24h" || report.OpenInvestigations != nil || report.Limits.InvestigationsAvailable || report.Bounds.Scanned != 1 {
				t.Fatal(body)
			}
		} else if !strings.Contains(body, "## Limits") {
			t.Fatal(body)
		}
	}
	for _, args := range [][]string{{}, {"--since", "1h"}, {"--since", "24h", "--since", "7d"}, {"--since", "7d", "--format", "bad"}, {"--since", "7d", "--format", "json", "--format", "md"}, {"--since", "7d", "extra"}} {
		if code, _, _ := run(t, append([]string{"digest"}, args...)...); code != 2 {
			t.Fatal(args, code)
		}
	}
	state := t.TempDir()
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	code, body, stderr := run(t, "digest", "--since", "7d", "--format", "json", "--data-dir", dir, "--investigations-dir", state)
	if code != 0 || !strings.Contains(body, `"open_investigations": 0`) {
		t.Fatal(body, stderr)
	}
	if entries, err := os.ReadDir(state); err != nil || len(entries) != 0 {
		t.Fatal("read-only digest mutated state")
	}
}
