package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/storage"
)

func seedOpenEvidence(t *testing.T, dir string) (*storage.Store, event.Envelope, string, string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	key := writeIdentityForCLI(t, id)
	s, err := storage.New(storage.Options{
		Dir: dir, Encryption: &storage.EncryptionOptions{Recipient: id.Recipient().String()},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	raw, err := os.ReadFile("testdata/recommend.event.json")
	if err != nil {
		t.Fatal(err)
	}
	var env event.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	segments, err := s.Segments()
	if err != nil || len(segments) != 1 {
		t.Fatalf("segments=%v err=%v", segments, err)
	}
	return s, env, key, segments[0].Name
}

func TestOpenSegmentCLIAndRequireSealed(t *testing.T) {
	dir := t.TempDir()
	s, env, key, segment := seedOpenEvidence(t, dir)
	// Publish a complete event without a checkpoint by exceeding bufio capacity.
	// It is deliberately outside the authenticated prefix.
	tail, err := event.New(&event.Sequencer{}, "tail",
		event.SensorRef{ID: "tail", Kind: "http", Listen: "127.0.0.1:1"},
		event.ClassificationInteraction, []byte(`{"pad":"`+strings.Repeat("x", 5000)+`"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append(context.Background(), tail); err != nil {
		t.Fatal(err)
	}
	for _, command := range [][]string{
		{"inspect", "list", "--json"},
		{"inspect", "show", "--id", env.ID},
		{"inspect", "export", "--out", "-"},
		{"recommend", "--json"},
	} {
		args := append(append([]string(nil), command...), "--data-dir", dir, "--identity", key)
		t.Run(strings.Join(command[:2], " "), func(t *testing.T) {
			code, out, stderr := run(t, args...)
			if code != 0 || !strings.Contains(out, env.ID) || strings.Contains(out, tail.ID) ||
				strings.Count(stderr, "later events may exist") != 1 || !strings.Contains(stderr, segment) {
				t.Fatalf("code=%d out=%q stderr=%q", code, out, stderr)
			}
			if command[1] != "export" {
				var result struct {
					OpenSegments []storage.OpenSegmentError `json:"open_segments"`
				}
				if err := json.Unmarshal([]byte(out), &result); err != nil || len(result.OpenSegments) != 1 {
					t.Fatalf("missing JSON status: err=%v out=%s", err, out)
				}
				status := result.OpenSegments[0]
				if status.Segment != segment || status.VerifiedEvents != 1 || status.Interrupted || status.TrailingBytes <= 0 {
					t.Fatalf("incorrect JSON status: %+v", status)
				}
			}
			code, out, stderr = run(t, append(args, "--require-sealed")...)
			if code != 1 || out != "" || !strings.Contains(stderr, "not sealed") {
				t.Fatalf("strict: code=%d out=%q stderr=%q", code, out, stderr)
			}
		})
	}
	// File exports keep their destination on strict failure.
	target := filepath.Join(t.TempDir(), "existing.ndjson")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := run(t, "inspect", "export", "--data-dir", dir, "--identity", key,
		"--out", target, "--require-sealed")
	raw, err := os.ReadFile(target)
	if code != 1 || out != "" || !strings.Contains(stderr, "not sealed") || err != nil || string(raw) != "keep" {
		t.Fatalf("strict export changed target: code=%d err=%v raw=%q stderr=%s", code, err, raw, stderr)
	}
	// Close publishes the entire stream, with no incompleteness notice.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	code, out, stderr = run(t, "inspect", "list", "--json", "--data-dir", dir, "--identity", key, "--require-sealed")
	if code != 0 || stderr != "" || !strings.Contains(out, tail.ID) || strings.Contains(out, "open_segments") {
		t.Fatalf("sealed: code=%d out=%q stderr=%q", code, out, stderr)
	}
}

func TestOpenSegmentCLIGolden(t *testing.T) {
	dir := t.TempDir()
	_, _, key, segment := seedOpenEvidence(t, dir)
	code, out, stderr := run(t, "inspect", "list", "--json", "--data-dir", dir, "--identity", key)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	got := strings.ReplaceAll(out+stderr, segment, "events-current.jsonl.age")
	want, err := os.ReadFile("testdata/checkpoint-list.golden.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("golden mismatch:\ngot:\n%swant:\n%s", got, want)
	}
}

func TestInterruptedSegmentCLIAndDoctor(t *testing.T) {
	workspace := scaffoldWorkspace(t)
	dir := filepath.Join(workspace, "data")
	_, env, key, segment := seedOpenEvidence(t, dir)
	// A newer segment represents the successor opened after a crash. The older
	// descriptor stays untouched so this also checks independent reader behavior.
	newer := filepath.Join(dir, "events-successor.jsonl")
	if err := os.WriteFile(newer, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for i, path := range []string{filepath.Join(dir, segment), newer} {
		stamp := time.Unix(int64(i+1), 0)
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	code, out, stderr := run(t, "inspect", "list", "--data-dir", dir, "--identity", key)
	if code != 0 || !strings.Contains(out, short(env.ID)) ||
		!strings.Contains(stderr, "WARNING: interrupted segment "+segment) {
		t.Fatalf("code=%d out=%q stderr=%q", code, out, stderr)
	}
	code, out, stderr = run(t, "doctor", "--config", filepath.Join(workspace, "mesh.yaml"), "--json")
	if code != 0 || stderr != "" || !strings.Contains(out, "interrupted segment "+segment) ||
		!strings.Contains(out, `"status": "warn"`) || !strings.Contains(out, "authenticity not checked") {
		t.Fatalf("doctor: code=%d out=%q stderr=%q", code, out, stderr)
	}
	// Before the successor's first flush its header has no usable checkpoint.
	// Doctor must retain the predecessor warning alongside that separate failure.
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	successor, err := storage.New(storage.Options{
		Dir: dir, Encryption: &storage.EncryptionOptions{Recipient: id.Recipient().String()},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer successor.Close()
	code, out, stderr = run(t, "doctor", "--config", filepath.Join(workspace, "mesh.yaml"), "--json")
	if code != 0 || stderr != "" || !strings.Contains(out, "interrupted segment "+segment) ||
		!strings.Contains(out, `"overall": "fail"`) || !strings.Contains(out, `"status": "warn"`) {
		t.Fatalf("doctor lost interrupted warning: code=%d out=%q stderr=%q", code, out, stderr)
	}
	code, out, stderr = run(t, "doctor", "--config", filepath.Join(workspace, "mesh.yaml"))
	if code != 1 || !strings.Contains(out, "interrupted segment "+segment) || !strings.Contains(out, "not sealed") {
		t.Fatalf("human doctor did not fail: code=%d out=%q stderr=%q", code, out, stderr)
	}
}
