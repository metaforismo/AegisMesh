package storage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
)

func mkEnv(t *testing.T, seq *event.Sequencer, obs string) event.Envelope {
	t.Helper()
	e, err := event.New(seq, "inst", event.SensorRef{ID: "s", Kind: "http", Listen: "127.0.0.1:1"},
		event.ClassificationInteraction, json.RawMessage(obs), nil)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func newStore(t *testing.T, opts Options) *Store {
	t.Helper()
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestAppendAndReadBack(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, Options{Dir: dir, MaxFileBytes: 1 << 20})
	seq := &event.Sequencer{}

	for i := 0; i < 5; i++ {
		if err := s.Append(context.Background(), mkEnv(t, seq, `{"n":`+string(rune('0'+i))+`}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}

	r, _ := NewReader(dir)
	count := 0
	err := r.ForEach(func(e event.Envelope) error {
		if err := e.VerifyIntegrity(); err != nil {
			t.Fatalf("integrity round-trip: %v", err)
		}
		count++
		return nil
	}, func(line string, err error) { t.Fatalf("unexpected corrupt line: %v", err) })
	if err != nil || count != 5 {
		t.Fatalf("read back %d events, err=%v", count, err)
	}
}

func TestRotation(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, Options{Dir: dir, MaxFileBytes: 4096})
	seq := &event.Sequencer{}
	big := `{"pad":"` + strings.Repeat("x", 2000) + `"}`
	for i := 0; i < 4; i++ {
		if err := s.Append(context.Background(), mkEnv(t, seq, big)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	segs, err := s.Segments()
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) < 2 {
		t.Fatalf("expected rotation into >=2 segments, got %d", len(segs))
	}
}

func TestSegmentFilePermissions(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, Options{Dir: dir, MaxFileBytes: 1 << 20})
	if err := s.Append(context.Background(), mkEnv(t, &event.Sequencer{}, `{}`)); err != nil {
		t.Fatal(err)
	}
	segs, _ := s.Segments()
	info, err := os.Stat(segs[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("evidence files must be owner-only, got %v", perm)
	}
}

func TestRetentionByAge(t *testing.T) {
	dir := t.TempDir()
	oldName := "events-20200101T000000.000000000Z.jsonl"
	if err := os.WriteFile(filepath.Join(dir, oldName), []byte("{\"schema\":\"aegismesh.event/v1\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newStore(t, Options{Dir: dir, MaxFileBytes: 1 << 20, MaxAgeDays: 30})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	removed, err := s.ApplyRetention(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != oldName {
		t.Fatalf("age retention removed %v", removed)
	}
}

func TestRetentionByCount(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, Options{Dir: dir, MaxFileBytes: 4096, MaxEvents: 2})
	seq := &event.Sequencer{}
	big := `{"pad":"` + strings.Repeat("x", 2000) + `"}`
	for i := 0; i < 4; i++ { // rotates into multiple segments
		if err := s.Append(context.Background(), mkEnv(t, seq, big)); err != nil {
			t.Fatal(err)
		}
	}
	s.Flush()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.ApplyRetention(ctx); err != nil {
		t.Fatal(err)
	}
	r, _ := NewReader(dir)
	total := 0
	err := r.ForEach(func(event.Envelope) error { total++; return nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if total > 2 {
		t.Fatalf("retention left %d events; cap is 2", total)
	}
}

func TestCorruptLinesSkipped(t *testing.T) {
	dir := t.TempDir()
	fPath := filepath.Join(dir, segName(time.Now()))
	os.WriteFile(fPath, []byte(
		"{\"schema\":\"aegismesh.event/v1\",\"id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"time\":\"2026-01-01T00:00:00Z\",\"seq\":1,\"sensor\":{\"id\":\"s\",\"kind\":\"http\"},\"classification\":\"interaction\",\"observation\":{},\"integrity\":{\"payload_sha256\":\"x\",\"algorithm\":\"sha256\"}}\n"+
			"{this is not json\n"), 0o600)
	r, err := NewReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	good, corrupt := 0, 0
	err = r.ForEach(func(e event.Envelope) error { good++; return nil },
		func(string, error) { corrupt++ })
	if err != nil || good != 1 || corrupt != 1 {
		t.Fatalf("good=%d corrupt=%d err=%v", good, corrupt, err)
	}
}

func TestReaderStreamsBeforeTrailingScannerFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, segName(time.Now()))
	valid := `{"schema":"aegismesh.event/v1","id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","time":"2026-01-01T00:00:00Z","seq":1,"sensor":{"id":"sensor-1","kind":"http"},"classification":"interaction","observation":{},"integrity":{"payload_sha256":"x","algorithm":"sha256"}}`
	content := valid + "\n" + strings.Repeat("x", (1<<20)+1) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := NewReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	stop := errors.New("stop after first envelope")
	seen := 0
	err = r.ForEach(func(event.Envelope) error {
		seen++
		return stop
	}, nil)
	if !errors.Is(err, stop) || seen != 1 {
		t.Fatalf("reader preloaded trailing segment data: seen=%d err=%v", seen, err)
	}
}

func TestOversizeEventRejected(t *testing.T) {
	s := newStore(t, Options{Dir: t.TempDir(), MaxFileBytes: 4096})
	huge := `{"pad":"` + strings.Repeat("x", 8192) + `"}`
	if err := s.Append(context.Background(), mkEnv(t, &event.Sequencer{}, huge)); err == nil {
		t.Fatal("oversize event must be rejected, not truncated")
	}
}

func TestMaxEventBytesIsEnforcedIndependentlyOfSegmentSize(t *testing.T) {
	s := newStore(t, Options{
		Dir:           t.TempDir(),
		MaxFileBytes:  1 << 20,
		MaxEventBytes: 1024,
	})
	large := `{"pad":"` + strings.Repeat("x", 2048) + `"}`
	err := s.Append(context.Background(), mkEnv(t, &event.Sequencer{}, large))
	if err == nil || !strings.Contains(err.Error(), "max_event_bytes 1024") {
		t.Fatalf("expected max_event_bytes rejection, got %v", err)
	}
	if s.appended != 0 {
		t.Fatalf("rejected event changed append count: %d", s.appended)
	}
}

func TestMaxEventBytesDefaultsToConfiguredSchemaValue(t *testing.T) {
	s := newStore(t, Options{Dir: t.TempDir(), MaxFileBytes: 1 << 20})
	large := `{"pad":"` + strings.Repeat("x", defaultMaxEventBytes) + `"}`
	err := s.Append(context.Background(), mkEnv(t, &event.Sequencer{}, large))
	if err == nil || !strings.Contains(err.Error(), "max_event_bytes 262144") {
		t.Fatalf("expected default max_event_bytes rejection, got %v", err)
	}
}

func TestMaxEventBytesMinimum(t *testing.T) {
	_, err := New(Options{Dir: t.TempDir(), MaxFileBytes: 4096, MaxEventBytes: 1023})
	if err == nil || !strings.Contains(err.Error(), "max_event_bytes must be >= 1024") {
		t.Fatalf("expected minimum validation, got %v", err)
	}
}

func FuzzDecodeEventEnvelope(f *testing.F) {
	f.Add([]byte(`{"schema":"aegismesh.event/v1"}`))
	f.Add([]byte(`{"schema":123}`))
	f.Add([]byte(``))
	f.Add([]byte(strings.Repeat("[", 100)))
	f.Fuzz(func(t *testing.T, raw []byte) {
		var e event.Envelope
		if json.Unmarshal(raw, &e) == nil {
			_ = e.Validate()
			_ = e.VerifyIntegrity() // must never panic on attacker-controlled input
		}
	})
}
