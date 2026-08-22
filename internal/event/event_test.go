package event

import (
	"context"
	"encoding/json"

	"log/slog"
	"sync"
	"testing"
	"time"
)

func testEnvelope(t *testing.T, seq *Sequencer) Envelope {
	t.Helper()
	env, err := New(seq, "inst", SensorRef{ID: "s1", Kind: "http", Listen: "127.0.0.1:1"},
		ClassificationInteraction, json.RawMessage(`{"path":"/x"}`), []string{"t"})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestEnvelopeIntegrityLifecycle(t *testing.T) {
	seq := &Sequencer{}
	env := testEnvelope(t, seq)
	if err := env.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := env.VerifyIntegrity(); err != nil {
		t.Fatalf("fresh envelope must verify: %v", err)
	}
	env.Observation = json.RawMessage(`{"path":"/tampered"}`)
	if err := env.VerifyIntegrity(); err == nil {
		t.Fatal("tampered observation must fail integrity")
	}
}

func TestEnvelopeIDsUniqueAndNonEnumerable(t *testing.T) {
	seq := &Sequencer{}
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		e := testEnvelope(t, seq)
		if len(e.ID) != 32 || seen[e.ID] {
			t.Fatalf("bad/duplicate id: %s", e.ID)
		}
		seen[e.ID] = true
	}
}

func TestSequencerMonotonic(t *testing.T) {
	seq := &Sequencer{}
	prev := uint64(0)
	for i := 0; i < 100; i++ {
		n := seq.Next()
		if n <= prev {
			t.Fatalf("non-monotonic: %d after %d", n, prev)
		}
		prev = n
	}
}

type blockingSink struct {
	mu      sync.Mutex
	release chan struct{}
	got     []Envelope
}

func (b *blockingSink) Append(_ context.Context, e Envelope) error {
	<-b.release
	b.mu.Lock()
	b.got = append(b.got, e)
	b.mu.Unlock()
	return nil
}

// TestBusBoundedAndDropCounted proves the bus never blocks producers and that
// drops are counted exactly when the sink is stalled.
func TestBusBoundedAndDropCounted(t *testing.T) {
	sink := &blockingSink{release: make(chan struct{})}
	bus := NewBus(2, sink, slog.New(slog.NewTextHandler(&testWriter{}, nil)))
	defer bus.Close()

	seq := &Sequencer{}
	for i := 0; i < 5; i++ { // 2 buffered + 1 in-flight-append + 2 dropped
		bus.Submit(testEnvelope(t, seq))
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && bus.Dropped() < 2 {
		time.Sleep(5 * time.Millisecond)
	}
	if got := bus.Dropped(); got != 2 {
		t.Fatalf("dropped = %d, want 2 (worker blocked on first append)", got)
	}
	close(sink.release) // let the worker drain the rest
	bus.Close()
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.got) != 3 {
		t.Fatalf("delivered = %d, want 3 (1 blocked + 2 queued)", len(sink.got))
	}
}

type testWriter struct{}

func (*testWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestEnvelopeValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Envelope)
	}{
		{"schema", func(e *Envelope) { e.Schema = "other/v9" }},
		{"id-length", func(e *Envelope) { e.ID = "short" }},
		{"time", func(e *Envelope) { e.Time = time.Time{} }},
		{"sensor", func(e *Envelope) { e.Sensor = SensorRef{} }},
		{"classification", func(e *Envelope) { e.Classification = "incident" }},
		{"observation", func(e *Envelope) { e.Observation = json.RawMessage("{broken") }},
		{"integrity", func(e *Envelope) { e.Integrity.PayloadSHA256 = "" }},
	}
	base := testEnvelope(t, &Sequencer{})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := base // copy
			tc.mut(&e)
			if err := e.Validate(); err == nil {
				t.Fatal("expected Validate failure")
			}
		})
	}
}
