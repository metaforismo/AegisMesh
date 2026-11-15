package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/metaforismo/aegismesh/internal/event"
)

func TestEncodedAppendAndByteRetention(t *testing.T) {
	store, err := New(Options{Dir: t.TempDir(), MaxFileBytes: 4096, MaxEventBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	envelope, err := event.New(&event.Sequencer{}, "synthetic", event.SensorRef{ID: "web", Kind: "http"},
		event.ClassificationInteraction, json.RawMessage(`{"x":"`+string(bytes.Repeat([]byte("a"), 2000))+`"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	for range 6 {
		if err := store.AppendEncoded(raw); err != nil {
			t.Fatal(err)
		}
	}
	total, err := store.RetainBytes(5000)
	if err != nil || total > 5000 {
		t.Fatalf("byte retention: %d %v", total, err)
	}
	count := 0
	if err := store.Reader().ForEach(func(e event.Envelope) error { count++; return e.VerifyIntegrity() }, nil); err != nil || count != 2 {
		t.Fatalf("retained evidence: %d %v", count, err)
	}
	for _, invalid := range [][]byte{[]byte("null\n"), []byte(`{`), bytes.Repeat([]byte("x"), 4097)} {
		if err := store.AppendEncoded(invalid); err == nil {
			t.Fatal("accepted malformed encoded input")
		}
	}
	if err := store.Append(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
}
