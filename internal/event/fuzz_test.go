package event

import (
	"encoding/json"
	"strings"
	"testing"
)

// validSeed is a well-formed envelope used as the base for fuzz mutations.
var validSeed = func() string {
	e, err := New(&Sequencer{}, "fuzz",
		SensorRef{ID: "http-decoy", Kind: "http", Listen: "127.0.0.1:8081"},
		ClassificationInteraction, json.RawMessage(`{"path":"/"}`), nil)
	if err != nil {
		panic(err)
	}
	b, _ := json.Marshal(e)
	return string(b)
}()

func FuzzDecodeEventEnvelope(f *testing.F) {
	f.Add(validSeed)
	f.Add(`{"id":"deadbeef","payload":{}}`)
	f.Add(`{"classification":"nonsense"}`)
	f.Add(``)
	f.Add(`[]`)
	f.Add(strings.Repeat("A", 4096))
	f.Fuzz(func(t *testing.T, raw string) {
		var e Envelope
		if err := json.Unmarshal([]byte(raw), &e); err != nil {
			return // malformed input is expected and fine
		}
		// Decoding must never panic; validation must reject anything it
		// cannot vouch for; integrity verification must not crash.
		_ = e.Validate()
		_ = e.VerifyIntegrity()
	})
}
