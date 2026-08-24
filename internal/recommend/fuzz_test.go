package recommend

import (
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
)

func FuzzGenerateObservation(f *testing.F) {
	f.Add(`{"detection":{"action":"refuse","findings":[{"rule_id":"PI-001","severity":"high","confidence":"medium","reason":"static"}]}}`, false)
	f.Add(`{"rule_id":"COR-001","summary":"static","source_key":"source","source_event_ids":[],"truncated":false}`, true)
	f.Fuzz(func(t *testing.T, raw string, correlation bool) {
		e := testFuzzEnvelope(raw, correlation)
		_, _ = Generate([]event.Envelope{e}, Options{})
	})
}

func testFuzzEnvelope(raw string, correlation bool) event.Envelope {
	classification := event.ClassificationInteraction
	if correlation {
		classification = event.ClassificationCorrelationSignal
	}
	return event.Envelope{
		Schema:         event.SchemaV1,
		ID:             "00000000000000000000000000000001",
		Time:           time.Unix(1, 0).UTC(),
		Seq:            1,
		Instance:       "fuzz",
		Sensor:         event.SensorRef{ID: "sensor", Kind: "mcp", Listen: "127.0.0.1:1"},
		Classification: classification,
		Integrity: event.Integrity{
			PayloadSHA256: event.SHA256Hex([]byte(raw)),
			Algorithm:     "sha256",
		},
		Observation: []byte(raw),
	}
}
