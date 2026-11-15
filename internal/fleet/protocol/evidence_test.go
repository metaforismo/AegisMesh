package protocol

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
)

func evidenceFixture(t testing.TB) event.Envelope {
	t.Helper()
	envelope, err := event.New(&event.Sequencer{}, "synthetic", event.SensorRef{ID: "web", Kind: "http"},
		event.ClassificationInteraction, json.RawMessage(`{"method":"GET","path":"/"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestEvidenceValidation(t *testing.T) {
	for _, mode := range []string{
		"valid", "hash", "schema", "id", "seq", "time", "future",
		"instance", "kind", "algorithm", "oversize", "duplicate", "unknown", "utf8",
	} {
		t.Run(mode, func(t *testing.T) {
			envelope := evidenceFixture(t)
			switch mode {
			case "hash":
				envelope.Integrity.PayloadSHA256 = strings.Repeat("0", 64)
			case "schema":
				envelope.Schema = "future"
			case "id":
				envelope.ID = strings.Repeat("Z", 32)
			case "seq":
				envelope.Seq = 0
			case "time":
				envelope.Time = time.Unix(0, 0)
			case "future":
				envelope.Time = time.Now().Add(121 * time.Second)
			case "instance":
				envelope.Instance = strings.Repeat("a", 129)
			case "kind":
				envelope.Sensor.Kind = "shell"
			case "algorithm":
				envelope.Integrity.Algorithm = "md5"
			case "oversize":
				envelope.Observation = json.RawMessage(`{"x":"` + strings.Repeat("a", event.MaxStoredEnvelopeBytes) + `"}`)
			}
			body, _ := json.Marshal(envelope)
			switch mode {
			case "duplicate":
				body = append([]byte(`{"id":"duplicate",`), body[1:]...)
			case "unknown":
				body = append([]byte(`{"unknown":1,`), body[1:]...)
			case "utf8":
				body = append(body, 255)
			}
			_, err := DecodeEvidence(body, time.Now())
			if (err == nil) != (mode == "valid") {
				t.Fatalf("validation: %v", err)
			}
		})
	}
}

func TestBatchFraming(t *testing.T) {
	prefix := `{"stream_id":"` + strings.Repeat("a", 32) + `",`
	for _, body := range []string{
		`null`, `{}`, prefix + `"first":1,"last":1,"events":null}`,
		prefix + `"first":0,"last":1,"events":[{}]}`,
		prefix + `"first":2,"last":1,"events":[{}]}`,
		prefix + `"first":1,"last":2,"events":[{}]}`,
		prefix + `"first":1,"first":1,"last":1,"events":[{}]}`,
		prefix + `"first":1,"last":1,"events":[{}],"extra":true}`,
		prefix + `"first":1,"last":1,"events":[{}]} {}`,
	} {
		if _, err := DecodeBatch([]byte(body)); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
	body := prefix + `"first":1,"last":2,"events":[null,{"unknown":true}]}`
	if batch, err := DecodeBatch([]byte(body)); err != nil || len(batch.Events) != 2 {
		t.Fatal("invalid individual envelopes must survive framing", err)
	}
}

func FuzzEvidenceBatch(f *testing.F) {
	f.Add([]byte(`{"stream_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","first":1,"last":1,"events":[{}]}`))
	f.Add([]byte(`{"events":null}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > MaxEvidenceBytes+1 {
			return
		}
		batch, err := DecodeBatch(body)
		if err != nil {
			return
		}
		if len(batch.Events) > MaxBatchEvents || batch.First == 0 || batch.Last-batch.First != uint64(len(batch.Events)-1) {
			t.Fatal("unbounded or inconsistent batch")
		}
		for _, raw := range batch.Events {
			_, _ = DecodeEvidence(raw, time.Unix(1800000000, 0))
		}
	})
}
