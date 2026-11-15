package protocol

import (
	"bytes"
	"encoding/json"
	"io"
	"time"
	"unicode/utf8"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/strictjson"
)

// EvidencePath accepts signed data only; it has no response command channel.
const EvidencePath = "/fleet/v1/evidence"

// MaxEvidenceBytes bounds a batch independently of the inventory body limit.
const MaxEvidenceBytes = 4 << 20

// MaxBatchEvents bounds framing, validation and append work per request.
const MaxBatchEvents = 1000

// Forwarding reports process counters and hub-authored gap accounting.
type Forwarding struct {
	// Enabled records explicit evidence disclosure consent.
	Enabled bool `json:"enabled"`
	// ForwardedTotal counts envelopes acknowledged in this process, including duplicates.
	ForwardedTotal uint64 `json:"forwarded_total"`
	// DroppedTotal counts queue overflow and individually rejected envelopes.
	DroppedTotal uint64 `json:"dropped_total"`
	// LastForwardedAt is the last successful delivery time.
	LastForwardedAt string `json:"last_forwarded_at"`
	// GapsTotal counts missing sequence positions observed by the hub.
	GapsTotal uint64 `json:"gaps_total"`
	// QueuedEvents counts pending envelopes in the bounded process queue.
	QueuedEvents int `json:"queued_events,omitempty"`
	// QueuedBytes counts encoded pending envelope bytes.
	QueuedBytes int `json:"queued_bytes,omitempty"`
	// LastError is a fixed local category, never server-authored prose.
	LastError string `json:"last_error,omitempty"`
}

// EvidenceBatch carries contiguous process-local forwarding sequence positions.
type EvidenceBatch struct {
	// StreamID disambiguates sequence resets after a process restart.
	StreamID string `json:"stream_id"`
	// First is the first position, starting at one.
	First uint64 `json:"first"`
	// Last is inclusive and must agree with the number of envelopes.
	Last uint64 `json:"last"`
	// Events preserves each native stored envelope without origin decoration.
	Events []json.RawMessage `json:"events"`
}

// EvidenceAck acknowledges the whole range, including skipped invalid events.
type EvidenceAck struct {
	// NodeID binds the acknowledgement to the requesting cryptographic identity.
	NodeID string `json:"node_id"`
	// Accepted counts successfully appended envelopes.
	Accepted int `json:"accepted"`
	// Invalid counts individually rejected envelopes.
	Invalid int `json:"invalid"`
	// Duplicates counts IDs in this node's bounded deduplication window.
	Duplicates int `json:"duplicates"`
}

// BodyLimit returns the independently versioned endpoint body cap.
func BodyLimit(path string) int {
	if path == EvidencePath {
		return MaxEvidenceBytes
	}
	return MaxBodyBytes
}

// DecodeBatch rejects malformed framing without conflating invalid events with framing.
func DecodeBatch(body []byte) (EvidenceBatch, error) {
	var batch EvidenceBatch
	if len(body) > MaxEvidenceBytes || !utf8.Valid(body) {
		return batch, ErrInvalid
	}
	// Decode the outer object separately: an invalid envelope is skipped by ingestion.
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return batch, ErrInvalid
	}
	fields = make(map[string]json.RawMessage, 4)
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || fields[key] != nil || len(fields) >= 4 {
			return batch, ErrInvalid
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(value, []byte("null")) {
			return batch, ErrInvalid
		}
		fields[key] = value
	}
	if _, err = decoder.Token(); err != nil || decoder.Decode(new(any)) != io.EOF || len(fields) != 4 {
		return batch, ErrInvalid
	}
	if json.Unmarshal(fields["stream_id"], &batch.StreamID) != nil ||
		json.Unmarshal(fields["first"], &batch.First) != nil || json.Unmarshal(fields["last"], &batch.Last) != nil ||
		!decodeBatchEvents(fields["events"], &batch.Events) || !Hex(batch.StreamID, 16) ||
		batch.First == 0 || batch.Last < batch.First || len(batch.Events) == 0 ||
		len(batch.Events) > MaxBatchEvents || batch.Last-batch.First != uint64(len(batch.Events)-1) {
		return batch, ErrInvalid
	}
	return batch, nil
}

// Stream the bounded outer array before allocating its entries; a hostile 4 MiB
// array of tiny values must not allocate an unbounded RawMessage slice.
func decodeBatchEvents(raw []byte, events *[]json.RawMessage) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('[') {
		return false
	}
	for decoder.More() {
		if len(*events) >= MaxBatchEvents {
			return false
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return false
		}
		*events = append(*events, value)
	}
	_, err = decoder.Token()
	return err == nil && decoder.Decode(new(any)) == io.EOF
}

// DecodeEvidence strictly validates an untrusted stored envelope and recomputes its payload hash.
func DecodeEvidence(raw []byte, now time.Time) (event.Envelope, error) {
	var envelope event.Envelope
	if len(raw) > event.MaxStoredEnvelopeBytes || bytes.ContainsAny(raw, "\r\n") || !strictjson.ValidObject(raw) {
		return envelope, ErrInvalid
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return envelope, ErrInvalid
	}
	for _, key := range []string{
		"schema", "id", "time", "seq", "instance", "sensor",
		"classification", "redaction", "integrity", "observation",
	} {
		value, ok := fields[key]
		if !ok || bytes.Equal(value, []byte("null")) {
			return envelope, ErrInvalid
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || envelope.Validate() != nil || envelope.VerifyIntegrity() != nil ||
		!Hex(envelope.ID, 16) || envelope.Seq == 0 || envelope.Integrity.Algorithm != "sha256" ||
		!Hex(envelope.Integrity.PayloadSHA256, 32) || (len(envelope.Sensor.ID) == 0 || len(envelope.Sensor.ID) > 64) ||
		len(envelope.Instance) > 128 || len(envelope.Sensor.Listen) > 256 || len(envelope.Redaction.Rules) > 64 ||
		envelope.Time.Before(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)) || envelope.Time.After(now.Add(Window)) {
		return envelope, ErrInvalid
	}
	switch envelope.Sensor.Kind {
	case "http", "tcp", "mcp", "ssh", "correlation":
	default:
		return envelope, ErrInvalid
	}
	for _, rule := range envelope.Redaction.Rules {
		if len(rule) > 128 {
			return envelope, ErrInvalid
		}
	}
	return envelope, nil
}
