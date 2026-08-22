// Package event defines the versioned evidence envelope, its integrity
// metadata, and the bounded bus that carries envelopes from sensors to sinks.
//
// Semantics (enforced by naming and docs, not just convention): an Envelope is
// an *observation*. It records that something interacted with a decoy. It is
// never an incident; classification of incidents is a human act.
package event

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

const (
	// SchemaV1 identifies the current envelope schema.
	SchemaV1 = "aegismesh.event/v1"

	ClassificationInteraction = "interaction"
	ClassificationCanaryHit   = "canary_invocation"
)

var errEnvelope = errors.New("event envelope")

type SensorRef struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Listen string `json:"listen"`
}

// RedactionRecord documents which minimization transformations were applied.
type RedactionRecord struct {
	Rules []string `json:"rules,omitempty"`
}

type Integrity struct {
	PayloadSHA256 string `json:"payload_sha256"`
	Algorithm     string `json:"algorithm"`
}

type Envelope struct {
	Schema         string          `json:"schema"`
	ID             string          `json:"id"`
	Time           time.Time       `json:"time"`
	Seq            uint64          `json:"seq"`
	Instance       string          `json:"instance"`
	Sensor         SensorRef       `json:"sensor"`
	Classification string          `json:"classification"`
	Redaction      RedactionRecord `json:"redaction"`
	Integrity      Integrity       `json:"integrity"`
	Observation    json.RawMessage `json:"observation"`
}

// Sequencer assigns per-process monotonic sequence numbers.
type Sequencer struct{ n atomic.Uint64 }

func (s *Sequencer) Next() uint64 { return s.n.Add(1) }

// New builds an envelope around a redacted observation payload. Integrity
// covers the canonical observation bytes so downstream tampering is detectable.
func New(seq *Sequencer, instance string, sensor SensorRef, classification string, observation json.RawMessage, rules []string) (Envelope, error) {
	if !json.Valid(observation) {
		return Envelope{}, fmt.Errorf("%w: observation is not valid JSON", errEnvelope)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil { //nolint:gosec // crypto/rand IS the secure source
		return Envelope{}, fmt.Errorf("%w: generate id: %v", errEnvelope, err)
	}
	return Envelope{
		Schema:         SchemaV1,
		ID:             hex.EncodeToString(id),
		Time:           time.Now().UTC(),
		Seq:            seq.Next(),
		Instance:       instance,
		Sensor:         sensor,
		Classification: classification,
		Redaction:      RedactionRecord{Rules: rules},
		Integrity:      Integrity{PayloadSHA256: SHA256Hex(observation), Algorithm: "sha256"},
		Observation:    observation,
	}, nil
}

// Validate checks structural invariants when reading envelopes back
// (inspect/export). Unknown future schemas are rejected explicitly.
func (e *Envelope) Validate() error {
	switch e.Schema {
	case SchemaV1:
	default:
		return fmt.Errorf("%w: unsupported schema %q", errEnvelope, e.Schema)
	}
	if len(e.ID) != 32 {
		return fmt.Errorf("%w: id must be 32 hex chars, got %d", errEnvelope, len(e.ID))
	}
	if e.Time.IsZero() {
		return fmt.Errorf("%w: missing time", errEnvelope)
	}
	if e.Sensor.ID == "" || e.Sensor.Kind == "" {
		return fmt.Errorf("%w: incomplete sensor ref", errEnvelope)
	}
	switch e.Classification {
	case ClassificationInteraction, ClassificationCanaryHit:
	default:
		return fmt.Errorf("%w: unknown classification %q", errEnvelope, e.Classification)
	}
	if !json.Valid(e.Observation) {
		return fmt.Errorf("%w: observation is not valid JSON", errEnvelope)
	}
	if e.Integrity.PayloadSHA256 == "" {
		return fmt.Errorf("%w: missing integrity hash", errEnvelope)
	}
	return nil
}

// VerifyIntegrity recomputes the payload hash and compares it to the stored one.
func (e *Envelope) VerifyIntegrity() error {
	want := SHA256Hex(e.Observation)
	if want != e.Integrity.PayloadSHA256 {
		return fmt.Errorf("%w: integrity mismatch for event %s (stored %s, computed %s)", errEnvelope, e.ID, e.Integrity.PayloadSHA256, want)
	}
	return nil
}

func SHA256Hex(b []byte) string {
	// Local re-export keeps callers from importing the redact package twice;
	// implementation delegates to the shared helper.
	return sha256Hex(b)
}
