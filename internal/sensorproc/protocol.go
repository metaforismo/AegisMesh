// Package sensorproc contains the bounded, observe-only protocol used by an
// optionally isolated sensor worker. The worker is a fault-containment seam,
// not a general sandbox: the child still has the same OS identity and network
// policy as its parent.
package sensorproc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/event"
)

const (
	// ProtocolV1 is deliberately private to the executable pair. It is not an
	// external API and must be changed when wire semantics change.
	ProtocolV1 = "aegismesh.sensor/v1"

	// WorkerArg and WorkerEnv are fixed literals used by the parent command
	// factory and the hidden command entry point. Neither is config-derived.
	workerEnvName = "AEGISMESH_SENSOR_WORKER"
	WorkerArg     = "__sensor-worker"
	WorkerEnv     = workerEnvName + "=1"

	maxFrameBytes = 512 << 10
	// Config is JSON-encoded over the start channel. A validated 4 MiB aggregate
	// of body text can expand substantially through JSON escaping; 32 MiB is a
	// fixed start-only ceiling, while all runtime output remains 512 KiB.
	maxStartFrameBytes  = 32 << 20
	maxObservationBytes = 256 << 10
	maxObservationDepth = 64
	maxAddrBytes        = 256
	maxFailureCodeBytes = 64
	maxMetricNameBytes  = 128
	maxMetricHelpBytes  = 512
	maxMetricLabelBytes = 64
	maxRedactionRules   = 32
	maxRedactionBytes   = 128
	maxQueueFrames      = 1024
	maxMetricSeries     = 64
	maxPendingMetrics   = 128
	maxDeclaredMetrics  = 16
	challengeBytes      = 16
)

const (
	frameStart       = "start"
	frameStop        = "stop"
	frameReady       = "ready"
	frameObservation = "observation"
	frameMetric      = "metric"
	frameFailure     = "failure"
	frameStopped     = "stopped"
)

// WorkerSpec is the only configuration crossing the process boundary. The
// parent must materialize body files and clear all file references before
// creating one. API keys, provider destinations, models, and credential
// references are intentionally absent.
type WorkerSpec struct {
	Sensor             config.Sensor      `json:"sensor"`
	Detection          config.Detection   `json:"detection"`
	Instance           string             `json:"instance"`
	MaterializedBodies []MaterializedBody `json:"materialized_bodies,omitempty"`
}

// MaterializedBody preserves exact body_file bytes without giving the worker
// a filesystem path. Content uses encoding/json's bounded base64 form.
type MaterializedBody struct {
	RuleIndex int    `json:"rule_index"`
	Content   []byte `json:"content"`
}

// ValidateWorkerSpec is a second boundary after the complete parent config
// validation. It rejects unsupported identity and any filesystem path that
// must have been materialized before launch.
func ValidateWorkerSpec(s WorkerSpec) error {
	if s.Sensor.ID == "" || len(s.Sensor.ID) > 128 {
		return fmt.Errorf("sensorproc: sensor id is empty or too long")
	}
	if s.Sensor.Kind != config.SensorKindHTTP && s.Sensor.Kind != config.SensorKindTCP &&
		s.Sensor.Kind != config.SensorKindMCP && s.Sensor.Kind != config.SensorKindSSH {
		return fmt.Errorf("sensorproc: unsupported sensor kind %q", s.Sensor.Kind)
	}
	if s.Sensor.Kind == config.SensorKindHTTP && s.Sensor.Persona == nil {
		return fmt.Errorf("sensorproc: http sensor %s is missing its validated persona", s.Sensor.ID)
	}
	if len(s.Instance) > 128 {
		return fmt.Errorf("sensorproc: instance is too long")
	}
	for _, rule := range s.Sensor.Rules {
		if rule.BodyFile != "" {
			return fmt.Errorf("sensorproc: sensor %s contains body_file path", s.Sensor.ID)
		}
	}
	if len(s.MaterializedBodies) > len(s.Sensor.Rules) || (s.Sensor.Kind != config.SensorKindHTTP && len(s.MaterializedBodies) != 0) {
		return fmt.Errorf("sensorproc: invalid materialized bodies")
	}
	seenBodies := make(map[int]bool, len(s.MaterializedBodies))
	for _, body := range s.MaterializedBodies {
		if body.RuleIndex < 0 || body.RuleIndex >= len(s.Sensor.Rules) || body.Content == nil || len(body.Content) > config.MaxHTTPBodyBytes || seenBodies[body.RuleIndex] {
			return fmt.Errorf("sensorproc: invalid materialized body")
		}
		rule := s.Sensor.Rules[body.RuleIndex]
		if rule.Body != "" || rule.BodyFile != "" {
			return fmt.Errorf("sensorproc: materialized body conflicts with rule content")
		}
		seenBodies[body.RuleIndex] = true
	}
	if s.Sensor.Fallback != nil && s.Sensor.Fallback.Enabled && s.Sensor.Kind != config.SensorKindHTTP {
		return fmt.Errorf("sensorproc: fallback is only valid for http sensor %s", s.Sensor.ID)
	}
	return nil
}

type wireFrame struct {
	Protocol string          `json:"protocol"`
	Type     string          `json:"type"`
	Payload  json.RawMessage `json:"payload"`
}

type startPayload struct {
	Spec      WorkerSpec `json:"spec"`
	Challenge string     `json:"challenge"`
}
type stopPayload struct {
	Reason string `json:"reason,omitempty"`
}

type readyPayload struct {
	Addr      string `json:"addr"`
	Challenge string `json:"challenge"`
}

// Observation is intentionally a projection of an event. IDs, time, sequence
// and integrity are never accepted from a worker; the parent owns those.
type Observation struct {
	SensorID       string          `json:"sensor_id"`
	Kind           string          `json:"kind"`
	Classification string          `json:"classification"`
	Observation    json.RawMessage `json:"observation"`
	Redaction      []string        `json:"redaction,omitempty"`
}

// Metric is a bounded operation, not a serialized registry. Values are
// applied to the parent's injected Meter after name/cardinality validation.
type Metric struct {
	Kind      string  `json:"kind"`
	Operation string  `json:"operation"`
	Name      string  `json:"name"`
	Help      string  `json:"help,omitempty"`
	Label     string  `json:"label,omitempty"`
	Value     float64 `json:"value,omitempty"`
	MaxSeries int     `json:"max_series,omitempty"`
}

type failurePayload struct {
	Code string `json:"code"`
}
type stoppedPayload struct {
	Reason string `json:"reason,omitempty"`
}

func encodeFrame(typ string, payload any) ([]byte, error) {
	if typ == "" {
		return nil, fmt.Errorf("sensorproc: empty frame type")
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("sensorproc: encode %s payload: %w", typ, err)
	}
	b, err := json.Marshal(wireFrame{Protocol: ProtocolV1, Type: typ, Payload: payloadBytes})
	if err != nil {
		return nil, fmt.Errorf("sensorproc: encode %s frame: %w", typ, err)
	}
	frameLimit := maxFrameBytes
	if typ == frameStart {
		frameLimit = maxStartFrameBytes
	}
	if len(b) > frameLimit {
		return nil, fmt.Errorf("sensorproc: %s frame exceeds %d bytes", typ, frameLimit)
	}
	return append(b, '\n'), nil
}

func decodeFrame(line []byte) (wireFrame, error) {
	return decodeFrameWithLimit(line, maxFrameBytes)
}

func decodeFrameWithLimit(line []byte, limit int) (wireFrame, error) {
	if len(line) == 0 {
		return wireFrame{}, fmt.Errorf("sensorproc: frame exceeds %d bytes", limit)
	}
	if line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}
	if len(line) == 0 || len(line) > limit || !json.Valid(line) {
		return wireFrame{}, fmt.Errorf("sensorproc: malformed frame")
	}
	var f wireFrame
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return wireFrame{}, fmt.Errorf("sensorproc: decode frame: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return wireFrame{}, fmt.Errorf("sensorproc: trailing frame data")
	}
	canonical, err := json.Marshal(f)
	if err != nil || !bytes.Equal(canonical, line) {
		return wireFrame{}, fmt.Errorf("sensorproc: frame is not canonical")
	}
	if f.Protocol != ProtocolV1 || f.Type == "" || len(f.Payload) == 0 || !json.Valid(f.Payload) {
		return wireFrame{}, fmt.Errorf("sensorproc: invalid frame envelope")
	}
	return f, nil
}

func decodePayload(raw json.RawMessage, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("sensorproc: decode payload: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("sensorproc: payload has trailing data")
	}
	canonical, err := json.Marshal(dst)
	if err != nil || !bytes.Equal(canonical, raw) {
		return fmt.Errorf("sensorproc: payload is not canonical")
	}
	return nil
}

func validateObservation(o Observation, spec WorkerSpec) error {
	if o.SensorID != spec.Sensor.ID || o.Kind != spec.Sensor.Kind {
		return fmt.Errorf("sensorproc: observation identity mismatch")
	}
	if o.Classification != event.ClassificationInteraction && o.Classification != event.ClassificationCanaryHit {
		return fmt.Errorf("sensorproc: unsupported observation classification")
	}
	if len(o.Observation) == 0 || len(o.Observation) > maxObservationBytes || !canonicalJSON(o.Observation) {
		return fmt.Errorf("sensorproc: observation payload exceeds bound or is invalid")
	}
	if len(o.Redaction) > maxRedactionRules {
		return fmt.Errorf("sensorproc: too many redaction rules")
	}
	seen := make(map[string]bool, len(o.Redaction))
	for _, rule := range o.Redaction {
		if len(rule) == 0 || len(rule) > maxRedactionBytes || strings.TrimSpace(rule) != rule || !validRedactionRule(rule) || seen[rule] {
			return fmt.Errorf("sensorproc: invalid redaction rule")
		}
		seen[rule] = true
	}
	return nil
}

func canonicalJSON(raw []byte) bool {
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil || !bytes.Equal(compact.Bytes(), raw) {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := walkUniqueJSONValue(dec, 0); err != nil {
		return false
	}
	var trailing any
	return dec.Decode(&trailing) == io.EOF
}

func walkUniqueJSONValue(dec *json.Decoder, depth int) error {
	if depth > maxObservationDepth {
		return fmt.Errorf("sensorproc: observation nesting exceeds bound")
	}
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("sensorproc: invalid observation object key")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("sensorproc: duplicate observation key")
			}
			seen[key] = struct{}{}
			if err := walkUniqueJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := walkUniqueJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("sensorproc: invalid observation delimiter")
	}
	_, err = dec.Token()
	return err
}

func validRedactionRule(rule string) bool {
	switch rule {
	case "header_values_policy", "query_string_dropped", "credential_scrub", "preview_truncated",
		"username_content_dropped", "credential_content_dropped", "request_payload_dropped",
		"channel_payload_dropped", "input_truncated":
		return true
	default:
		return false
	}
}

func validateMetric(m Metric) error {
	switch m.Kind {
	case "counter":
		if m.Operation != "declare" && m.Operation != "inc" && m.Operation != "add" {
			return fmt.Errorf("sensorproc: unsupported metric operation")
		}
	case "gauge":
		if m.Operation != "declare" && m.Operation != "set" && m.Operation != "add" {
			return fmt.Errorf("sensorproc: unsupported metric operation")
		}
	case "counter_vec":
		if m.Operation != "declare" && m.Operation != "inc" {
			return fmt.Errorf("sensorproc: unsupported metric operation")
		}
	default:
		return fmt.Errorf("sensorproc: unsupported metric kind")
	}
	if len(m.Name) == 0 || len(m.Name) > maxMetricNameBytes || !validMetricName(m.Name) {
		return fmt.Errorf("sensorproc: invalid metric name")
	}
	if len(m.Help) > maxMetricHelpBytes || strings.ContainsAny(m.Help, "\r\n") {
		return fmt.Errorf("sensorproc: invalid metric help")
	}
	if len(m.Label) > maxMetricLabelBytes || (m.Kind == "counter_vec" && m.Operation == "inc" && !validMetricLabel(m.Label)) {
		return fmt.Errorf("sensorproc: invalid metric label")
	}
	if m.Kind != "counter_vec" && (m.Label != "" || m.MaxSeries != 0) {
		return fmt.Errorf("sensorproc: incompatible metric fields")
	}
	if m.Kind == "counter_vec" && m.Value != 0 {
		return fmt.Errorf("sensorproc: incompatible metric fields")
	}
	if m.Operation == "inc" && m.Kind == "counter" && m.Value != 0 {
		return fmt.Errorf("sensorproc: incompatible metric fields")
	}
	if m.Operation == "declare" && (m.Value != 0 || m.Label != "") {
		return fmt.Errorf("sensorproc: incompatible metric fields")
	}
	if (m.Operation == "set" || m.Operation == "add") && (math.IsNaN(m.Value) || math.IsInf(m.Value, 0)) {
		return fmt.Errorf("sensorproc: metric value is not finite")
	}
	if m.Kind == "counter" && m.Operation == "add" && m.Value < 0 {
		return fmt.Errorf("sensorproc: counter cannot decrease")
	}
	if m.Kind == "counter_vec" && (m.MaxSeries < 1 || m.MaxSeries > maxMetricSeries) {
		return fmt.Errorf("sensorproc: metric series cap out of bounds")
	}
	return nil
}

func validMetricName(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_' || c == ':':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

func validMetricLabel(s string) bool {
	if s == "" || len(s) > maxMetricLabelBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}
