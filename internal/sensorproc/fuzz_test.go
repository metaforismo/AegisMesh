package sensorproc

import (
	"encoding/json"
	"testing"

	"github.com/metaforismo/aegismesh/internal/event"
)

func FuzzDecodeSensorProcessFrame(f *testing.F) {
	challenge := "00000000000000000000000000000000"
	valid, err := encodeFrame(frameReady, readyPayload{Addr: "127.0.0.1:8080", Challenge: challenge})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`{"protocol":"aegismesh.sensor/v1","type":"ready","payload":{"addr":"127.0.0.1:8080"}}`))
	f.Add([]byte(`{"protocol":"aegismesh.sensor/v1","type":"ready","payload":null}`))
	for _, seed := range []struct {
		typ     string
		payload any
	}{
		{typ: frameStart, payload: startPayload{Spec: testSpec(), Challenge: challenge}},
		{typ: frameStop, payload: stopPayload{Reason: "operator shutdown"}},
		{typ: frameObservation, payload: Observation{SensorID: "web", Kind: "http", Classification: event.ClassificationInteraction, Observation: json.RawMessage(`{"ok":true}`)}},
		{typ: frameMetric, payload: Metric{Kind: "counter", Operation: "inc", Name: "events_total"}},
		{typ: frameFailure, payload: failurePayload{Code: "sensor_failed"}},
		{typ: frameStopped, payload: stoppedPayload{Reason: "operator"}},
	} {
		encoded, encodeErr := encodeFrame(seed.typ, seed.payload)
		if encodeErr != nil {
			f.Fatal(encodeErr)
		}
		f.Add(encoded)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFrameBytes+1 {
			return
		}
		frame, err := decodeFrame(data)
		if err != nil {
			return
		}
		validateFuzzPayload(frame)
	})
}

func validateFuzzPayload(frame wireFrame) {
	switch frame.Type {
	case frameStart:
		var payload startPayload
		if decodePayload(frame.Payload, &payload) == nil {
			_ = ValidateWorkerSpec(payload.Spec)
		}
	case frameStop:
		var payload stopPayload
		_ = decodePayload(frame.Payload, &payload)
	case frameReady:
		var payload readyPayload
		if decodePayload(frame.Payload, &payload) == nil {
			_ = validateReadyAddr(payload.Addr, "127.0.0.1:0")
			_ = validChallenge(payload.Challenge)
		}
	case frameObservation:
		var payload Observation
		if decodePayload(frame.Payload, &payload) == nil {
			_ = validateObservation(payload, testSpec())
		}
	case frameMetric:
		var payload Metric
		if decodePayload(frame.Payload, &payload) == nil {
			_ = validateMetric(payload)
		}
	case frameFailure:
		var payload failurePayload
		if decodePayload(frame.Payload, &payload) == nil {
			_ = validFailureCode(payload.Code)
		}
	case frameStopped:
		var payload stoppedPayload
		_ = decodePayload(frame.Payload, &payload)
	}
}
