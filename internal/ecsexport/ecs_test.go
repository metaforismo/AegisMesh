package ecsexport

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
)

func fixedEnvelope() event.Envelope {
	observation := json.RawMessage(`{"path":"/admin"}`)
	return event.Envelope{
		Schema:         event.SchemaV1,
		ID:             strings.Repeat("a", 32),
		Time:           time.Date(2026, 8, 23, 10, 11, 12, 123456789, time.UTC),
		Seq:            7,
		Instance:       "demo-instance",
		Sensor:         event.SensorRef{ID: "http-decoy", Kind: "http", Listen: "127.0.0.1:8081"},
		Classification: event.ClassificationInteraction,
		Redaction:      event.RedactionRecord{Rules: []string{"credential"}},
		Integrity:      event.Integrity{PayloadSHA256: event.SHA256Hex(observation), Algorithm: "sha256"},
		Observation:    observation,
	}
}

func TestMarshalGoldenAndPreservesNativeEnvelope(t *testing.T) {
	env := fixedEnvelope()
	got, err := Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "interaction.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got)+"\n" != string(want) {
		t.Fatalf("ECS-compatible mapping changed\n got: %s\nwant: %s", got, want)
	}

	var decoded struct {
		Native struct {
			Envelope event.Envelope `json:"envelope"`
		} `json:"aegismesh"`
	}
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatal(err)
	}
	wantNative, _ := json.Marshal(env)
	gotNative, _ := json.Marshal(decoded.Native.Envelope)
	if string(gotNative) != string(wantNative) {
		t.Fatalf("native envelope changed\n got: %s\nwant: %s", gotNative, wantNative)
	}
}

func TestMarshalClassificationAndNetworkMapping(t *testing.T) {
	for _, tc := range []struct {
		name           string
		classification string
		kind           string
		wantNetwork    bool
	}{
		{"canary", event.ClassificationCanaryHit, "mcp", true},
		{"correlation", event.ClassificationCorrelationSignal, "tcp", true},
		{"future sensor", event.ClassificationInteraction, "future", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := fixedEnvelope()
			env.Classification = tc.classification
			env.Sensor.Kind = tc.kind
			raw, err := Marshal(env)
			if err != nil {
				t.Fatal(err)
			}
			var got struct {
				Event struct {
					Action string `json:"action"`
				} `json:"event"`
				Network *networkFields `json:"network"`
			}
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			if got.Event.Action != tc.classification || (got.Network != nil) != tc.wantNetwork {
				t.Fatalf("action=%q network=%+v", got.Event.Action, got.Network)
			}
		})
	}
}

func TestMarshalRejectsInvalidEnvelope(t *testing.T) {
	tests := map[string]func(*event.Envelope){
		"schema":      func(e *event.Envelope) { e.Schema = "future" },
		"id":          func(e *event.Envelope) { e.ID = "short" },
		"time":        func(e *event.Envelope) { e.Time = time.Time{} },
		"sensor":      func(e *event.Envelope) { e.Sensor.ID = "" },
		"observation": func(e *event.Envelope) { e.Observation = json.RawMessage(`{`) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			env := fixedEnvelope()
			mutate(&env)
			if _, err := Marshal(env); err == nil {
				t.Fatal("invalid envelope was mapped")
			}
		})
	}
}
