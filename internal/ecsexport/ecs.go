// Package ecsexport maps native AegisMesh evidence to a stable ECS-compatible
// document while preserving the complete native envelope.
package ecsexport

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
)

const (
	MappingVersion   = "aegismesh.ecs/v1"
	TargetECSVersion = "9.4.0"
)

type document struct {
	Timestamp time.Time      `json:"@timestamp"`
	ECS       ecsFields      `json:"ecs"`
	Event     eventFields    `json:"event"`
	Observer  observerFields `json:"observer"`
	Service   serviceFields  `json:"service"`
	Network   *networkFields `json:"network,omitempty"`
	Native    nativeFields   `json:"aegismesh"`
}

type ecsFields struct {
	Version string `json:"version"`
}

type eventFields struct {
	Action   string `json:"action"`
	Dataset  string `json:"dataset"`
	Hash     string `json:"hash"`
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Module   string `json:"module"`
	Sequence uint64 `json:"sequence"`
}

type observerFields struct {
	Name    string `json:"name"`
	Product string `json:"product"`
	Type    string `json:"type"`
}

type serviceFields struct {
	Address string `json:"address,omitempty"`
	Name    string `json:"name"`
	Type    string `json:"type"`
}

type networkFields struct {
	Protocol  string `json:"protocol"`
	Transport string `json:"transport"`
}

type nativeFields struct {
	MappingVersion string         `json:"mapping_version"`
	Envelope       event.Envelope `json:"envelope"`
}

// Marshal validates and maps one native envelope. It performs no I/O and does
// not interpret sensor-private observation payloads.
func Marshal(e event.Envelope) ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, fmt.Errorf("map ECS-compatible evidence: %w", err)
	}
	doc := document{
		Timestamp: e.Time,
		ECS:       ecsFields{Version: TargetECSVersion},
		Event: eventFields{
			Action:   e.Classification,
			Dataset:  "aegismesh.evidence",
			Hash:     e.Integrity.PayloadSHA256,
			ID:       e.ID,
			Kind:     "event",
			Module:   "aegismesh",
			Sequence: e.Seq,
		},
		Observer: observerFields{Name: e.Instance, Product: "AegisMesh", Type: "sensor"},
		Service:  serviceFields{Address: e.Sensor.Listen, Name: e.Sensor.ID, Type: e.Sensor.Kind},
		Native:   nativeFields{MappingVersion: MappingVersion, Envelope: e},
	}
	switch e.Sensor.Kind {
	case "http", "mcp", "tcp":
		doc.Network = &networkFields{Protocol: e.Sensor.Kind, Transport: "tcp"}
	}
	return json.Marshal(doc)
}
