// Package console serves a dedicated tenant-scoped operator API inside one process.
// Untrusted requests can read evidence snapshots or annotate operator state, never control sensors.
package console

import (
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/rulecatalog"
)

// Sensor is a runtime snapshot augmented with indexed observation counts.
type Sensor struct {
	// ID is the configured sensor identifier.
	ID string `json:"id"`
	// Kind is the configured sensor protocol.
	Kind string `json:"kind"`
	// Listen is the current sensor authority.
	Listen string `json:"listen"`
	// State reports running, stopped, or failed runtime state.
	State string `json:"state"`
	// ProcessIsolation reports whether the sensor uses a separate process.
	ProcessIsolation bool `json:"process_isolation"`
	// EventsTotal counts retained indexed observations.
	EventsTotal int `json:"events_total"`
	// LastEventAt is the latest indexed timestamp, or empty if none exists.
	LastEventAt string `json:"last_event_at"`
	// ByClassification counts retained observations by stored classification.
	ByClassification map[string]int `json:"by_classification"`
}

// Node describes the local runtime and bounded storage metadata.
type Node struct {
	// Instance is the configured local instance name.
	Instance string `json:"instance"`
	// Version identifies this executable and toolchain.
	Version NodeVersion `json:"version"`
	// StartedAt is the UTC runtime construction time.
	StartedAt string `json:"started_at"`
	// UptimeSeconds counts elapsed seconds since runtime construction.
	UptimeSeconds int64 `json:"uptime_seconds"`
	// Healthy requires a running runtime, all wanted sensors, and healthy storage.
	Healthy bool `json:"healthy"`
	// Sensors reports wanted and started counts.
	Sensors NodeSensors `json:"sensors"`
	// Bus reports event-bus drops.
	Bus NodeBus `json:"bus"`
	// Storage reports bounded physical metadata and configured retention.
	Storage NodeStorage `json:"storage"`
	// Index reports disposable index occupancy and history coverage.
	Index evidenceindex.Stats `json:"index"`
	// Console reports this listener and its session policy.
	Console NodeConsole `json:"console"`
}

// NodeVersion identifies the executable and Go toolchain.
type NodeVersion struct {
	// Version is the application build version.
	Version string `json:"version"`
	// Commit is the source revision embedded at build time.
	Commit string `json:"commit"`
	// Go identifies the Go toolchain.
	Go string `json:"go"`
}

// NodeSensors reports configured and started sensor counts.
type NodeSensors struct {
	// Wanted counts configured sensors.
	Wanted int `json:"wanted"`
	// Started counts successfully started sensors.
	Started int `json:"started"`
}

// NodeBus reports observations dropped by the bounded event bus.
type NodeBus struct {
	// DroppedEvents counts observations dropped by the bounded bus.
	DroppedEvents uint64 `json:"dropped_events"`
}

// NodeStorage reports physical segment totals and configured retention.
type NodeStorage struct {
	// Segments counts evidence segment files.
	Segments int `json:"segments"`
	// Bytes totals physical evidence segment bytes.
	Bytes int64 `json:"bytes"`
	// Encrypted reports configured evidence encryption.
	Encrypted bool `json:"encrypted"`
	// Retention reports configured evidence retention bounds.
	Retention Retention `json:"retention"`
}

// Retention describes configured evidence limits, independent of index capacity.
type Retention struct {
	// MaxEvents is the configured evidence count limit.
	MaxEvents int `json:"max_events"`
	// MaxAgeDays is the configured evidence age limit.
	MaxAgeDays int `json:"max_age_days"`
}

// NodeConsole describes the console authority and session policy.
type NodeConsole struct {
	// Listen is the actual bound console authority.
	Listen string `json:"listen"`
	// TLS reports whether this listener uses TLS.
	TLS bool `json:"tls"`
	// SessionTTLSeconds is the configured absolute session lifetime.
	SessionTTLSeconds int `json:"session_ttl_seconds"`
}

// Runtime exposes value snapshots only; the console cannot control sensors.
type Runtime interface {
	// ConsoleNode snapshots local status and bounded storage metadata.
	ConsoleNode() (Node, error)
	// ConsoleSensors snapshots sensor state without control operations.
	ConsoleSensors() []Sensor
}

// Rule is catalog-authored rule metadata with its effective enabled state.
type Rule struct {
	// ObserveOnly marks rules that cannot select an enforcement action.
	ObserveOnly bool `json:"observe_only"`
	// Guidance is static next-step operator advice.
	Guidance string `json:"guidance"`
	// Frameworks lists editorial relates-to references from the catalog.
	Frameworks []rulecatalog.FrameworkMapping `json:"frameworks"`
	// ID is the catalog rule identifier.
	ID string `json:"id"`
	// Family distinguishes detection and correlation rules.
	Family string `json:"family"`
	// Title is catalog-authored rule summary text.
	Title string `json:"title"`
	// Description is catalog-authored explanatory text.
	Description string `json:"description"`
	// Severity is the catalog severity.
	Severity string `json:"severity"`
	// Enabled reports effective runtime enablement.
	Enabled bool `json:"enabled"`
}
