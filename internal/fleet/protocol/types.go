package protocol

import (
	"regexp"
	"time"
)

// Enrollment binds a one-time credential and proposed identity to a signed request.
type Enrollment struct {
	// Token is the one-time enrollment credential, never retained in the registry.
	Token string `json:"token"`
	// PublicKey encodes the proposed raw Ed25519 public key as lowercase hex.
	PublicKey string `json:"public_key"`
	// Name is the immutable enrolled node slug.
	Name string `json:"name"`
	// IntervalSeconds sets the 10..300 second reporting cadence used for liveness.
	IntervalSeconds int `json:"interval_seconds"`
}

// Version identifies the reporting executable; these values are self-reported.
type Version struct {
	// Version identifies the reporting application build.
	Version string `json:"version"`
	// Commit identifies the self-reported source revision.
	Commit string `json:"commit"`
	// Go identifies the reporting Go toolchain.
	Go string `json:"go"`
}

// Sensor contains inventory metadata only, without addresses or evidence.
type Sensor struct {
	// ID is the stable node or configured sensor identifier.
	ID string `json:"id"`
	// Kind is the sensor protocol: http, tcp, mcp or ssh.
	Kind string `json:"kind"`
	// State reports running, stopped or failed.
	State string `json:"state"`
}

// Counters counts successful local evidence appends since this process started.
type Counters struct {
	// Interaction counts successfully stored interactions in this process.
	Interaction uint64 `json:"interaction"`
	// CanaryInvocation counts successfully stored canary invocations in this process.
	CanaryInvocation uint64 `json:"canary_invocation"`
	// CorrelationSignal counts directly persisted correlation signals in this process.
	CorrelationSignal uint64 `json:"correlation_signal"`
}

// Heartbeat is the bounded self-reported status projection.
type Heartbeat struct {
	// Forwarding is optional for compatibility with inventory-only agents.
	Forwarding *Forwarding `json:"forwarding,omitempty"`
	// Name is the immutable enrolled node slug.
	Name string `json:"name"`
	// Version identifies the reporting application build.
	Version Version `json:"version"`
	// UptimeSeconds is the nonnegative reporting process uptime.
	UptimeSeconds int64 `json:"uptime_seconds"`
	// Sensors contains at most 64 inventory records without addresses.
	Sensors []Sensor `json:"sensors"`
	// SensorsWanted equals the configured sensor list length.
	SensorsWanted int `json:"sensors_wanted"`
	// SensorsStarted counts started healthy sensors, bounded by SensorsWanted.
	SensorsStarted int `json:"sensors_started"`
	// Counters reports process-local successful appends by classification.
	Counters Counters `json:"counters"`
	// BusDroppedEvents counts process-local bounded-bus drops.
	BusDroppedEvents uint64 `json:"bus_dropped_events"`
	// StorageHealthy is false after an observed append or flush failure.
	StorageHealthy bool `json:"storage_healthy"`
	// ConsoleEnabled reports the local operator-console role flag.
	ConsoleEnabled bool `json:"console_enabled"`
	// HubEnabled reports the local inventory-hub role flag.
	HubEnabled bool `json:"hub_enabled"`
}

// Node is the operator inventory view with read-time liveness.
type Node struct {
	// Forwarding combines reported counters with hub-authored gap accounting.
	Forwarding *Forwarding `json:"forwarding,omitempty"`
	// ID is the stable node or configured sensor identifier.
	ID string `json:"id"`
	// Name is the immutable enrolled node slug.
	Name string `json:"name"`
	// Status is online, stale, offline or permanently revoked.
	Status string `json:"status"`
	// EnrolledAt is the hub-authored enrollment time in UTC RFC3339Nano.
	EnrolledAt string `json:"enrolled_at"`
	// LastSeenAt is the last hub receive time, empty before any heartbeat.
	LastSeenAt string `json:"last_seen_at"`
	// Version identifies the reporting application build.
	Version Version `json:"version"`
	// UptimeSeconds is the nonnegative reporting process uptime.
	UptimeSeconds int64 `json:"uptime_seconds"`
	// Sensors contains at most 64 inventory records without addresses.
	Sensors []Sensor `json:"sensors"`
	// Counters reports process-local successful appends by classification.
	Counters Counters `json:"counters"`
	// BusDroppedEvents counts process-local bounded-bus drops.
	BusDroppedEvents uint64 `json:"bus_dropped_events"`
	// StorageHealthy is false after an observed append or flush failure.
	StorageHealthy bool `json:"storage_healthy"`
	// PublicKeyFingerprint is the full lowercase SHA-256 digest of the public key.
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
}

// AgentStatus exposes only safe local delivery state.
type AgentStatus struct {
	// Forwarding reports local consent, counters and pending delivery state.
	Forwarding Forwarding `json:"forwarding"`
	// Enabled reports whether this role is enabled locally.
	Enabled bool `json:"enabled"`
	// HubURL is the fixed trusted destination origin without credential references.
	HubURL string `json:"hub_url"`
	// NodeID is the local public-key-derived node identifier.
	NodeID string `json:"node_id"`
	// Enrolled reports whether this process has completed signed enrollment.
	Enrolled bool `json:"enrolled"`
	// LastHeartbeatAt is the last locally acknowledged send time, or empty.
	LastHeartbeatAt string `json:"last_heartbeat_at"`
	// LastError contains a fixed safe delivery category, never hub-authored text.
	LastError string `json:"last_error"`
}

// HubStatus describes the configured dedicated inventory listener.
type HubStatus struct {
	// AcceptEvidence reports explicit hub evidence reception consent.
	AcceptEvidence bool `json:"accept_evidence"`
	// Enabled reports whether this role is enabled locally.
	Enabled bool `json:"enabled"`
	// Listen is the dedicated hub authority, including the assigned test port.
	Listen string `json:"listen"`
	// TLS reports whether the hub listener uses TLS.
	TLS bool `json:"tls"`
}

// Status combines local hub and agent roles without exposing credentials.
type Status struct {
	// Hub describes local hub exposure.
	Hub HubStatus `json:"hub"`
	// Agent describes local delivery state.
	Agent AgentStatus `json:"agent"`
}

var slug = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)

// NameValid restricts identity labels to bounded operator-friendly ASCII slugs.
func NameValid(name string) bool {
	return slug.MatchString(name)
}

// Valid checks inventory size, enum and string bounds before persistence.
func (h Heartbeat) Valid() bool {
	if h.Forwarding != nil {
		f := h.Forwarding
		if f.QueuedEvents < 0 || f.QueuedEvents > 4096 || f.QueuedBytes < 0 || f.QueuedBytes > 16<<20 ||
			len(f.LastError) > 64 || len(f.LastForwardedAt) > 40 {
			return false
		}
		if f.LastForwardedAt != "" {
			if _, err := time.Parse(time.RFC3339Nano, f.LastForwardedAt); err != nil {
				return false
			}
		}
	}
	if !NameValid(h.Name) || h.UptimeSeconds < 0 || len(h.Sensors) > 64 ||
		h.SensorsWanted != len(h.Sensors) || h.SensorsStarted < 0 || h.SensorsStarted > h.SensorsWanted {
		return false
	}
	for _, text := range []string{h.Version.Version, h.Version.Commit, h.Version.Go} {
		if len(text) > 128 {
			return false
		}
		for _, value := range text {
			if value < 32 || value > 126 {
				return false
			}
		}
	}
	seen := map[string]bool{}
	for _, sensor := range h.Sensors {
		if !NameValid(sensor.ID) || seen[sensor.ID] {
			return false
		}
		seen[sensor.ID] = true
		switch sensor.Kind {
		case "http", "tcp", "mcp", "ssh":
		default:
			return false
		}
		switch sensor.State {
		case "running", "stopped", "failed":
		default:
			return false
		}
	}
	return true
}
