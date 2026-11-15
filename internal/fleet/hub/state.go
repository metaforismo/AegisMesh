package hub

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
)

func encodeState(state snapshot) ([]byte, error) {
	return json.Marshal(state)
}

func decodeState(body []byte, state *snapshot) error {
	// Snapshots have one exact canonical encoding; reject alternate encodings and duplicate fields.
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(state); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return protocol.ErrInvalid
	}
	encoded, err := encodeState(*state)
	if err != nil || !bytes.Equal(encoded, body) {
		return protocol.ErrInvalid
	}
	return nil
}

func (h *Hub) validState() bool {
	if h.state.Version != 1 || h.state.Nodes == nil || h.state.Tokens == nil || h.state.Nonces == nil ||
		len(h.state.Nodes) > MaxNodes || len(h.state.Tokens) > MaxTokens || len(h.state.Nonces) > MaxNonces {
		return false
	}
	for id, record := range h.state.Nodes {
		if record.Node.Tenant != "" && record.Node.Tenant != h.tenantID {
			return false
		}
		key, err := hex.DecodeString(record.PublicKey)
		node := record.Node
		if err != nil || !protocol.Hex(record.PublicKey, 32) || protocol.ID(key) != id || node.ID != id ||
			!protocol.NameValid(node.Name) || record.IntervalSeconds < 10 || record.IntervalSeconds > 300 ||
			node.PublicKeyFingerprint != protocol.Digest(key) || !validTime(node.EnrolledAt) ||
			(node.LastSeenAt != "" && !validTime(node.LastSeenAt)) ||
			(node.Status != "online" && node.Status != "revoked") {
			return false
		}
		if node.LastSeenAt != "" && !record.Heartbeat.Valid() {
			return false
		}
		heartbeat := protocol.Heartbeat{
			Name:          node.Name,
			Version:       node.Version,
			UptimeSeconds: node.UptimeSeconds,
			Sensors:       node.Sensors,
			SensorsWanted: len(node.Sensors),
		}
		if !heartbeat.Valid() {
			return false
		}
	}
	for id, record := range h.state.Tokens {
		if record.Tenant != "" && record.Tenant != h.tenantID {
			return false
		}
		if id != record.ID || !protocol.Hex(id, 16) || !protocol.Hex(record.Digest, 32) ||
			record.ExpiresAt <= 0 || !noteValid(record.Note) {
			return false
		}
	}
	counts := make(map[string]int)
	for key, expiry := range h.state.Nonces {
		parts := strings.Split(key, ":")
		if len(parts) != 2 || !protocol.Hex(parts[0], 16) || !protocol.Hex(parts[1], 16) || expiry <= 0 {
			return false
		}
		if _, exists := h.state.Nodes[parts[0]]; !exists {
			return false
		}
		// Older draft snapshots may contain more entries per node. Expired entries
		// can be discarded on load; never silently evict live replay protection.
		if expiry >= h.now().Unix() {
			counts[parts[0]]++
			if counts[parts[0]] > MaxNoncesPerNode {
				return false
			}
		}
	}
	return true
}

func validTime(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.Unix() > 0
}
