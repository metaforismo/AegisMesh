package hub

import (
	"sort"
	"time"

	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
)

func (h *Hub) project(record registration) protocol.Node {
	node := record.Node
	if node.Forwarding != nil {
		forwarding := *node.Forwarding
		node.Forwarding = &forwarding
	}
	node.Sensors = append([]protocol.Sensor{}, node.Sensors...)
	if node.Status == "revoked" {
		return node
	}
	lastSeen, _ := time.Parse(time.RFC3339Nano, node.LastSeenAt)
	age := h.now().Sub(lastSeen)
	interval := time.Duration(record.IntervalSeconds) * time.Second
	switch {
	case node.LastSeenAt == "" || age >= 10*interval:
		node.Status = "offline"
	case age >= 3*interval:
		node.Status = "stale"
	default:
		node.Status = "online"
	}
	return node
}

// Nodes snapshots sorted inventory, deriving liveness with the injected clock.
func (h *Hub) Nodes(status string) ([]protocol.Node, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failed.Load() {
		return nil, failure("unavailable")
	}
	switch status {
	case "", "online", "stale", "offline", "revoked":
	default:
		return nil, failure("invalid_argument")
	}
	nodes := []protocol.Node{}
	for _, record := range h.state.Nodes {
		node := h.project(record)
		if status == "" || node.Status == status {
			nodes = append(nodes, node)
		}
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	return nodes, nil
}

// Node returns one safe inventory snapshot.
func (h *Hub) Node(id string) (protocol.Node, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failed.Load() {
		return protocol.Node{}, failure("unavailable")
	}
	record, exists := h.state.Nodes[id]
	if !exists {
		return protocol.Node{}, failure("not_found")
	}
	return h.project(record), nil
}

// Revoke permanently refuses a key's authenticated requests and future enrollment.
func (h *Hub) Revoke(id string) (protocol.Node, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failed.Load() {
		return protocol.Node{}, failure("unavailable")
	}
	record, exists := h.state.Nodes[id]
	if !exists {
		return protocol.Node{}, failure("not_found")
	}
	record.Node.Status = "revoked"
	h.state.Nodes[id] = record
	if err := h.save(); err != nil {
		return protocol.Node{}, err
	}
	return h.project(record), nil
}
