package hub

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"

	"github.com/metaforismo/aegismesh/internal/console/tenant"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
)

// ForTenant returns only an existing startup-declared registry, never creates one from input.
func (h *Hub) ForTenant(name string) *Hub {
	if h == nil {
		return nil
	}
	if h.tenantID == name {
		return h
	}
	return h.partitions[name]
}

// New opens independently quota-bounded registries, resuming legacy state migration.
func New(opts Options) (*Hub, error) {
	names := tenant.Names(opts.Tenants)
	paths, err := tenant.Prepare(opts.StateDir, names)
	if err != nil {
		return nil, err
	}
	partitions := map[string]*Hub{}
	owners := map[string]bool{}
	for _, name := range names {
		childOpts := opts
		childOpts.StateDir = paths[name]
		childOpts.partition = name
		childOpts.Audit = nil
		if opts.TenantAudit != nil {
			childOpts.Audit = func(action, target, outcome string) error {
				return opts.TenantAudit(name, action, target, outcome)
			}
		} else if opts.Audit != nil && name == tenant.Default {
			childOpts.Audit = opts.Audit
		}
		if opts.Evidence != nil {
			evidence := *opts.Evidence
			// The receiver belongs to its registry partition; node IDs never select a tenant.
			evidence.Dir = filepath.Join(paths[name], "evidence")
			if opts.TenantAppend != nil {
				evidence.OnAppend = func(id string, envelope event.Envelope) { opts.TenantAppend(name, id, envelope) }
			}
			childOpts.Evidence = &evidence
		}
		child, err := newSingle(childOpts)
		if err != nil {
			for _, opened := range partitions {
				_ = opened.Close()
			}
			return nil, err
		}
		duplicate := false
		for id := range child.state.Nodes {
			if owners[id] {
				duplicate = true
			}
			owners[id] = true
		}
		if duplicate {
			_ = child.Close()
			for _, opened := range partitions {
				_ = opened.Close()
			}
			return nil, failure("corrupt_state")
		}
		partitions[name] = child
	}
	primary := partitions[tenant.Default]
	if primary == nil {
		primary = partitions[names[0]]
	}
	primary.partitions = partitions
	return primary, nil
}

// routePartition chooses immutable node ownership or the outstanding token's owner.
// The selected registry still performs full parsing, signature verification and token comparison.
func (h *Hub) routePartition(w http.ResponseWriter, r *http.Request) {
	authentication, _, err := protocol.Parse(r, nil)
	if err != nil {
		h.serveSingle(w, r)
		return
	}
	for _, partition := range h.partitions {
		partition.mu.Lock()
		_, exists := partition.state.Nodes[authentication.NodeID]
		partition.mu.Unlock()
		if exists {
			partition.serveSingle(w, r)
			return
		}
	}
	if r.URL.Path != protocol.EnrollPath {
		h.serveSingle(w, r)
		return
	}
	if !h.allowRemote(r.RemoteAddr) {
		h.respond(w, failure("rate_limited"))
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(protocol.BodyLimit(protocol.EnrollPath))))
	if err != nil {
		h.respond(w, failure("body_too_large"))
		return
	}
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	var enrollment protocol.Enrollment
	if json.Unmarshal(body, &enrollment) != nil {
		h.serveSingle(w, r)
		return
	}
	h.enrollMu.Lock()
	defer h.enrollMu.Unlock()
	for _, partition := range h.partitions {
		partition.mu.Lock()
		_, exists := partition.state.Nodes[authentication.NodeID]
		partition.mu.Unlock()
		if exists {
			partition.serveSingle(w, r)
			return
		}
	}
	digest := protocol.Digest([]byte(enrollment.Token))
	var selected *Hub
	for _, partition := range h.partitions {
		partition.mu.Lock()
		for _, token := range partition.state.Tokens {
			if subtle.ConstantTimeCompare([]byte(token.Digest), []byte(digest)) == 1 {
				selected = partition
			}
		}
		partition.mu.Unlock()
	}
	if selected == nil {
		selected = h
	}
	selected.serveSingle(w, r)
}
