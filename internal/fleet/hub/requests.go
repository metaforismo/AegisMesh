package hub

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
)

// ServeHTTP accepts only versioned enrollment and heartbeat submissions on a separate listener.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if !h.allowRemote(r.RemoteAddr) {
		h.reject(w, failure("rate_limited"))
		return
	}
	if r.Method != http.MethodPost || (r.URL.Path != protocol.EnrollPath && r.URL.Path != protocol.HeartbeatPath) {
		h.reject(w, failure("not_found"))
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		h.reject(w, failure("invalid_argument"))
		return
	}
	// Parse header shape before reading a potentially slow body. The body hash is
	// recomputed below, once the bounded read has completed.
	if _, _, err := protocol.Parse(r, nil); err != nil {
		h.reject(w, failure("unauthenticated"))
		return
	}
	if r.ContentLength > protocol.MaxBodyBytes {
		h.reject(w, failure("body_too_large"))
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, protocol.MaxBodyBytes))
	if err != nil {
		h.reject(w, failure("body_too_large"))
		return
	}
	auth, canonical, err := protocol.Parse(r, body)
	if err != nil {
		h.reject(w, failure("unauthenticated"))
		return
	}
	now := h.now()
	if auth.Time.Before(now.Add(-protocol.Window)) || auth.Time.After(now.Add(protocol.Window)) {
		h.reject(w, failure("clock_skew"))
		return
	}
	var enrollInput protocol.Enrollment
	var heartbeatInput protocol.Heartbeat
	var publicKey string
	if r.URL.Path == protocol.EnrollPath {
		if protocol.Decode(body, &enrollInput) != nil || !protocol.NameValid(enrollInput.Name) ||
			!protocol.Hex(enrollInput.PublicKey, ed25519.PublicKeySize) || enrollInput.IntervalSeconds < 10 ||
			enrollInput.IntervalSeconds > 300 || (enrollInput.Token != "" && !protocol.Hex(enrollInput.Token, 32)) {
			h.reject(w, failure("invalid_argument"))
			return
		}
		publicKey = enrollInput.PublicKey
	} else {
		if protocol.Decode(body, &heartbeatInput) != nil || !heartbeatInput.Valid() {
			h.reject(w, failure("invalid_argument"))
			return
		}
		// The sole state dependency needed for signature verification is a copied
		// immutable public key. Crypto and JSON parsing never hold the hub mutex.
		h.mu.Lock()
		publicKey = h.state.Nodes[auth.NodeID].PublicKey
		h.mu.Unlock()
	}
	key, _ := hex.DecodeString(publicKey)
	if len(key) != ed25519.PublicKeySize || protocol.ID(key) != auth.NodeID ||
		!ed25519.Verify(key, []byte(canonical), auth.Signature) {
		h.reject(w, failure("unauthenticated"))
		return
	}
	h.mu.Lock()
	if h.failed.Load() {
		h.mu.Unlock()
		h.reject(w, failure("unavailable"))
		return
	}
	var node protocol.Node
	if r.URL.Path == protocol.EnrollPath {
		node, err = h.enroll(enrollInput, auth)
	} else {
		node, err = h.heartbeat(heartbeatInput, auth)
	}
	h.mu.Unlock()
	if err != nil {
		h.reject(w, err)
		return
	}
	h.requests.Inc("accepted")
	_ = json.NewEncoder(w).Encode(map[string]string{"node_id": node.ID})
}

func (h *Hub) reject(w http.ResponseWriter, err error) {
	h.queueRejection()
	h.respond(w, err)
}

func (h *Hub) respond(w http.ResponseWriter, err error) {
	code := Code(err)
	status := http.StatusBadRequest
	switch code {
	case "unauthenticated", "clock_skew", "replay", "invalid_token":
		status = http.StatusUnauthorized
	case "rate_limited":
		status = http.StatusTooManyRequests
		seconds := 60
		if typed, ok := err.(*Error); ok && typed.retryAfter > 0 {
			seconds = typed.retryAfter
		}
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
	case "revoked":
		status = http.StatusForbidden
	case "not_found":
		status = http.StatusNotFound
	case "body_too_large":
		status = http.StatusRequestEntityTooLarge
	case "capacity", "unavailable":
		status = http.StatusServiceUnavailable
	}
	h.requests.Inc(code)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code}})
}

func (h *Hub) replayed(auth protocol.Authentication) bool {
	expiry, exists := h.replay[auth.NodeID][auth.Nonce]
	return exists && expiry >= h.now().Unix()
}

func (h *Hub) remember(auth protocol.Authentication) error {
	if h.replayed(auth) {
		return failure("replay")
	}
	nonces := h.replay[auth.NodeID]
	now := h.now().Unix()
	for nonce, expiry := range nonces {
		if expiry < now {
			delete(nonces, nonce)
			delete(h.state.Nonces, auth.NodeID+":"+nonce)
		}
	}
	if len(nonces) >= MaxNoncesPerNode {
		return failure("capacity")
	}
	if nonces == nil {
		nonces = make(map[string]int64)
		h.replay[auth.NodeID] = nonces
	}
	expiry := auth.Time.Add(protocol.Window).Unix()
	nonces[auth.Nonce] = expiry
	h.state.Nonces[auth.NodeID+":"+auth.Nonce] = expiry
	h.dirty = true
	return nil
}

func (h *Hub) enroll(input protocol.Enrollment, auth protocol.Authentication) (protocol.Node, error) {
	key, _ := hex.DecodeString(input.PublicKey)
	if known, exists := h.state.Nodes[auth.NodeID]; exists {
		if known.PublicKey != input.PublicKey || known.Node.Status == "revoked" {
			return protocol.Node{}, failure("revoked")
		}
		if h.replayed(auth) {
			return protocol.Node{}, failure("replay")
		}
		if last := h.lastEnrollment[auth.NodeID]; !last.IsZero() &&
			h.now().Sub(last) < time.Duration(known.IntervalSeconds)*time.Second {
			return protocol.Node{}, rateLimited(time.Duration(known.IntervalSeconds)*time.Second - h.now().Sub(last))
		}
		if err := h.remember(auth); err != nil {
			return protocol.Node{}, err
		}
		h.lastEnrollment[auth.NodeID] = h.now()
		// Unchanged retries only dirty replay state; they cannot force disk writes.
		if known.IntervalSeconds != input.IntervalSeconds {
			known.IntervalSeconds = input.IntervalSeconds
			h.state.Nodes[auth.NodeID] = known
			if err := h.save(); err != nil {
				return protocol.Node{}, err
			}
		}
		return h.project(known), nil
	}
	h.prune()
	matched := ""
	digest := protocol.Digest([]byte(input.Token))
	for id, token := range h.state.Tokens {
		if subtle.ConstantTimeCompare([]byte(token.Digest), []byte(digest)) == 1 {
			matched = id
		}
	}
	if matched == "" {
		return protocol.Node{}, failure("invalid_token")
	}
	if len(h.state.Nodes) >= MaxNodes {
		return protocol.Node{}, failure("capacity")
	}
	if err := h.remember(auth); err != nil {
		return protocol.Node{}, err
	}
	node := protocol.Node{
		ID:                   auth.NodeID,
		Name:                 input.Name,
		Status:               "online",
		EnrolledAt:           h.now().UTC().Format(time.RFC3339Nano),
		Sensors:              []protocol.Sensor{},
		PublicKeyFingerprint: protocol.Digest(key),
	}
	h.state.Nodes[node.ID] = registration{
		PublicKey:       input.PublicKey,
		IntervalSeconds: input.IntervalSeconds,
		Node:            node,
	}
	h.lastEnrollment[node.ID] = h.now()
	delete(h.state.Tokens, matched)
	if err := h.save(); err != nil {
		return protocol.Node{}, err
	}
	if err := h.record("fleet.node.enroll", node.ID, "ok"); err != nil {
		return protocol.Node{}, err
	}
	return node, nil
}

func (h *Hub) heartbeat(input protocol.Heartbeat, auth protocol.Authentication) (protocol.Node, error) {
	record, exists := h.state.Nodes[auth.NodeID]
	if !exists {
		return protocol.Node{}, failure("unauthenticated")
	}
	if record.Node.Status == "revoked" {
		return protocol.Node{}, failure("revoked")
	}
	if h.replayed(auth) {
		return protocol.Node{}, failure("replay")
	}
	if record.Node.LastSeenAt != "" {
		last, _ := time.Parse(time.RFC3339Nano, record.Node.LastSeenAt)
		if h.now().Sub(last) < time.Duration(record.IntervalSeconds)*time.Second {
			return protocol.Node{}, rateLimited(time.Duration(record.IntervalSeconds)*time.Second - h.now().Sub(last))
		}
	}
	if input.Name != record.Node.Name {
		return protocol.Node{}, failure("invalid_argument")
	}
	if err := h.remember(auth); err != nil {
		return protocol.Node{}, err
	}
	record.Heartbeat = input
	record.Node.LastSeenAt = h.now().UTC().Format(time.RFC3339Nano)
	record.Node.Version = input.Version
	record.Node.UptimeSeconds = input.UptimeSeconds
	record.Node.Sensors = append([]protocol.Sensor{}, input.Sensors...)
	record.Node.Counters = input.Counters
	record.Node.BusDroppedEvents = input.BusDroppedEvents
	record.Node.StorageHealthy = input.StorageHealthy
	h.state.Nodes[auth.NodeID] = record
	h.dirty = true
	return record.Node, nil
}
