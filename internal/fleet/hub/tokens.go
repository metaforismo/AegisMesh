package hub

import (
	"sort"
	"time"

	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
)

// Token is the persisted, secret-free outstanding enrollment credential metadata.
type Token struct {
	// ID is a random hub-authored identifier.
	ID string `json:"id"`
	// ExpiresAt is the absolute expiry in Unix seconds.
	ExpiresAt int64 `json:"expires_at"`
	// Note is bounded operator-authored metadata, never a credential.
	Note string `json:"note"`
}

// Minted returns the raw secret exactly once; only its digest is persisted.
type Minted struct {
	// ID identifies the outstanding credential without exposing its secret.
	ID string `json:"id"`
	// Token is the one-time raw credential; callers must protect it.
	Token string `json:"token"`
	// ExpiresAt is the UTC RFC3339Nano expiry.
	ExpiresAt string `json:"expires_at"`
}

func noteValid(note string) bool {
	if len(note) > 256 {
		return false
	}
	for _, value := range note {
		if value < 32 || value > 126 {
			return false
		}
	}
	return true
}

// Mint creates a one-use 256-bit credential with a 1-hour default and 24-hour maximum TTL.
func (h *Hub) Mint(ttlSeconds int, note string) (Minted, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failed.Load() {
		return Minted{}, failure("unavailable")
	}
	if ttlSeconds == 0 {
		ttlSeconds = 3600
	}
	if ttlSeconds < 1 || ttlSeconds > 86400 || !noteValid(note) {
		return Minted{}, failure("invalid_argument")
	}
	h.prune()
	if len(h.state.Tokens) >= MaxTokens {
		return Minted{}, failure("capacity")
	}
	id, err := protocol.Random(16)
	if err != nil {
		return Minted{}, err
	}
	secret, err := protocol.Random(32)
	if err != nil {
		return Minted{}, err
	}
	expiry := h.now().Add(time.Duration(ttlSeconds) * time.Second)
	h.state.Tokens[id] = tokenRecord{
		Token: Token{
			ID:        id,
			ExpiresAt: expiry.Unix(),
			Note:      note,
		},
		Digest: protocol.Digest([]byte(secret)),
	}
	if err = h.save(); err != nil {
		return Minted{}, err
	}
	return Minted{
		ID:        id,
		Token:     secret,
		ExpiresAt: expiry.UTC().Format(time.RFC3339Nano),
	}, nil
}

// Tokens returns outstanding metadata only, sorted by hub-generated ID.
func (h *Hub) Tokens() ([]Token, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failed.Load() {
		return nil, failure("unavailable")
	}
	h.prune()
	tokens := []Token{}
	for _, record := range h.state.Tokens {
		tokens = append(tokens, record.Token)
	}
	sort.Slice(tokens, func(i, j int) bool { return tokens[i].ID < tokens[j].ID })
	return tokens, nil
}

// DeleteToken revokes a still-outstanding token by ID without ever accepting its secret as a path.
func (h *Hub) DeleteToken(id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failed.Load() {
		return failure("unavailable")
	}
	h.prune()
	if _, exists := h.state.Tokens[id]; !exists {
		return failure("not_found")
	}
	delete(h.state.Tokens, id)
	return h.save()
}
