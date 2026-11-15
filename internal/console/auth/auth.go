// Package auth authenticates untrusted tokens against trusted configured digests.
// Session ids, CSRF secrets, and login throttles remain bounded and process-local.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
)

// MaxSessions bounds the in-memory session registry; the earliest expiry is evicted first.
const MaxSessions = 1024

// MaxRemotes bounds login-throttle state; new remotes fail closed when it is full.
const MaxRemotes = 4096

// Principal identifies an operator authenticated against a configured token digest.
type Principal struct {
	// Name identifies the configured operator.
	Name string `json:"name"`
	// Role is the configured viewer, analyst, or admin role.
	Role string `json:"role"`
}

// Session contains the principal, independent CSRF token, and absolute expiry.
type Session struct {
	// Principal identifies the authenticated operator.
	Principal Principal `json:"principal"`
	// CSRFToken is independent of the session id and is required for cookie mutations.
	CSRFToken string `json:"csrf_token"`
	// ExpiresAt is the absolute UTC expiry; bearer-only responses use zero time.
	ExpiresAt time.Time `json:"expires_at"`
}

type operator struct {
	principal Principal
	digest    [32]byte
}

type attempt struct {
	start time.Time
	count int
}

// Manager authenticates tokens and owns bounded ephemeral sessions and login attempts.
type Manager struct {
	mu        sync.Mutex
	operators []operator
	sessions  map[string]Session
	attempts  map[string]attempt
	ttl       time.Duration
	now       func() time.Time
}

// New constructs a manager with the system clock and configured token digests.
func New(operators []config.Operator, ttl time.Duration) (*Manager, error) {
	return NewWithClock(operators, ttl, time.Now)
}

// NewWithClock constructs a manager using a trusted clock; nil uses time.Now.
func NewWithClock(operators []config.Operator, ttl time.Duration, now func() time.Time) (*Manager, error) {
	if now == nil {
		now = time.Now
	}
	if len(operators) < 1 || len(operators) > 32 || ttl < time.Minute || ttl > 24*time.Hour {
		return nil, errors.New("auth: invalid operators or TTL")
	}

	manager := &Manager{
		sessions: map[string]Session{},
		attempts: map[string]attempt{},
		ttl:      ttl,
		now:      now,
	}

	for _, operatorConfig := range operators {
		digestBytes, err := hex.DecodeString(operatorConfig.TokenSHA256)
		if err != nil || len(digestBytes) != 32 {
			return nil, errors.New("auth: invalid digest")
		}
		var digest [32]byte
		copy(digest[:], digestBytes)
		manager.operators = append(manager.operators, operator{
			principal: Principal{
				Name: operatorConfig.Name,
				Role: operatorConfig.Role,
			},
			digest: digest,
		})
	}

	return manager, nil
}

// Token returns 32 random bytes encoded as an unpadded URL-safe token.
func Token() (string, error) {
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(entropy[:]), nil
}

// Digest computes the SHA-256 hex digest stored in operator configuration.
func Digest(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// Authenticate compares a bounded token against every configured digest.
func (manager *Manager) Authenticate(token string) (Principal, bool) {
	if len(token) == 0 || len(token) > 4096 {
		return Principal{}, false
	}

	hash := sha256.Sum256([]byte(token))
	principal := Principal{}
	matched := 0
	// Always scan the whole registry, including after a match.
	for _, operator := range manager.operators {
		equal := subtle.ConstantTimeCompare(hash[:], operator.digest[:])
		if equal == 1 {
			principal = operator.principal
		}
		matched |= equal
	}

	return principal, matched == 1
}

// Login creates independent session and CSRF tokens, reclaiming expired or oldest sessions.
func (manager *Manager) Login(principal Principal) (string, Session, error) {
	id, err := Token()
	if err != nil {
		return "", Session{}, err
	}

	csrf, err := Token()
	if err != nil {
		return "", Session{}, err
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()

	now := manager.now()
	for id, session := range manager.sessions {
		if !now.Before(session.ExpiresAt) {
			delete(manager.sessions, id)
		}
	}

	if len(manager.sessions) >= MaxSessions {
		oldID := ""
		var oldest time.Time
		for id, session := range manager.sessions {
			if oldID == "" || session.ExpiresAt.Before(oldest) {
				oldID = id
				oldest = session.ExpiresAt
			}
		}
		delete(manager.sessions, oldID)
	}

	session := Session{
		Principal: principal,
		CSRFToken: csrf,
		ExpiresAt: now.Add(manager.ttl).UTC(),
	}

	manager.sessions[id] = session
	return id, session, nil
}

// Session looks up a session and removes it at or after its expiry.
func (manager *Manager) Session(id string) (Session, bool) {
	if len(id) != 43 {
		return Session{}, false
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()

	session, ok := manager.sessions[id]
	if ok && !manager.now().Before(session.ExpiresAt) {
		delete(manager.sessions, id)
		ok = false
	}

	return session, ok
}

// Logout invalidates a session id, including unknown or already expired ids.
func (manager *Manager) Logout(id string) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	delete(manager.sessions, id)
}

// AllowLogin admits at most ten attempts per remote per minute with bounded remote state.
func (manager *Manager) AllowLogin(remote string) bool {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	now := manager.now()
	attempts := manager.attempts[remote]
	if now.Sub(attempts.start) >= time.Minute {
		attempts = attempt{start: now}
	}

	if attempts.count >= 10 {
		return false
	}

	if _, ok := manager.attempts[remote]; !ok && len(manager.attempts) >= MaxRemotes {
		for address, attempts := range manager.attempts {
			if now.Sub(attempts.start) >= time.Minute {
				delete(manager.attempts, address)
			}
		}
		if len(manager.attempts) >= MaxRemotes {
			return false
		}
	}

	attempts.count++
	manager.attempts[remote] = attempts
	return true
}

// Granted checks the fixed viewer, analyst, and admin role ordering.
func Granted(role, required string) bool {
	rank := map[string]int{
		"viewer":  1,
		"analyst": 2,
		"admin":   3,
	}

	return rank[required] > 0 && rank[role] >= rank[required]
}

// CSRF compares fixed-length CSRF tokens in constant time.
func CSRF(got, want string) bool {
	return len(got) == 43 && len(want) == 43 && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
