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
	"github.com/metaforismo/aegismesh/internal/console/tenant"
	"slices"
	"sync"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
)

// MaxSessions bounds sessions per active tenant; eviction never crosses partitions.
const MaxSessions = 1024

// MaxTotalSessions bounds aggregate session state across the declared partition cap.
const MaxTotalSessions = MaxSessions * tenant.MaxTenants

// MaxRemotes bounds login-throttle state; new remotes fail closed when it is full.
const MaxRemotes = 4096

// Principal identifies an operator authenticated by a token digest or verified OIDC claims.
type Principal struct {
	// AuthMethod identifies token or oidc authentication.
	AuthMethod string `json:"auth_method"`
	// Tenant is the one active isolation partition.
	Tenant string `json:"tenant"`
	// Tenants is the bounded membership set.
	Tenants []string `json:"tenants"`
	// Issuer and Subject retain stable federated audit identity, never bearer credentials.
	Issuer  string `json:"-"`
	Subject string `json:"-"`
	// Name identifies the configured operator.
	Name string `json:"name"`
	// Role is the configured viewer, analyst, or admin role.
	Role string `json:"role"`
}

// Session contains the principal, independent CSRF token, and absolute expiry.
type Session struct {
	// Tenant is the active partition and Tenants is the available membership set.
	Tenant  string   `json:"tenant"`
	Tenants []string `json:"tenants"`
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
	if len(operators) > 32 || ttl < time.Minute || ttl > 24*time.Hour {
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
				Name:       operatorConfig.Name,
				AuthMethod: "token",
				Tenant:     tenant.Membership(operatorConfig.Tenants)[0],
				Tenants:    tenant.Membership(operatorConfig.Tenants),
				Role:       operatorConfig.Role,
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
	return manager.LoginUntil(principal, time.Time{})
}

// LoginUntil creates a session capped by the identity credential's absolute expiry.
func (manager *Manager) LoginUntil(principal Principal, expiry time.Time) (string, Session, error) {
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

	if principal.AuthMethod == "" {
		principal.AuthMethod = "token"
	}
	principal.Tenants = tenant.Membership(principal.Tenants)
	if principal.Tenant == "" {
		principal.Tenant = principal.Tenants[0]
	}
	count := 0
	oldestID := ""
	var oldest time.Time
	for existingID, existing := range manager.sessions {
		if existing.Principal.Tenant != principal.Tenant {
			continue
		}
		count++
		if oldestID == "" || existing.ExpiresAt.Before(oldest) {
			oldestID, oldest = existingID, existing.ExpiresAt
		}
	}
	if count >= MaxSessions {
		delete(manager.sessions, oldestID)
	}
	if len(manager.sessions) >= MaxTotalSessions {
		return "", Session{}, errors.New("auth: global session capacity")
	}

	end := now.Add(manager.ttl).UTC()
	if !expiry.IsZero() && expiry.Before(end) {
		end = expiry
	}
	if !end.After(now) {
		return "", Session{}, errors.New("auth: expired credential")
	}
	session := Session{
		Tenant:    principal.Tenant,
		Tenants:   slices.Clone(principal.Tenants),
		Principal: principal,
		CSRFToken: csrf,
		ExpiresAt: end,
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

// Switch rotates the session id and CSRF token, invalidating streams of the old tenant.
func (manager *Manager) Switch(id, name string) (string, Session, error) {
	manager.mu.Lock()
	current, ok := manager.sessions[id]
	if !ok || !manager.now().Before(current.ExpiresAt) || !slices.Contains(current.Principal.Tenants, name) {
		manager.mu.Unlock()
		return "", Session{}, errors.New("auth: tenant unavailable")
	}
	delete(manager.sessions, id)
	manager.mu.Unlock()
	current.Principal.Tenant = name
	return manager.LoginUntil(current.Principal, current.ExpiresAt)
}
