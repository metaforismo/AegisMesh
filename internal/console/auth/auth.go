// Package auth authenticates untrusted tokens against trusted configured digests.
// Session ids, CSRF secrets, and login throttles remain bounded and process-local.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console/tenant"
)

// MaxSessions bounds sessions per active tenant; eviction never crosses partitions.
const MaxSessions = 1024

// MaxTotalSessions bounds aggregate session state across the declared partition cap.
const MaxTotalSessions = MaxSessions * tenant.MaxTenants

// MaxRemotes bounds login-throttle state; new remotes fail closed when it is full.
const MaxRemotes = 4096

// Principal sources.
const (
	SourceConfig  = "config"
	SourceManaged = "managed"
	SourceOIDC    = "oidc"
)

// Principal identifies an operator authenticated by a token digest or verified OIDC claims.
type Principal struct {
	// ID is the stable identity: cfg:<name>, acc_<hex> or oidc:<12hex>.
	ID string `json:"id"`
	// Source is config, managed or oidc.
	Source string `json:"source"`
	// Kind is person or service.
	Kind string `json:"kind"`
	// KeyID names the managed API key that authenticated this principal, if any.
	KeyID string `json:"-"`
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

// Registry authenticates managed API keys. Match must compare digest against
// every usable key in constant time per entry and return the key's absolute expiry.
type Registry interface {
	Match(digest [32]byte) (Principal, time.Time, bool)
}

// Meta is bounded connection metadata recorded with a new session.
type Meta struct {
	// Remote is the peer host, never a forwarded header.
	Remote string
	// UserAgent is reduced to a fixed client family and never stored.
	UserAgent string
}

// SessionInfo is the listable, secret-free view of a session.
type SessionInfo struct {
	// Handle is an opaque HMAC of the session id; it cannot authenticate.
	Handle string `json:"handle"`
	// Current marks the caller's own session.
	Current bool `json:"current"`
	// AuthMethod is token or oidc.
	AuthMethod string `json:"auth_method"`
	// Tenant is the session's active partition.
	Tenant string `json:"tenant"`
	// CreatedAt is the first login time; tenant switches keep it.
	CreatedAt time.Time `json:"created_at"`
	// LastSeenAt is the last authenticated request on this session.
	LastSeenAt time.Time `json:"last_seen_at"`
	// ExpiresAt is the absolute expiry.
	ExpiresAt time.Time `json:"expires_at"`
	// IdleExpiresAt is when inactivity ends the session, or null when disabled.
	IdleExpiresAt *time.Time `json:"idle_expires_at"`
	// Remote is the peer host recorded at login.
	Remote string `json:"remote"`
	// Client is a fixed-vocabulary client family.
	Client string `json:"client"`
	// AccountID and AccountName identify the principal.
	AccountID   string `json:"account_id"`
	AccountName string `json:"account_name"`
}

type entry struct {
	session  Session
	handle   string
	created  time.Time
	lastSeen time.Time
	remote   string
	client   string
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
	sessions  map[string]entry
	attempts  map[string]attempt
	seen      map[string]time.Time
	registry  Registry
	ttl       time.Duration
	idle      time.Duration
	now       func() time.Time
	handleKey [32]byte
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
		sessions: map[string]entry{},
		attempts: map[string]attempt{},
		seen:     map[string]time.Time{},
		ttl:      ttl,
		now:      now,
	}
	if _, err := rand.Read(manager.handleKey[:]); err != nil {
		return nil, err
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
				ID:         "cfg:" + operatorConfig.Name,
				Source:     SourceConfig,
				Kind:       "person",
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

// SetIdleTimeout ends sessions after this much inactivity; zero disables it.
func (manager *Manager) SetIdleTimeout(idle time.Duration) error {
	if idle != 0 && (idle < 5*time.Minute || idle > 24*time.Hour) {
		return errors.New("auth: invalid idle timeout")
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.idle = idle
	return nil
}

// SetRegistry attaches the managed API key registry; nil detaches it.
func (manager *Manager) SetRegistry(registry Registry) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.registry = registry
}

// Authenticate compares a bounded token against every configured digest and managed key.
func (manager *Manager) Authenticate(token string) (Principal, bool) {
	principal, _, ok := manager.AuthenticateUntil(token)
	return principal, ok
}

// AuthenticateUntil also returns the credential's absolute expiry (zero for config operators).
func (manager *Manager) AuthenticateUntil(token string) (Principal, time.Time, bool) {
	if len(token) == 0 || len(token) > 4096 {
		return Principal{}, time.Time{}, false
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

	manager.mu.Lock()
	registry := manager.registry
	manager.mu.Unlock()
	// The managed registry is always scanned too, so timing does not reveal
	// which registry (if any) holds the digest.
	var managed Principal
	var expiry time.Time
	managedOK := false
	if registry != nil {
		managed, expiry, managedOK = registry.Match(hash)
	}
	if matched == 1 {
		manager.touch(principal)
		return clonePrincipal(principal), time.Time{}, true
	}
	if managedOK {
		return clonePrincipal(managed), expiry, true
	}
	return Principal{}, time.Time{}, false
}

func clonePrincipal(principal Principal) Principal {
	principal.Tenants = slices.Clone(principal.Tenants)
	return principal
}

// touch records in-memory activity for config principals, which have no persisted record.
func (manager *Manager) touch(principal Principal) {
	if principal.Source != SourceConfig {
		return
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.seen) < 64 || !manager.seen[principal.ID].IsZero() {
		manager.seen[principal.ID] = manager.now().UTC()
	}
}

// LastSeen reports in-memory activity of a config principal since process start.
func (manager *Manager) LastSeen(id string) (time.Time, bool) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	seen, ok := manager.seen[id]
	return seen, ok
}

// Operators returns the config principals, without digests.
func (manager *Manager) Operators() []Principal {
	out := make([]Principal, 0, len(manager.operators))
	for _, operator := range manager.operators {
		out = append(out, clonePrincipal(operator.principal))
	}
	return out
}

// Handle derives the opaque listable handle of a session id with a per-process key.
func (manager *Manager) Handle(id string) string {
	mac := hmac.New(sha256.New, manager.handleKey[:])
	mac.Write([]byte(id))
	return "ses_" + hex.EncodeToString(mac.Sum(nil))[:16]
}

// Login creates independent session and CSRF tokens, reclaiming expired or oldest sessions.
func (manager *Manager) Login(principal Principal) (string, Session, error) {
	return manager.LoginUntil(principal, time.Time{})
}

// LoginUntil creates a session capped by the identity credential's absolute expiry.
func (manager *Manager) LoginUntil(principal Principal, expiry time.Time) (string, Session, error) {
	return manager.LoginWith(principal, expiry, Meta{})
}

// LoginWith creates a session capped by expiry and records bounded connection metadata.
func (manager *Manager) LoginWith(principal Principal, expiry time.Time, meta Meta) (string, Session, error) {
	return manager.login(principal, expiry, meta.Remote, ClientFamily(meta.UserAgent), time.Time{})
}

func (manager *Manager) login(principal Principal, expiry time.Time, remote, client string, created time.Time) (string, Session, error) {
	if len(remote) > 64 {
		remote = ""
	}
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
	for id, existing := range manager.sessions {
		if manager.expired(existing, now) {
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
		if existing.session.Principal.Tenant != principal.Tenant {
			continue
		}
		count++
		if oldestID == "" || existing.session.ExpiresAt.Before(oldest) {
			oldestID, oldest = existingID, existing.session.ExpiresAt
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

	if created.IsZero() {
		created = now.UTC()
	}
	manager.sessions[id] = entry{
		session: session, handle: manager.Handle(id), created: created,
		lastSeen: now.UTC(), remote: remote, client: client,
	}
	if principal.Source == SourceConfig && (len(manager.seen) < 64 || !manager.seen[principal.ID].IsZero()) {
		manager.seen[principal.ID] = now.UTC()
	}
	return id, cloneSession(session), nil
}

func cloneSession(session Session) Session {
	session.Tenants = slices.Clone(session.Tenants)
	session.Principal = clonePrincipal(session.Principal)
	return session
}

func (manager *Manager) expired(existing entry, now time.Time) bool {
	return !now.Before(existing.session.ExpiresAt) ||
		manager.idle > 0 && !now.Before(existing.lastSeen.Add(manager.idle))
}

// Session looks up a session, removes it at or after its absolute or idle
// expiry, and records the lookup as activity.
func (manager *Manager) Session(id string) (Session, bool) {
	return manager.lookup(id, true)
}

// Peek looks up a session like Session without counting as activity; event
// streams use it so an open tab alone does not defeat the idle timeout.
func (manager *Manager) Peek(id string) (Session, bool) {
	return manager.lookup(id, false)
}

func (manager *Manager) lookup(id string, activity bool) (Session, bool) {
	if len(id) != 43 {
		return Session{}, false
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()

	now := manager.now()
	existing, ok := manager.sessions[id]
	if !ok {
		return Session{}, false
	}
	if manager.expired(existing, now) {
		delete(manager.sessions, id)
		return Session{}, false
	}
	if activity {
		existing.lastSeen = now.UTC()
		manager.sessions[id] = existing
		principal := existing.session.Principal
		if principal.Source == SourceConfig {
			manager.seen[principal.ID] = now.UTC()
		}
	}
	return cloneSession(existing.session), true
}

// Sessions lists live sessions of one principal, or of everyone when principalID is empty.
// currentID marks the caller's own session; it is never returned.
func (manager *Manager) Sessions(principalID, currentID string) []SessionInfo {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	now := manager.now()
	out := []SessionInfo{}
	for id, existing := range manager.sessions {
		if manager.expired(existing, now) {
			delete(manager.sessions, id)
			continue
		}
		if principalID != "" && existing.session.Principal.ID != principalID {
			continue
		}
		info := manager.info(existing)
		info.Current = currentID != "" && id == currentID
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].Handle < out[j].Handle
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out
}

// CountSessions counts live sessions of one principal.
func (manager *Manager) CountSessions(principalID string) int {
	return len(manager.Sessions(principalID, ""))
}

func (manager *Manager) info(existing entry) SessionInfo {
	info := SessionInfo{
		Handle: existing.handle, AuthMethod: existing.session.Principal.AuthMethod,
		Tenant: existing.session.Tenant, CreatedAt: existing.created, LastSeenAt: existing.lastSeen,
		ExpiresAt: existing.session.ExpiresAt.UTC(), Remote: existing.remote, Client: existing.client,
		AccountID: existing.session.Principal.ID, AccountName: existing.session.Principal.Name,
	}
	if manager.idle > 0 {
		idle := existing.lastSeen.Add(manager.idle).UTC()
		if idle.After(info.ExpiresAt) {
			idle = info.ExpiresAt
		}
		info.IdleExpiresAt = &idle
	}
	return info
}

// Revoke deletes the session with handle when owner is empty or owns it.
func (manager *Manager) Revoke(handle, owner string) (SessionInfo, bool) {
	if len(handle) != 20 {
		return SessionInfo{}, false
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	for id, existing := range manager.sessions {
		if subtle.ConstantTimeCompare([]byte(existing.handle), []byte(handle)) != 1 {
			continue
		}
		if owner != "" && existing.session.Principal.ID != owner {
			return SessionInfo{}, false
		}
		info := manager.info(existing)
		delete(manager.sessions, id)
		return info, true
	}
	return SessionInfo{}, false
}

// RevokePrincipal deletes every session of one principal and returns how many ended.
func (manager *Manager) RevokePrincipal(principalID string) int {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	count := 0
	for id, existing := range manager.sessions {
		if principalID != "" && existing.session.Principal.ID == principalID {
			delete(manager.sessions, id)
			count++
		}
	}
	return count
}

// RevokeKey deletes every session that a managed API key created.
func (manager *Manager) RevokeKey(keyID string) int {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	count := 0
	for id, existing := range manager.sessions {
		if keyID != "" && existing.session.Principal.KeyID == keyID {
			delete(manager.sessions, id)
			count++
		}
	}
	return count
}

// Logout invalidates a session id, including unknown or already expired ids.
func (manager *Manager) Logout(id string) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	delete(manager.sessions, id)
}

// LoginAvailable checks an existing attempt budget without charging successful API calls.
func (manager *Manager) LoginAvailable(remote string) bool {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	now := manager.now()
	if attempts, exists := manager.attempts[remote]; exists {
		return now.Sub(attempts.start) >= time.Minute || attempts.count < 10
	}
	if len(manager.attempts) >= MaxRemotes {
		for key, attempts := range manager.attempts {
			if now.Sub(attempts.start) >= time.Minute {
				delete(manager.attempts, key)
			}
		}
	}
	return len(manager.attempts) < MaxRemotes
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
	if !ok || manager.expired(current, manager.now()) || !slices.Contains(current.session.Principal.Tenants, name) {
		manager.mu.Unlock()
		return "", Session{}, errors.New("auth: tenant unavailable")
	}
	delete(manager.sessions, id)
	manager.mu.Unlock()
	principal := current.session.Principal
	principal.Tenant = name
	return manager.login(principal, current.session.ExpiresAt, current.remote, current.client, current.created)
}
