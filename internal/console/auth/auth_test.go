package auth

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
)

func newManager(t *testing.T, now func() time.Time) *Manager {
	t.Helper()
	manager, err := NewWithClock([]config.Operator{
		{
			Name:        "alice",
			Role:        "admin",
			TokenSHA256: Digest("synthetic-token"),
		},
	}, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func TestAuthenticate(t *testing.T) {
	manager := newManager(t, nil)
	cases := []struct {
		name  string
		token string
		want  bool
	}{
		{
			name:  "valid",
			token: "synthetic-token",
			want:  true,
		},
		{name: "empty"},
		{
			name:  "wrong",
			token: "wrong",
		},
		{
			name:  "case sensitive",
			token: "synthetic-tokeN",
		},
		{
			name:  "oversized",
			token: strings.Repeat("x", 4097),
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			principal, ok := manager.Authenticate(testCase.token)
			if ok != testCase.want {
				t.Fatalf("authenticated = %t; want %t", ok, testCase.want)
			}
			if ok && (principal.Name != "alice" || principal.Role != "admin" || principal.AuthMethod != "token" ||
				principal.Tenant != "default" || len(principal.Tenants) != 1) {
				t.Fatalf("principal = %+v", principal)
			}
		})
	}
}

func TestSessionsExpireRevokeAndEvict(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	manager := newManager(t, func() time.Time {
		return now
	})
	principal, _ := manager.Authenticate("synthetic-token")
	first, session, err := manager.Login(principal)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 43 || len(session.CSRFToken) != 43 || first == session.CSRFToken {
		t.Fatalf("invalid session entropy lengths or reuse")
	}
	for attempt := range MaxSessions {
		now = now.Add(time.Second)
		if _, _, err := manager.Login(principal); err != nil {
			t.Fatal(err)
		}
		if len(manager.sessions) > MaxSessions {
			t.Fatalf("session count exceeded cap at %d", attempt)
		}
	}
	if len(manager.sessions) != MaxSessions {
		t.Fatalf("session count = %d", len(manager.sessions))
	}
	if _, ok := manager.Session(first); ok {
		t.Fatal("oldest session survived eviction")
	}
	newest, _, err := manager.Login(principal)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := manager.Session(newest); !ok {
		t.Fatal("newest session was evicted")
	}
	manager.Logout(newest)
	if _, ok := manager.Session(newest); ok {
		t.Fatal("logout did not revoke session")
	}

	expiring, session, err := manager.Login(principal)
	if err != nil {
		t.Fatal(err)
	}
	now = session.ExpiresAt.Add(-time.Nanosecond)
	if _, ok := manager.Session(expiring); !ok {
		t.Fatal("session expired early")
	}
	now = session.ExpiresAt
	if _, ok := manager.Session(expiring); ok {
		t.Fatal("session accepted at TTL boundary")
	}
	if _, retained := manager.sessions[expiring]; retained {
		t.Fatal("expired session retained")
	}
}

func TestLoginThrottleBoundsAndExpiry(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	manager := newManager(t, func() time.Time {
		return now
	})
	for attempt := range 11 {
		if got := manager.AllowLogin("127.0.0.1"); got != (attempt < 10) {
			t.Fatalf("login attempt %d allowed = %t", attempt, got)
		}
	}
	for remote := range MaxRemotes + 50 {
		allowed := manager.AllowLogin(fmt.Sprintf("2001:db8::%x", remote))
		if allowed != (remote < MaxRemotes-1) {
			t.Fatalf("remote %d allowed = %t", remote, allowed)
		}
		if len(manager.attempts) > MaxRemotes {
			t.Fatal("remote state exceeded bound")
		}
	}
	now = now.Add(time.Minute - time.Nanosecond)
	if manager.AllowLogin("new-remote") {
		t.Fatal("remote quota expired early")
	}
	now = now.Add(time.Nanosecond)
	if !manager.AllowLogin("new-remote") {
		t.Fatal("expired entries were not reclaimed")
	}
	if len(manager.attempts) != 1 {
		t.Fatalf("remote state after reclamation = %d", len(manager.attempts))
	}
	if !manager.AllowLogin("127.0.0.1") {
		t.Fatal("per-address rate limit did not expire")
	}
}

func TestCSRFComparison(t *testing.T) {
	token := strings.Repeat("a", 43)
	for _, testCase := range []struct {
		name  string
		got   string
		want  string
		valid bool
	}{
		{
			name:  "equal",
			got:   token,
			want:  token,
			valid: true,
		},
		{
			name: "wrong",
			got:  strings.Repeat("b", 43),
			want: token,
		},
		{
			name: "short",
			got:  "a",
			want: token,
		},
		{name: "empty"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if CSRF(testCase.got, testCase.want) != testCase.valid {
				t.Fatal("unexpected CSRF result")
			}
		})
	}
}

func TestRoles(t *testing.T) {
	for _, role := range []string{
		"",
		"unknown",
		"viewer",
		"analyst",
		"admin",
	} {
		for _, required := range []string{
			"",
			"unknown",
			"viewer",
			"analyst",
			"admin",
		} {
			t.Run(role+"/"+required, func(t *testing.T) {
				validRequired := required == "viewer" || required == "analyst" || required == "admin"
				want := validRequired && (role == "admin" || role == required || role == "analyst" && required == "viewer")
				if Granted(role, required) != want {
					t.Fatalf("Granted(%q, %q) != %t", role, required, want)
				}
			})
		}
	}
}

func TestSessionEvictionCannotCrossTenant(t *testing.T) {
	now := time.Now()
	manager := newManager(t, func() time.Time { return now })
	b, _, err := manager.Login(Principal{Name: "B", Role: "viewer", Tenant: "bravo", Tenants: []string{"bravo"}})
	if err != nil {
		t.Fatal(err)
	}
	a := Principal{Name: "A", Role: "viewer", Tenant: "default", Tenants: []string{"default"}}
	first, _, err := manager.Login(a)
	if err != nil {
		t.Fatal(err)
	}
	for range MaxSessions {
		now = now.Add(time.Second)
		if _, _, err := manager.Login(a); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := manager.Session(first); ok {
		t.Fatal("A did not evict its oldest session")
	}
	if _, ok := manager.Session(b); !ok {
		t.Fatal("A evicted B's session")
	}
}

func TestLoginAvailableHonorsCapacityAndPrunesExpiredKeys(t *testing.T) {
	now := time.Unix(1800000000, 0)
	manager := newManager(t, func() time.Time { return now })
	for i := 0; i < MaxRemotes; i++ {
		if !manager.AllowLogin(fmt.Sprintf("remote-%d", i)) {
			t.Fatal("early quota")
		}
	}
	if manager.LoginAvailable("new-remote") {
		t.Fatal("full throttle table admitted unknown remote")
	}
	now = now.Add(time.Minute)
	if !manager.LoginAvailable("new-remote") || len(manager.attempts) != 0 {
		t.Fatal("expired quota did not recover")
	}
}

func TestClientFamilyIsClosedVocabulary(t *testing.T) {
	for _, testCase := range []struct{ ua, want string }{
		{"", ClientUnknown},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36", "Chrome on macOS"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36 Edg/131.0", "Edge on Windows"},
		{"Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0", "Firefox on Linux"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1", "Safari on iOS"},
		{"curl/8.7.1", "curl"},
		{"python-requests/2.32", "Python client"},
		{"Go-http-client/1.1", "Go HTTP client"},
		{"<script>alert(1)</script>", ClientOther},
		{strings.Repeat("A", 10000), ClientOther},
	} {
		if got := ClientFamily(testCase.ua); got != testCase.want {
			t.Errorf("ClientFamily(%.40q) = %q; want %q", testCase.ua, got, testCase.want)
		}
	}
}

type fakeRegistry struct {
	digest [32]byte
	calls  int
}

func (registry *fakeRegistry) Match(digest [32]byte) (Principal, time.Time, bool) {
	registry.calls++
	if digest != registry.digest {
		return Principal{}, time.Time{}, false
	}
	return Principal{ID: "acc_0123456789abcdef", Source: SourceManaged, Name: "svc", Role: "viewer",
			AuthMethod: "token", Tenant: "default", Tenants: []string{"default"}, KeyID: "key_000000000001"},
		time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), true
}

func TestRegistryIsAlwaysScannedAndConfigIdentityIsStable(t *testing.T) {
	manager := newManager(t, nil)
	registry := &fakeRegistry{digest: sha256.Sum256([]byte("amk_synthetic"))}
	manager.SetRegistry(registry)
	principal, expiry, ok := manager.AuthenticateUntil("synthetic-token")
	if !ok || principal.ID != "cfg:alice" || principal.Source != SourceConfig || !expiry.IsZero() {
		t.Fatalf("config principal = %+v %v %v", principal, expiry, ok)
	}
	principal, expiry, ok = manager.AuthenticateUntil("amk_synthetic")
	if !ok || principal.Source != SourceManaged || expiry.IsZero() {
		t.Fatalf("managed principal = %+v %v %v", principal, expiry, ok)
	}
	if _, ok = manager.Authenticate("unknown"); ok {
		t.Fatal("unknown token authenticated")
	}
	if registry.calls != 3 {
		t.Fatalf("registry scanned %d times; want 3 (every attempt)", registry.calls)
	}
}

func TestSessionMetadataIdleHandlesAndRevocation(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	manager := newManager(t, func() time.Time { return now })
	if err := manager.SetIdleTimeout(time.Minute); err == nil {
		t.Fatal("idle below five minutes accepted")
	}
	if err := manager.SetIdleTimeout(10 * time.Minute); err != nil {
		t.Fatal(err)
	}
	principal, _ := manager.Authenticate("synthetic-token")
	id, _, err := manager.LoginWith(principal, time.Time{}, Meta{Remote: "203.0.113.7", UserAgent: "curl/8"})
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := manager.LoginWith(principal, time.Time{}, Meta{})
	if err != nil {
		t.Fatal(err)
	}
	list := manager.Sessions("cfg:alice", id)
	if len(list) != 2 {
		t.Fatalf("sessions = %+v", list)
	}
	var current SessionInfo
	for _, info := range list {
		if info.Current {
			current = info
		}
		if strings.Contains(info.Handle, id) || strings.Contains(info.Handle, other) || len(info.Handle) != 20 {
			t.Fatalf("handle %q leaks or has wrong shape", info.Handle)
		}
	}
	if current.Remote != "203.0.113.7" || current.Client != "curl" || current.IdleExpiresAt == nil ||
		!current.IdleExpiresAt.Equal(now.Add(10*time.Minute)) || current.Handle != manager.Handle(id) {
		t.Fatalf("current = %+v", current)
	}
	// A handle can never be used as a session id.
	if _, ok := manager.Session(current.Handle); ok {
		t.Fatal("handle authenticated as a session id")
	}
	// Peek does not refresh idle activity; Session does.
	now = now.Add(9 * time.Minute)
	if _, ok := manager.Peek(id); !ok {
		t.Fatal("peek before idle expiry failed")
	}
	if _, ok := manager.Session(other); !ok {
		t.Fatal("session before idle expiry failed")
	}
	now = now.Add(2 * time.Minute)
	if _, ok := manager.Peek(id); ok {
		t.Fatal("idle session survived")
	}
	if _, ok := manager.Session(other); !ok {
		t.Fatal("recently active session expired")
	}
	if _, ok := manager.Revoke(manager.Handle(other), "cfg:bob"); ok {
		t.Fatal("foreign owner revoked a session")
	}
	if _, ok := manager.Revoke(manager.Handle(other), "cfg:alice"); !ok {
		t.Fatal("owner could not revoke")
	}
	if _, ok := manager.Session(other); ok {
		t.Fatal("revoked session still valid")
	}
	managed := Principal{ID: "acc_1", Source: SourceManaged, KeyID: "key_1", Name: "svc", Role: "viewer"}
	first, _, _ := manager.LoginWith(managed, now.Add(time.Hour), Meta{})
	second, _, _ := manager.LoginWith(managed, now.Add(time.Hour), Meta{})
	if manager.RevokeKey("key_1") != 2 {
		t.Fatal("key revocation did not end its sessions")
	}
	if _, ok := manager.Session(first); ok {
		t.Fatal("session survived key revocation")
	}
	third, _, _ := manager.LoginWith(managed, now.Add(time.Hour), Meta{})
	if manager.RevokePrincipal("acc_1") != 1 {
		t.Fatal("principal revocation count")
	}
	for _, id := range []string{second, third} {
		if _, ok := manager.Session(id); ok {
			t.Fatal("session survived principal revocation")
		}
	}
}

func TestSwitchKeepsCreationAndMetadata(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	manager := newManager(t, func() time.Time { return now })
	principal := Principal{ID: "cfg:alice", Source: SourceConfig, Name: "alice", Role: "admin",
		Tenants: []string{"default", "bravo"}}
	id, _, err := manager.LoginWith(principal, time.Time{}, Meta{Remote: "192.0.2.1", UserAgent: "curl/8"})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	next, _, err := manager.Switch(id, "bravo")
	if err != nil {
		t.Fatal(err)
	}
	list := manager.Sessions("cfg:alice", next)
	if len(list) != 1 || !list[0].Current || list[0].Tenant != "bravo" || list[0].Remote != "192.0.2.1" ||
		list[0].Client != "curl" || !list[0].CreatedAt.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("switched = %+v", list)
	}
}
