package auth

import (
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
