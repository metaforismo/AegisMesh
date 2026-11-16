package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/testutil/oidctest"
)

func managerFor(t *testing.T, p *oidctest.Provider, now func() time.Time) *Manager {
	t.Helper()
	cfg := (config.Console{OIDC: config.OIDC{
		Enabled: true, Issuer: p.Server.URL, ClientID: "console",
		RedirectURI: "http://127.0.0.1:9999/api/v1/auth/oidc/callback",
		RoleMapping: map[string]string{"admins": "admin", "readers": "viewer"},
	}}).WithDefaults().OIDC
	m, err := New(Options{Config: cfg, Tenants: []string{"default", "bravo"}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	return m
}

func authorize(t *testing.T, m *Manager) (state, browser, code string) {
	t.Helper()
	location, browser, err := m.Begin()
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get(location)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 302 {
		t.Fatalf("authorization: %d", response.StatusCode)
	}
	callback, _ := url.Parse(response.Header.Get("Location"))
	return callback.Query().Get("state"), browser, callback.Query().Get("code")
}

func TestRealProviderValidation(t *testing.T) {
	for _, mode := range []string{"happy", "multi-audience", "nonce", "audience", "issuer", "expired",
		"future-iat", "future-nbf", "no-sub", "azp", "unmapped", "no-tenant", "oversized", "large-token",
		"array-large", "none", "hmac", "sanitized", "tenant-bravo"} {
		t.Run(mode, func(t *testing.T) {
			p := oidctest.New(t)
			p.Configure(mode, "", "")
			m := managerFor(t, p, nil)
			state, browser, code := authorize(t, m)
			principal, expiry, err := m.Finish(context.Background(), state, browser, code)
			success := mode == "happy" || mode == "multi-audience" || mode == "sanitized" || mode == "tenant-bravo"
			if success {
				if err != nil || principal.Role != "admin" || principal.Subject != "stable-subject" || expiry.IsZero() {
					t.Fatalf("principal=%+v expiry=%v err=%v", principal, expiry, err)
				}
				if strings.ContainsAny(principal.Name, "\n<>") {
					t.Fatalf("unsafe name: %q", principal.Name)
				}
			} else if err == nil {
				t.Fatal("invalid identity admitted")
			}
			if _, _, err := m.Finish(context.Background(), state, browser, code); !errors.Is(err, ErrState) {
				t.Fatalf("callback replay: %v", err)
			}
		})
	}
}

func TestStateBindingExpiryAndCapacity(t *testing.T) {
	p := oidctest.New(t)
	var offset atomic.Int64
	m := managerFor(t, p, func() time.Time { return time.Now().Add(time.Duration(offset.Load())) })
	for _, mode := range []string{"state", "missing-cookie", "foreign-cookie", "expired"} {
		state, browser, code := authorize(t, m)
		switch mode {
		case "state":
			state = strings.Repeat("x", 43)
		case "missing-cookie":
			browser = ""
		case "foreign-cookie":
			browser = strings.Repeat("x", 43)
		case "expired":
			offset.Store(int64(PendingTTL + time.Second))
		}
		if _, _, err := m.Finish(context.Background(), state, browser, code); !errors.Is(err, ErrState) {
			t.Fatalf("%s: %v", mode, err)
		}
	}
	for range MaxPending {
		if _, _, err := m.Begin(); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := m.Begin(); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity: %v", err)
	}
	offset.Add(int64(PendingTTL + time.Second))
	if _, _, err := m.Begin(); err != nil {
		t.Fatalf("expired states not reclaimed: %v", err)
	}
}

func TestUnknownKIDRotationIsPaced(t *testing.T) {
	p := oidctest.New(t)
	var offset atomic.Int64
	m := managerFor(t, p, func() time.Time { return time.Now().Add(time.Duration(offset.Load())) })
	state, browser, code := authorize(t, m)
	if _, _, err := m.Finish(context.Background(), state, browser, code); err != nil {
		t.Fatal(err)
	}
	p.Rotate(t, "rotated")
	for range 8 {
		state, browser, code = authorize(t, m)
		if _, _, err := m.Finish(context.Background(), state, browser, code); err == nil {
			t.Fatal("unpaced refresh")
		}
	}
	if p.KeyRequests.Load() != 1 {
		t.Fatalf("unknown kid caused %d fetches", p.KeyRequests.Load())
	}
	offset.Store(int64(6 * time.Second))
	state, browser, code = authorize(t, m)
	if _, _, err := m.Finish(context.Background(), state, browser, code); err != nil {
		t.Fatal(err)
	}
	if p.KeyRequests.Load() != 2 {
		t.Fatal("rotation was not fetched")
	}
}

func TestStartupUnavailableThenRecovery(t *testing.T) {
	p := oidctest.New(t)
	m := managerFor(t, p, nil)
	m.ready = nil
	p.Down.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.Run(ctx)
	}()
	if _, _, err := m.Begin(); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	p.Down.Store(false)
	deadline := time.Now().Add(4 * time.Second)
	for {
		if _, _, err := m.Begin(); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("provider did not recover")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}

func TestAsymmetricAlgorithmsAndConfidentialClient(t *testing.T) {
	for _, algorithm := range []jose.SignatureAlgorithm{jose.RS256, jose.ES256} {
		p := oidctest.New(t)
		p.SigningAlgorithm(t, algorithm)
		m := managerFor(t, p, nil)
		state, browser, code := authorize(t, m)
		if _, _, err := m.Finish(context.Background(), state, browser, code); err != nil {
			t.Fatalf("%s: %v", algorithm, err)
		}
	}
	p := oidctest.New(t)
	p.Configure("", "", "synthetic-confidential-secret")
	m := managerFor(t, p, nil)
	m.secret = "synthetic-confidential-secret"
	if err := m.discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, browser, code := authorize(t, m)
	if _, _, err := m.Finish(context.Background(), state, browser, code); err != nil {
		t.Fatal("confidential client exchange failed", err)
	}
}
