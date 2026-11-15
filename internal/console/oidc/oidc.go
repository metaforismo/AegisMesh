// Package oidc implements bounded experimental Authorization Code SSO with PKCE.
// All provider data stays inside the authentication boundary and never selects a path or action.
package oidc

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console/auth"
)

// MaxPending bounds browser login attempts across the process.
const MaxPending = 128

// PendingTTL limits authorization round trips to two minutes.
const PendingTTL = 2 * time.Minute

// ClockSkew permits only thirty seconds of issuer clock drift.
const ClockSkew = 30 * time.Second

// ErrUnavailable is a safe fixed error; provider-supplied diagnostics are never reflected.
var ErrUnavailable = errors.New("oidc: unavailable")

// ErrState marks expired, reused or browser-unbound callbacks.
var ErrState = errors.New("oidc: invalid state")

// ErrToken marks an invalid identity credential.
var ErrToken = errors.New("oidc: invalid token")

// ErrDenied marks an authenticated identity without configured authorization.
var ErrDenied = errors.New("oidc: authorization denied")

// ErrCapacity marks bounded pending-login exhaustion.
var ErrCapacity = errors.New("oidc: pending capacity")

// Options injects validated configuration, transient credential, time and optional test transport.
type Options struct {
	// Config fixes the issuer and authorization mapping policy.
	Config config.OIDC
	// Tenants contains only startup-validated partition names.
	Tenants []string
	// Secret is a transient resolved reference, never configuration or persisted state.
	Secret string
	// Now drives state and identity time validation; nil uses time.Now.
	Now func() time.Time
	// Transport injects test networking; nil uses the guarded direct transport.
	Transport http.RoundTripper
}

type provider struct {
	oauth    oauth2.Config
	verifier *coreoidc.IDTokenVerifier
}

type pending struct {
	browser  string
	nonce    string
	verifier string
	expires  time.Time
	provider *provider
}

// Manager owns immutable provider snapshots and single-use browser-bound login state.
type Manager struct {
	mu        sync.Mutex
	cfg       config.OIDC
	tenants   []string
	secret    string
	now       func() time.Time
	client    *http.Client
	transport boundedTransport
	ready     *provider
	pending   map[string]pending
}

// New constructs authentication state without contacting any endpoint.
func New(opts Options) (*Manager, error) {
	client, transport, err := providerClient(opts.Config, opts.Transport)
	if err != nil {
		return nil, err
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Manager{
		cfg: opts.Config, tenants: append([]string{}, opts.Tenants...), secret: opts.Secret,
		now: opts.Now, client: client, transport: transport, pending: map[string]pending{},
	}, nil
}

// Run refreshes discovery with bounded backoff; failure never stops sensors or token login.
func (m *Manager) Run(ctx context.Context) {
	delay := time.Duration(0)
	backoff := time.Second
	for {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if m.discover(ctx) == nil {
			delay, backoff = 15*time.Minute, time.Second
		} else {
			delay = backoff
			backoff = min(backoff*2, time.Minute)
		}
	}
}

func (m *Manager) discover(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(m.cfg.Issuer, "/")+
		"/.well-known/openid-configuration", nil)
	if err != nil {
		return ErrUnavailable
	}
	response, err := m.client.Do(request)
	if err != nil {
		return ErrUnavailable
	}
	defer response.Body.Close()
	var metadata struct {
		Issuer        string `json:"issuer"`
		Authorization string `json:"authorization_endpoint"`
		Token         string `json:"token_endpoint"`
		Keys          string `json:"jwks_uri"`
	}
	if response.StatusCode != 200 || json.NewDecoder(response.Body).Decode(&metadata) != nil ||
		metadata.Issuer != m.cfg.Issuer || !m.transport.allowed(metadata.Authorization) ||
		!m.transport.allowed(metadata.Token) || !m.transport.allowed(metadata.Keys) {
		return ErrUnavailable
	}
	keys := &keyCache{client: m.client, url: metadata.Keys, now: m.now}
	style := oauth2.AuthStyleInParams
	if m.secret != "" {
		style = oauth2.AuthStyleInHeader
	}
	ready := &provider{
		oauth: oauth2.Config{
			ClientID: m.cfg.ClientID, ClientSecret: m.secret, RedirectURL: m.cfg.RedirectURI,
			Scopes:   []string{"openid", "email", "profile"},
			Endpoint: oauth2.Endpoint{AuthURL: metadata.Authorization, TokenURL: metadata.Token, AuthStyle: style},
		},
		verifier: coreoidc.NewVerifier(m.cfg.Issuer, keys, &coreoidc.Config{
			ClientID: m.cfg.ClientID, SupportedSigningAlgs: []string{"RS256", "ES256", "EdDSA"},
			// Enforce exp/iat/nbf together below with our tighter thirty-second skew.
			SkipExpiryCheck: true, Now: m.now,
		}),
	}
	m.mu.Lock()
	m.ready = ready
	m.mu.Unlock()
	return nil
}

// Begin reserves single-use state bound to an independent pre-login browser cookie.
func (m *Manager) Begin() (location, browser string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ready == nil {
		return "", "", ErrUnavailable
	}
	now := m.now()
	for state, item := range m.pending {
		if !now.Before(item.expires) {
			delete(m.pending, state)
		}
	}
	if len(m.pending) >= MaxPending {
		return "", "", ErrCapacity
	}
	values := make([]string, 4)
	for i := range values {
		values[i], err = auth.Token()
		if err != nil {
			return "", "", ErrUnavailable
		}
	}
	state, browser, nonce, verifier := values[0], values[1], values[2], values[3]
	m.pending[state] = pending{
		browser: browser, nonce: nonce, verifier: verifier, expires: now.Add(PendingTTL), provider: m.ready,
	}
	return m.ready.oauth.AuthCodeURL(state, coreoidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), browser, nil
}

// Finish consumes state once, exchanges the code and returns an authorized principal and credential expiry.
// The principal retains verified stable identity even when membership mapping refuses login.
func (m *Manager) Finish(ctx context.Context, state, browser, code string) (auth.Principal, time.Time, error) {
	m.mu.Lock()
	item, ok := m.pending[state]
	delete(m.pending, state)
	m.mu.Unlock()
	if !ok || len(state) != 43 || len(browser) != 43 || !m.now().Before(item.expires) ||
		subtle.ConstantTimeCompare([]byte(browser), []byte(item.browser)) != 1 {
		return auth.Principal{}, time.Time{}, ErrState
	}
	if len(code) == 0 || len(code) > 2048 {
		return auth.Principal{}, time.Time{}, ErrToken
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ctx = coreoidc.ClientContext(ctx, m.client)
	token, err := item.provider.oauth.Exchange(ctx, code, oauth2.VerifierOption(item.verifier))
	if err != nil {
		return auth.Principal{}, time.Time{}, ErrToken
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || len(raw) > 24<<10 {
		return auth.Principal{}, time.Time{}, ErrToken
	}
	verified, err := item.provider.verifier.Verify(ctx, raw)
	if err != nil {
		return auth.Principal{}, time.Time{}, ErrToken
	}
	claims := map[string]json.RawMessage{}
	if verified.Claims(&claims) != nil || len(claims) > 64 {
		return auth.Principal{}, time.Time{}, ErrToken
	}
	if err := m.validate(verified, claims, item.nonce); err != nil {
		return auth.Principal{}, time.Time{}, err
	}
	principal := auth.Principal{Issuer: verified.Issuer, Subject: verified.Subject, AuthMethod: "oidc"}
	if err := m.mapPrincipal(&principal, claims); err != nil {
		return principal, time.Time{}, err
	}
	return principal, verified.Expiry, nil
}

func (m *Manager) validate(token *coreoidc.IDToken, claims map[string]json.RawMessage, nonce string) error {
	now := m.now()
	var azp string
	var nbf int64
	if raw, ok := claims["azp"]; ok && json.Unmarshal(raw, &azp) != nil {
		return ErrToken
	}
	if raw, ok := claims["nbf"]; ok && json.Unmarshal(raw, &nbf) != nil {
		return ErrToken
	}
	if token.Issuer != m.cfg.Issuer || len(token.Subject) == 0 || len(token.Subject) > 255 ||
		token.Nonce != nonce || len(token.Audience) > 32 ||
		len(token.Audience) > 1 && azp != m.cfg.ClientID || azp != "" && azp != m.cfg.ClientID ||
		token.IssuedAt.IsZero() || token.IssuedAt.After(now.Add(ClockSkew)) ||
		token.Expiry.IsZero() || !token.Expiry.After(now) || token.Expiry.Before(token.IssuedAt) ||
		nbf > now.Add(ClockSkew).Unix() {
		return ErrToken
	}
	return nil
}
