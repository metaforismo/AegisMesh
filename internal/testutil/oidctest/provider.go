// Package oidctest supplies a real loopback Authorization Code provider for integration tests.
package oidctest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

type grant struct{ nonce, challenge, redirect string }

// Provider issues real Ed25519 tokens after a single-use code and S256 exchange.
type Provider struct {
	alg         jose.SignatureAlgorithm
	Server      *httptest.Server
	Down        atomic.Bool
	KeyRequests atomic.Int64
	mu          sync.Mutex
	key         crypto.Signer
	kid         string
	mode        string
	redirect    string
	secret      string
	grants      map[string]grant
}

// New starts a loopback provider with a fresh signing key and bounded code registry.
func New(t *testing.T) *Provider {
	t.Helper()
	p := &Provider{grants: map[string]grant{}}
	p.Rotate(t, "initial")
	p.Server = httptest.NewServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.Server.Close)
	return p
}

// Configure chooses deterministic negative cases without racing handler reads.
func (p *Provider) Configure(mode, redirect, secret string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.mode, p.redirect, p.secret = mode, redirect, secret
}

// Rotate replaces the published key and key ID, exercising live JWKS rotation.
func (p *Provider) Rotate(t *testing.T, kid string) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.key, p.kid, p.alg = key, kid, jose.EdDSA
}

func (p *Provider) serve(w http.ResponseWriter, r *http.Request) {
	if p.Down.Load() {
		w.WriteHeader(503)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": p.Server.URL, "authorization_endpoint": p.Server.URL + "/authorize",
			"token_endpoint": p.Server.URL + "/token", "jwks_uri": p.Server.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"EdDSA"},
		})
	case "/keys":
		p.KeyRequests.Add(1)
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: p.key.Public(), KeyID: p.kid, Algorithm: string(p.alg), Use: "sig",
		}}})
	case "/authorize":
		q := r.URL.Query()
		if q.Get("client_id") != "console" || q.Get("response_type") != "code" ||
			q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" ||
			q.Get("code_challenge") == "" || p.redirect != "" && q.Get("redirect_uri") != p.redirect {
			w.WriteHeader(400)
			return
		}
		var entropy [32]byte
		_, _ = rand.Read(entropy[:])
		code := base64.RawURLEncoding.EncodeToString(entropy[:])
		if len(p.grants) >= 256 {
			w.WriteHeader(503)
			return
		}
		p.grants[code] = grant{q.Get("nonce"), q.Get("code_challenge"), q.Get("redirect_uri")}
		target, _ := url.Parse(q.Get("redirect_uri"))
		values := target.Query()
		values.Set("state", q.Get("state"))
		values.Set("code", code)
		target.RawQuery = values.Encode()
		http.Redirect(w, r, target.String(), 302)
	case "/token":
		if r.Method != "POST" || r.ParseForm() != nil {
			w.WriteHeader(400)
			return
		}
		g, ok := p.grants[r.Form.Get("code")]
		delete(p.grants, r.Form.Get("code"))
		clientID := r.Form.Get("client_id")
		if p.secret != "" {
			id, secret, valid := r.BasicAuth()
			if !valid || id != "console" || secret != p.secret {
				w.WriteHeader(401)
				return
			}
			clientID = id
		}
		if !ok || clientID != "console" || r.Form.Get("grant_type") != "authorization_code" ||
			r.Form.Get("redirect_uri") != g.redirect ||
			oauth2.S256ChallengeFromVerifier(r.Form.Get("code_verifier")) != g.challenge {
			w.WriteHeader(400)
			return
		}
		claims := map[string]any{
			"iss": p.Server.URL, "sub": "stable-subject", "aud": "console",
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
			"nonce": g.nonce, "groups": []string{"readers", "admins"},
			"tenants": []string{"default"}, "email": "operator@example.invalid",
		}
		if p.mode == "bravo-viewer" || p.mode == "bravo-analyst" || p.mode == "bravo-admin" {
			claims["tenants"] = []string{"bravo"}
			claims["groups"] = []string{p.mode[len("bravo-"):]}
		}
		switch p.mode {
		case "nonce":
			claims["nonce"] = "wrong"
		case "audience":
			claims["aud"] = "foreign"
		case "issuer":
			claims["iss"] = "https://foreign.invalid"
		case "expired":
			claims["exp"] = time.Now().Add(-time.Minute).Unix()
		case "future-iat":
			claims["iat"] = time.Now().Add(time.Minute).Unix()
		case "future-nbf":
			claims["nbf"] = time.Now().Add(time.Minute).Unix()
		case "no-sub":
			delete(claims, "sub")
		case "azp":
			claims["aud"], claims["azp"] = []string{"console", "other"}, "other"
		case "multi-audience":
			claims["aud"], claims["azp"] = []string{"console", "other"}, "console"
		case "unmapped":
			claims["groups"] = []string{"strangers"}
		case "no-tenant":
			claims["tenants"] = []string{"foreign"}
		case "oversized":
			claims["email"] = string(make([]byte, 257))
		case "large-token":
			claims["oversized"] = string(make([]byte, 32<<10))
		case "short-expiry":
			claims["exp"] = time.Now().Add(20 * time.Second).Unix()
		case "array-large":
			claims["groups"] = make([]string, 65)
		case "tenant-bravo":
			claims["tenants"] = []string{"bravo"}
		case "sanitized":
			claims["email"] = "name\n<script>@example.invalid"
		}
		payload, _ := json.Marshal(claims)
		alg, key := p.alg, any(p.key)
		if p.mode == "hmac" {
			alg, key = jose.HS256, []byte("synthetic-hmac-key-32-bytes-long!!")
		}
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", p.kid))
		signed, _ := signer.Sign(payload)
		token, _ := signed.CompactSerialize()
		if p.mode == "none" {
			token = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"initial"}`)) + "." +
				base64.RawURLEncoding.EncodeToString(payload) + "."
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "synthetic-unused", "token_type": "Bearer", "expires_in": 3600, "id_token": token,
		})
	default:
		w.WriteHeader(404)
	}
}

// SigningAlgorithm selects each supported asymmetric family for verifier integration tests.
func (p *Provider) SigningAlgorithm(t *testing.T, algorithm jose.SignatureAlgorithm) {
	t.Helper()
	var key crypto.Signer
	var err error
	switch algorithm {
	case jose.RS256:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case jose.ES256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		t.Fatal("unsupported test algorithm")
	}
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.key, p.alg = key, algorithm
}
