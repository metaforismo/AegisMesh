package console_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console"
	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/testutil/oidctest"
)

func oidcOptions(t *testing.T, p *oidctest.Provider, opts *console.Options) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	opts.Config.Listen = address
	opts.Config.OIDC = config.OIDC{
		Enabled: true, Issuer: p.Server.URL, ClientID: "console", DisplayName: "Test identity",
		RedirectURI: "http://" + address + "/api/v1/auth/oidc/callback",
		RoleMapping: map[string]string{"admins": "admin", "readers": "viewer", "viewer": "viewer", "analyst": "analyst", "admin": "admin"},
	}
}

func beginOIDC(t *testing.T, h *consoleHarness) (apiResponse, *http.Cookie) {
	t.Helper()
	for range 8 {
		start := h.request(t, apiRequest{method: "GET", path: "/api/v1/auth/oidc/login"})
		requireStatus(t, start, 302)
		if strings.HasPrefix(start.header.Get("Location"), "http") {
			if len(start.cookies) != 1 {
				t.Fatal("pre-login cookie missing")
			}
			cookie := start.cookies[0]
			if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge != 120 {
				t.Fatal("unsafe pre-login cookie")
			}
			return start, cookie
		}
		time.Sleep(40 * time.Millisecond)
	}
	t.Fatal("SSO never became available")
	return apiResponse{}, nil
}

func oidcRoundTrip(t *testing.T, h *consoleHarness) (string, *http.Cookie) {
	t.Helper()
	start, cookie := beginOIDC(t, h)
	response, err := h.client.Get(start.header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 302 {
		t.Fatalf("provider authorization: %d", response.StatusCode)
	}
	callback, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return callback.RequestURI(), cookie
}

func loginOIDC(t *testing.T, h *consoleHarness) (*http.Cookie, auth.Session) {
	t.Helper()
	path, pre := oidcRoundTrip(t, h)
	response := h.request(t, apiRequest{method: "GET", path: path, cookie: pre})
	requireStatus(t, response, 302)
	if response.header.Get("Location") != "/" {
		t.Fatalf("SSO failed: %s", response.header.Get("Location"))
	}
	var cookie *http.Cookie
	for _, c := range response.cookies {
		if c.Name == console.CookieName {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe session cookie")
	}
	current := h.request(t, apiRequest{method: "GET", path: "/api/v1/session", cookie: cookie})
	requireStatus(t, current, 200)
	var session auth.Session
	if err := json.Unmarshal(current.body, &session); err != nil {
		t.Fatal(err)
	}
	if session.Principal.AuthMethod != "oidc" || session.CSRFToken == "" {
		t.Fatal("wrong OIDC session")
	}
	return cookie, session
}

func TestOIDCCallbackBrowserAndSessionBoundary(t *testing.T) {
	p := oidctest.New(t)
	h := newConsoleHarness(t, func(opts *console.Options) { oidcOptions(t, p, opts) })
	cookie, session := loginOIDC(t, h)
	if session.Tenant != "default" {
		t.Fatal("missing tenant")
	}
	old := cookie
	cookie, _ = loginOIDC(t, h)
	// Supply the old session during successful authentication to prove fixation rotation.
	path, pre := oidcRoundTrip(t, h)
	req, _ := http.NewRequest("GET", h.base+path, nil)
	req.AddCookie(pre)
	req.AddCookie(old)
	response, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 302 || response.Header.Get("Location") != "/" {
		t.Fatal("reauthentication failed")
	}
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/session", cookie: old}), 401)
	for _, mode := range []string{
		"state", "missing-cookie", "foreign-cookie", "nonce", "audience", "issuer",
		"expired", "none", "hmac", "unmapped", "oversized",
	} {
		t.Run(mode, func(t *testing.T) {
			p.Configure(mode, "", "")
			path, pre := oidcRoundTrip(t, h)
			if mode == "state" {
				u, _ := url.Parse(path)
				q := u.Query()
				q.Set("state", strings.Repeat("x", 43))
				u.RawQuery = q.Encode()
				path = u.String()
			}
			if mode == "missing-cookie" {
				pre = nil
			}
			if mode == "foreign-cookie" {
				pre.Value = strings.Repeat("x", 43)
			}
			callback := h.request(t, apiRequest{method: "GET", path: path, cookie: pre})
			requireStatus(t, callback, 302)
			if !strings.HasPrefix(callback.header.Get("Location"), "/#/login?error=") {
				t.Fatal("invalid callback succeeded")
			}
			for _, c := range callback.cookies {
				if c.Name == console.CookieName {
					t.Fatal("denied callback created session")
				}
			}
			replay := h.request(t, apiRequest{method: "GET", path: path, cookie: pre})
			requireStatus(t, replay, 302)
			h.clock.advance(10 * time.Second)
		})
	}
	p.Configure("happy", "", "")
	_, _ = loginOIDC(t, h)
	audit := h.request(t, apiRequest{method: "GET", path: "/api/v1/audit?limit=200", token: "synthetic-admin"})
	requireStatus(t, audit, 200)
	if !strings.Contains(string(audit.body), p.Server.URL) {
		t.Fatal("issuer missing in audit")
	}
	if !strings.Contains(string(audit.body), `"subject":"stable-subject"`) ||
		!strings.Contains(string(audit.body), `"action":"session.oidc_denied"`) {
		t.Fatal("stable OIDC audit identity missing")
	}
	_ = cookie
}

func TestOIDCTokenDisabledAndExpiryCap(t *testing.T) {
	p := oidctest.New(t)
	p.Configure("short-expiry", "", "")
	h := newConsoleHarness(t, func(opts *console.Options) {
		oidcOptions(t, p, opts)
		disabled := false
		opts.Config.TokenLogin = &disabled
		opts.Config.Operators = nil
	})
	requireStatus(t, h.request(t, apiRequest{method: "POST", path: "/api/v1/session", body: `{"token":"synthetic-admin"}`}), 403)
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/events", token: "synthetic-admin"}), 401)
	cookie, session := loginOIDC(t, h)
	if time.Until(session.ExpiresAt) > 21*time.Second {
		t.Fatal("session outlived ID token")
	}
	h.clock.advance(21 * time.Second)
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/session", cookie: cookie}), 401)
	meta := h.request(t, apiRequest{method: "GET", path: "/api/v1/meta"})
	if !strings.Contains(string(meta.body), `"token":false`) || !strings.Contains(string(meta.body), `"enabled":true`) {
		t.Fatal("wrong sign-in metadata")
	}
}

func TestOIDCProviderOutageDoesNotBlockConsole(t *testing.T) {
	p := oidctest.New(t)
	p.Down.Store(true)
	h := newConsoleHarness(t, func(opts *console.Options) { oidcOptions(t, p, opts) })
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/events", token: "synthetic-admin"}), 200)
	unavailable := h.request(t, apiRequest{method: "GET", path: "/api/v1/auth/oidc/login"})
	requireStatus(t, unavailable, 302)
	if unavailable.header.Get("Location") != "/#/login?error=unavailable" {
		t.Fatal("outage not reported")
	}
	p.Down.Store(false)
	time.Sleep(1100 * time.Millisecond)
	_, _ = loginOIDC(t, h)
	path, pre := oidcRoundTrip(t, h)
	callback, _ := url.Parse(path)
	values := callback.Query()
	values.Del("code")
	values.Set("error", "provider-private-message")
	values.Set("error_description", "<script>provider-private-message</script>")
	callback.RawQuery = values.Encode()
	denied := h.request(t, apiRequest{method: "GET", path: callback.String(), cookie: pre})
	requireStatus(t, denied, 302)
	if strings.Contains(string(denied.body)+denied.header.Get("Location"), "provider-private-message") {
		t.Fatal("provider text reflected")
	}
}

func TestOIDCRedirectURIMustMatchListener(t *testing.T) {
	p := oidctest.New(t)
	_ = newConsoleHarness(t, func(opts *console.Options) {
		oidcOptions(t, p, opts)
		bad := *opts
		bad.Config.Listen = "127.0.0.1:0"
		bad.StateDir = filepath.Join(t.TempDir(), "mismatch")
		server, err := console.New(bad)
		if err == nil {
			_ = server.Close(context.Background())
			t.Fatal("foreign redirect authority accepted")
		}
	})
}
