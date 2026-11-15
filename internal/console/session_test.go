package console_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/console"
	"github.com/metaforismo/aegismesh/internal/console/auth"
)

func TestCSRF(t *testing.T) {
	harness := newConsoleHarness(t, nil)
	cookie, session := harness.login(t, nil)
	cases := []struct {
		name   string
		csrf   string
		origin string
		bearer bool
		status int
	}{
		{
			name:   "missing header",
			status: 403,
		},
		{
			name:   "wrong header",
			csrf:   strings.Repeat("x", 43),
			status: 403,
		},
		{
			name:   "foreign origin",
			csrf:   session.CSRFToken,
			origin: "http://evil.invalid",
			status: 403,
		},
		{
			name:   "same origin",
			csrf:   session.CSRFToken,
			origin: harness.base,
			status: 201,
		},
		{
			name:   "bearer without csrf",
			bearer: true,
			status: 201,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			input := apiRequest{
				method: "POST",
				path:   "/api/v1/investigations",
				body:   `{"title":"CSRF fixture"}`,
				cookie: cookie,
				csrf:   testCase.csrf,
				origin: testCase.origin,
			}
			if testCase.bearer {
				input.cookie = nil
				input.token = "synthetic-admin"
			}
			requireStatus(t, harness.request(t, input), testCase.status)
		})
	}
}

func TestSessionLifecycle(t *testing.T) {
	harness := newConsoleHarness(t, nil)
	first, _ := harness.login(t, nil)
	rotated, session := harness.login(t, first)
	if first.Value == rotated.Value {
		t.Fatal("re-login did not rotate the session id")
	}
	if !rotated.HttpOnly || rotated.Secure || rotated.Path != "/" || rotated.SameSite != http.SameSiteStrictMode {
		t.Fatalf("unsafe HTTP cookie attributes: %+v", rotated)
	}
	requireStatus(t, harness.request(t, apiRequest{
		method: "GET",
		path:   "/api/v1/session",
		cookie: first,
	}), 401)
	requireStatus(t, harness.request(t, apiRequest{
		method: "DELETE",
		path:   "/api/v1/session",
		cookie: rotated,
		csrf:   session.CSRFToken,
	}), 204)
	requireStatus(t, harness.request(t, apiRequest{
		method: "GET",
		path:   "/api/v1/session",
		cookie: rotated,
	}), 401)
	current, _ := harness.login(t, nil)
	harness.clock.advance(time.Minute - time.Nanosecond)
	requireStatus(t, harness.request(t, apiRequest{
		method: "GET",
		path:   "/api/v1/session",
		cookie: current,
	}), 200)
	harness.clock.advance(time.Nanosecond)
	requireStatus(t, harness.request(t, apiRequest{
		method: "GET",
		path:   "/api/v1/session",
		cookie: current,
	}), 401)
}

func TestLoginRateLimit(t *testing.T) {
	harness := newConsoleHarness(t, nil)
	for attempt := range 11 {
		response := harness.request(t, apiRequest{
			method: "POST",
			path:   "/api/v1/session",
			body:   `{"token":"invalid"}`,
		})
		want := 401
		if attempt == 10 {
			want = 429
			if response.header.Get("Retry-After") != "60" {
				t.Fatal("missing Retry-After")
			}
		}
		requireStatus(t, response, want)
	}
	response := harness.request(t, apiRequest{
		method: "GET",
		path:   "/api/v1/audit?action=session.login_failed",
		token:  "synthetic-admin",
	})
	requireStatus(t, response, 200)
	var page struct {
		Records []json.RawMessage `json:"records"`
	}
	if err := json.Unmarshal(response.body, &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 11 {
		t.Fatalf("failed logins audited = %d; want 11", len(page.Records))
	}
	harness.clock.advance(time.Minute)
	harness.login(t, nil)
}

func TestSessionEvictionOverHTTP(t *testing.T) {
	harness := newConsoleHarness(t, func(opts *console.Options) {
		opts.Config.SessionTTLSeconds = 24 * 60 * 60
	})
	oldest, _ := harness.login(t, nil)
	var newest *http.Cookie
	for range auth.MaxSessions {
		// Six seconds keeps this one remote below ten logins/minute without expiring the sessions.
		harness.clock.advance(6 * time.Second)
		newest, _ = harness.login(t, nil)
	}
	requireStatus(t, harness.request(t, apiRequest{
		method: "GET",
		path:   "/api/v1/session",
		cookie: oldest,
	}), 401)
	requireStatus(t, harness.request(t, apiRequest{
		method: "GET",
		path:   "/api/v1/session",
		cookie: newest,
	}), 200)
}
