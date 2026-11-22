package console_test

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func TestEveryRouteAuthorization(t *testing.T) {
	harness := newConsoleHarness(t, nil)
	expired, _ := harness.login(t, nil)
	harness.clock.advance(time.Minute)
	create := harness.request(t, apiRequest{
		method: "POST",
		path:   "/api/v1/investigations",
		token:  "synthetic-admin",
		body:   `{"title":"Authorization fixture"}`,
	})
	requireStatus(t, create, 201)
	var investigation struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(create.body, &investigation); err != nil {
		t.Fatal(err)
	}

	type fixture struct {
		role   string
		body   string
		status int
	}
	attackerSessionID := sessionID(t, harness)
	fixtures := map[string]fixture{
		"GET /api/v1/sessions":      {role: "viewer", status: 200},
		"GET /api/v1/sessions/{id}": {role: "viewer", status: 200},
		"GET /api/v1/coverage":      {role: "viewer", status: 200},
		"GET /api/v1/campaigns":     {role: "viewer", status: 200},
		// The harness has a single source, so no campaign exists: authorized callers get 404.
		"GET /api/v1/campaigns/{id}":             {role: "viewer", status: 404},
		"GET /api/v1/posture":                    {role: "viewer", status: 200},
		"GET /api/v1/export/indicators":          {role: "analyst", status: 200},
		"GET /api/v1/sessions/{id}/report":       {role: "analyst", status: 200},
		"GET /api/v1/investigations/{id}/report": {role: "analyst", status: 200},
		"GET /api/v1/auth/oidc/login":            {status: 302},
		"GET /api/v1/auth/oidc/callback":         {status: 302},
		"POST /api/v1/session/tenant":            {role: "viewer", body: `{"tenant":"default"}`, status: 400},
		"GET /api/v1/fleet": {
			role:   "viewer",
			status: 200,
		},
		"GET /api/v1/fleet/nodes": {
			role:   "viewer",
			status: 503,
		},
		"GET /api/v1/fleet/nodes/{id}": {
			role:   "viewer",
			status: 503,
		},
		"POST /api/v1/fleet/nodes/{id}/revoke": {
			role:   "admin",
			status: 503,
		},
		"GET /api/v1/fleet/enrollment-tokens": {
			role:   "admin",
			status: 503,
		},
		"POST /api/v1/fleet/enrollment-tokens": {
			role:   "admin",
			body:   `{}`,
			status: 503,
		},
		"DELETE /api/v1/fleet/enrollment-tokens/{id}": {
			role:   "admin",
			status: 503,
		},
		"GET /api/v1/meta": {
			role:   "",
			status: 200,
		},
		"POST /api/v1/session": {
			role:   "",
			body:   `{"token":"synthetic-admin"}`,
			status: 200,
		},
		"GET /api/v1/session": {
			role:   "viewer",
			status: 200,
		},
		"DELETE /api/v1/session": {
			role:   "viewer",
			status: 204,
		},
		"GET /api/v1/overview": {
			role:   "viewer",
			status: 200,
		},
		"GET /api/v1/events": {
			role:   "viewer",
			status: 200,
		},
		"GET /api/v1/events/stream": {
			role:   "viewer",
			status: 200,
		},
		"GET /api/v1/events/{id}": {
			role:   "viewer",
			status: 200,
		},
		"GET /api/v1/sources": {
			role:   "viewer",
			status: 200,
		},
		"GET /api/v1/sources/{source}": {
			role:   "viewer",
			status: 200,
		},
		"GET /api/v1/sensors": {
			role:   "viewer",
			status: 200,
		},
		"GET /api/v1/rules": {
			role:   "viewer",
			status: 200,
		},
		"GET /api/v1/digest":        {role: "viewer", status: 200},
		"GET /api/v1/decoys":        {role: "viewer", status: 200},
		"GET /api/v1/honeytokens":   {role: "viewer", status: 200},
		"GET /api/v1/export/events": {role: "analyst", status: 200},
		"GET /api/v1/recommendations": {
			role:   "viewer",
			status: 200,
		},
		"GET /api/v1/node": {
			role:   "viewer",
			status: 200,
		},
		"GET /api/v1/investigations": {
			role:   "viewer",
			status: 200,
		},
		"POST /api/v1/investigations": {
			role:   "analyst",
			body:   `{"title":"Matrix creation"}`,
			status: 201,
		},
		"GET /api/v1/investigations/{id}": {
			role:   "viewer",
			status: 200,
		},
		"PATCH /api/v1/investigations/{id}": {
			role:   "analyst",
			body:   `{"priority":"high"}`,
			status: 200,
		},
		"POST /api/v1/investigations/{id}/notes": {
			role:   "analyst",
			body:   `{"text":"Synthetic note"}`,
			status: 201,
		},
		"PUT /api/v1/investigations/{id}/events/{event_id}": {
			role:   "analyst",
			status: 200,
		},
		"DELETE /api/v1/investigations/{id}/events/{event_id}": {
			role:   "analyst",
			status: 200,
		},
		"GET /api/v1/audit": {
			role:   "admin",
			status: 200,
		},
		"GET /api/v1/audit/verify": {
			role:   "admin",
			status: 200,
		},
	}
	roles := map[string]map[string]bool{
		"viewer": {
			"viewer":  true,
			"analyst": true,
			"admin":   true,
		},
		"analyst": {
			"analyst": true,
			"admin":   true,
		},
		"admin": {"admin": true},
	}
	routes := harness.server.RoutesForTest()
	if len(routes) != len(fixtures) {
		t.Fatalf("route fixtures = %d; registrations = %d", len(fixtures), len(routes))
	}
	for _, route := range routes {
		// Isolate the route authorization matrix from the independently tested failure throttle.
		harness.clock.advance(time.Minute)
		fixture, ok := fixtures[route.Pattern]
		if !ok {
			t.Fatalf("new route needs an explicit success fixture: %s", route.Pattern)
		}
		if route.Role != fixture.role {
			t.Fatalf("%s requires role %q; want %q", route.Pattern, route.Role, fixture.role)
		}
		method, path, _ := strings.Cut(route.Pattern, " ")
		path = strings.ReplaceAll(path, "{event_id}", harness.eventID)
		if strings.HasPrefix(path, "/api/v1/sessions/") {
			path = strings.ReplaceAll(path, "{id}", attackerSessionID)
		} else if strings.HasPrefix(path, "/api/v1/campaigns/") {
			path = strings.ReplaceAll(path, "{id}", "cmp_000000000000")
		} else if strings.HasPrefix(path, "/api/v1/events/") {
			path = strings.ReplaceAll(path, "{id}", harness.eventID)
		} else {
			path = strings.ReplaceAll(path, "{id}", investigation.ID)
		}
		path = strings.ReplaceAll(path, "{source}", "127.0.0.1")
		if path == "/api/v1/export/events" {
			path += "?window=24h&format=cef"
		}
		if path == "/api/v1/export/indicators" {
			path += "?window=24h&format=txt"
		}
		for _, mode := range []string{
			"none",
			"malformed",
			"wrong",
			"expired",
			"viewer",
			"analyst",
			"admin",
		} {
			t.Run(route.Pattern+"/"+mode, func(t *testing.T) {
				input := apiRequest{
					method: method,
					path:   path,
					body:   fixture.body,
				}
				switch mode {
				case "malformed":
					input.authorization = "Basic invalid"
				case "wrong":
					input.token = "synthetic-wrong"
				case "expired":
					input.cookie = expired
				case "viewer", "analyst", "admin":
					input.token = "synthetic-" + mode
				}
				want := fixture.status
				if fixture.role != "" {
					switch mode {
					case "none", "malformed", "wrong", "expired":
						want = 401
					default:
						if !roles[fixture.role][mode] {
							want = 403
						}
					}
				}
				requireStatus(t, harness.request(t, input), want)
			})
		}
	}
}

func TestHostAuthority(t *testing.T) {
	harness := newConsoleHarness(t, nil)
	_, port, err := net.SplitHostPort(harness.server.Addr())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		host   string
		status int
	}{
		{
			name:   "foreign",
			host:   "evil.invalid:" + port,
			status: 421,
		},
		{
			name:   "wrong port",
			host:   "127.0.0.1:1",
			status: 421,
		},
		{
			name:   "missing port",
			host:   "localhost",
			status: 421,
		},
		{
			name:   "localhost",
			host:   "localhost:" + port,
			status: 200,
		},
		{
			name:   "ipv6",
			host:   "[::1]:" + port,
			status: 200,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			requireStatus(t, harness.request(t, apiRequest{
				method: "GET",
				path:   "/api/v1/meta",
				host:   testCase.host,
			}), testCase.status)
		})
	}
}
