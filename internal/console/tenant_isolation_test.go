package console_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console"
	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/console/investigations"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/fleet/hub"
	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
	"github.com/metaforismo/aegismesh/internal/testutil/oidctest"
)

func tenantHarness(t *testing.T, p *oidctest.Provider) (*consoleHarness, *hub.Hub) {
	t.Helper()
	var registry *hub.Hub
	harness := newConsoleHarness(t, func(opts *console.Options) {
		opts.Config.Tenants = []string{"default", "bravo"}
		if p != nil {
			oidcOptions(t, p, opts)
		}
		for _, role := range []string{"viewer", "analyst", "admin"} {
			opts.Config.Operators = append(opts.Config.Operators, config.Operator{
				Name: "bravo-" + role, Role: role, TokenSHA256: auth.Digest("bravo-" + role), Tenants: []string{"bravo"},
			})
		}
		b, err := evidenceindex.New(1000, opts.Meter)
		if err != nil {
			t.Fatal(err)
		}
		indexes := map[string]*evidenceindex.Index{"default": opts.Index, "bravo": b}
		opts.TenantIndexes = indexes
		registry, err = hub.New(hub.Options{
			StateDir: filepath.Join(t.TempDir(), "hub"), Tenants: opts.Config.Tenants,
			Evidence:     &hub.EvidenceOptions{},
			TenantAppend: func(name, id string, envelope event.Envelope) { indexes[name].AddForwarded(envelope, id) },
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = registry.Close() })
		opts.FleetHub = registry
	})
	return harness, registry
}

func TestEveryRouteTenantIsolation(t *testing.T) {
	p := oidctest.New(t)
	h, registry := tenantHarness(t, p)
	created := h.request(t, apiRequest{
		method: "POST",
		path:   "/api/v1/investigations",
		token:  "synthetic-admin",
		body:   `{"title":"Tenant A secret"}`,
	})
	requireStatus(t, created, 201)
	var investigation struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(created.body, &investigation); err != nil {
		t.Fatal(err)
	}
	minted := h.request(t, apiRequest{method: "POST", path: "/api/v1/fleet/enrollment-tokens", token: "synthetic-admin", body: `{}`})
	requireStatus(t, minted, 201)
	var token struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(minted.body, &token); err != nil {
		t.Fatal(err)
	}
	machine := httptest.NewServer(registry)
	defer machine.Close()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nodeID := protocol.ID(key.Public().(ed25519.PublicKey))
	postMachine := func(path string, value any) {
		t.Helper()
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		request, _ := http.NewRequest("POST", machine.URL+path, bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if err := protocol.Sign(request, body, key, time.Now()); err != nil {
			t.Fatal(err)
		}
		response, err := machine.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatalf("machine request: %d", response.StatusCode)
		}
	}
	postMachine(protocol.EnrollPath, protocol.Enrollment{
		Token: token.Token, PublicKey: hex.EncodeToString(key.Public().(ed25519.PublicKey)),
		Name: "tenant-a-node", IntervalSeconds: 10,
	})
	forwarded, err := event.New(&event.Sequencer{}, "synthetic", event.SensorRef{ID: "remote-web", Kind: "http"},
		event.ClassificationInteraction, json.RawMessage(`{"method":"GET","path":"/tenant-a-remote","remote_host":"203.0.113.7"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(forwarded)
	postMachine(protocol.EvidencePath, protocol.EvidenceBatch{
		StreamID: strings.Repeat("d", 32), First: 1, Last: 1, Events: []json.RawMessage{raw},
	})
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/events/" + forwarded.ID, token: "synthetic-admin"}), 200)
	for _, path := range []string{
		"/api/v1/events?node=" + nodeID, "/api/v1/events/" + forwarded.ID + "?node=" + nodeID,
		"/api/v1/sources/203.0.113.7",
	} {
		result := h.request(t, apiRequest{method: "GET", path: path, token: "bravo-admin"})
		if strings.Contains(string(result.body), forwarded.ID) || strings.Contains(string(result.body), "tenant-a-remote") {
			t.Fatal("forwarded evidence crossed console tenant boundary")
		}
		if !strings.Contains(path, "?") || strings.Contains(path, "/events/"+forwarded.ID) {
			requireStatus(t, result, 404)
		}
	}
	// Keep an outstanding A token as a real foreign target after consuming the enrollment credential.
	minted = h.request(t, apiRequest{method: "POST", path: "/api/v1/fleet/enrollment-tokens", token: "synthetic-admin", body: `{}`})
	requireStatus(t, minted, 201)
	if err := json.Unmarshal(minted.body, &token); err != nil {
		t.Fatal(err)
	}

	for _, method := range []string{"token", "oidc"} {
		for _, role := range []string{"viewer", "analyst", "admin"} {
			var cookie *http.Cookie
			csrf := ""
			if method == "oidc" {
				p.Configure("bravo-"+role, "", "")
				var session auth.Session
				cookie, session = loginOIDC(t, h)
				csrf = session.CSRFToken
			}
			for _, route := range h.server.RoutesForTest() {
				if route.Role == "" {
					continue
				}
				t.Run(method+"/"+role+"/"+route.Pattern, func(t *testing.T) {
					verb, path, _ := strings.Cut(route.Pattern, " ")
					path = strings.ReplaceAll(path, "{event_id}", h.eventID)
					id := investigation.ID
					if strings.HasPrefix(path, "/api/v1/sessions/") {
						id = sessionID(t, h)
					}
					if strings.HasPrefix(path, "/api/v1/events/") {
						id = h.eventID
					}
					if strings.HasPrefix(path, "/api/v1/fleet/enrollment-tokens/") {
						id = token.ID
					}
					if strings.HasPrefix(path, "/api/v1/fleet/nodes/") {
						id = nodeID
					}
					path = strings.ReplaceAll(path, "{id}", id)
					path = strings.ReplaceAll(path, "{source}", "127.0.0.1")
					if path == "/api/v1/export/indicators" {
						path += "?window=24h&format=txt"
					}
					input := apiRequest{method: verb, path: path, cookie: cookie, csrf: csrf}
					if method == "token" {
						input.token = "bravo-" + role
					}
					if verb == "POST" || verb == "PATCH" {
						input.body = `{}`
					}
					switch route.Pattern {
					case "POST /api/v1/fleet/nodes/{id}/revoke":
						input.body = ""
					case "POST /api/v1/investigations":
						input.body = `{"title":"Tenant B only"}`
					case "PATCH /api/v1/investigations/{id}":
						input.body = `{"title":"Changed B"}`
					case "POST /api/v1/investigations/{id}/notes":
						input.body = `{"text":"B note"}`
					case "POST /api/v1/session/tenant":
						input.body = `{"tenant":"default"}`
					}
					result := h.request(t, input)
					// Local runtime and every direct foreign object have exactly the normal absent result.
					direct := strings.Contains(route.Pattern, "{id}") || strings.Contains(route.Pattern, "{source}") ||
						route.Pattern == "GET /api/v1/node"
					granted := auth.Granted(role, route.Role)
					if !granted && route.Pattern != "GET /api/v1/node" {
						requireStatus(t, result, 403)
						return
					}
					if direct {
						requireStatus(t, result, 404)
					}
					if strings.Contains(string(result.body), "Tenant A secret") || strings.Contains(string(result.body), h.eventID) ||
						strings.Contains(string(result.body), token.ID) || strings.Contains(string(result.body), token.Token) ||
						strings.Contains(string(result.body), nodeID) || strings.Contains(string(result.body), forwarded.ID) {
						t.Fatalf("tenant A data disclosed: %s", result.body)
					}
					if route.Pattern == "GET /api/v1/overview" {
						var overview struct {
							Totals struct {
								Events int `json:"events"`
							} `json:"totals"`
						}
						if json.Unmarshal(result.body, &overview) != nil || overview.Totals.Events != 0 {
							t.Fatal("cross-tenant counter")
						}
					}
					if route.Pattern == "GET /api/v1/audit" && strings.Contains(string(result.body), `"actor":"admin"`) {
						t.Fatal("A actions in B audit")
					}
				})
				// Logout invalidates the OIDC session; renew for subsequent routes.
				if method == "oidc" && route.Pattern == "DELETE /api/v1/session" {
					var session auth.Session
					cookie, session = loginOIDC(t, h)
					csrf = session.CSRFToken
				}
			}
		}
	}
	aAudit := h.request(t, apiRequest{method: "GET", path: "/api/v1/audit?limit=200", token: "synthetic-admin"})
	if strings.Contains(string(aAudit.body), "bravo-") || strings.Contains(string(aAudit.body), "operator@example.invalid") {
		t.Fatal("B actions entered A audit")
	}
}

func TestTenantSwitchRotatesSessionAndCSRF(t *testing.T) {
	h := newConsoleHarness(t, func(opts *console.Options) {
		opts.Config.Tenants = []string{"default", "bravo"}
		for i := range opts.Config.Operators {
			opts.Config.Operators[i].Tenants = []string{"default", "bravo"}
		}
	})
	old, session := h.login(t, nil)
	response := h.request(t, apiRequest{
		method: "POST",
		path:   "/api/v1/session/tenant",
		body:   `{"tenant":"bravo"}`,
		cookie: old,
		csrf:   session.CSRFToken,
	})
	requireStatus(t, response, 200)
	var switched auth.Session
	if err := json.Unmarshal(response.body, &switched); err != nil {
		t.Fatal(err)
	}
	if switched.Tenant != "bravo" || switched.Principal.Tenant != "bravo" ||
		switched.CSRFToken == session.CSRFToken || len(switched.Tenants) != 2 {
		t.Fatal("tenant switch did not rotate credentials")
	}
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/session", cookie: old}), 401)
	current := response.cookies[0]
	requireStatus(t, h.request(t, apiRequest{
		method: "POST",
		path:   "/api/v1/investigations",
		body:   `{"title":"B only"}`,
		cookie: current,
		csrf:   session.CSRFToken,
	}), 403)
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/events", cookie: current}), 200)
	requireStatus(t, h.request(t, apiRequest{
		method: "POST",
		path:   "/api/v1/session/tenant",
		body:   `{"tenant":"foreign"}`,
		cookie: current,
		csrf:   switched.CSRFToken,
	}), 404)
}

func TestInvestigationQuotaDoesNotCrossTenants(t *testing.T) {
	h := newConsoleHarness(t, func(opts *console.Options) {
		opts.Config.Tenants = []string{"default", "bravo"}
		opts.Config.Operators[0].Tenants = []string{"bravo"}
		opts.Config.Operators[0].Role = "analyst"
		items := map[string]investigations.Investigation{}
		for i := range investigations.MaxInvestigations {
			id := fmt.Sprintf("inv_%d", i)
			items[id] = investigations.Investigation{ID: id, Title: "A quota", Status: "open", Priority: "medium"}
		}
		body, err := json.Marshal(items)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(opts.StateDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(opts.StateDir, "investigations.json"), body, 0600); err != nil {
			t.Fatal(err)
		}
	})
	requireStatus(t, h.request(t, apiRequest{
		method: "POST",
		path:   "/api/v1/investigations",
		token:  "synthetic-admin",
		body:   `{"title":"A full"}`,
	}), 409)
	requireStatus(t, h.request(t, apiRequest{
		method: "POST",
		path:   "/api/v1/investigations",
		token:  "synthetic-viewer",
		body:   `{"title":"B has capacity"}`,
	}), 201)
	result := h.request(t, apiRequest{method: "GET", path: "/api/v1/investigations", token: "synthetic-viewer"})
	requireStatus(t, result, 200)
	if strings.Contains(string(result.body), "A quota") {
		t.Fatal("A quota records exposed in B")
	}
}
