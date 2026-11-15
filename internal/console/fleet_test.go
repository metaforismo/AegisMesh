package console_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/console"
	"github.com/metaforismo/aegismesh/internal/fleet/agent"
	"github.com/metaforismo/aegismesh/internal/fleet/hub"
	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
)

func fleetHarness(t *testing.T) (*consoleHarness, *hub.Hub, string, string) {
	t.Helper()
	registry, err := hub.New(hub.Options{StateDir: filepath.Join(t.TempDir(), "hub")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { registry.Close() })
	machine := httptest.NewServer(registry)
	t.Cleanup(machine.Close)
	minted, err := registry.Mint(0, "synthetic")
	if err != nil {
		t.Fatal(err)
	}
	reporter, err := agent.New(agent.Options{
		HubURL:   machine.URL,
		StateDir: filepath.Join(t.TempDir(), "agent"),
		Name:     "test-node",
		Token:    minted.Token,
		Interval: 10 * time.Second,
		Snapshot: func() protocol.Heartbeat {
			return protocol.Heartbeat{
				Name:           "test-node",
				Sensors:        []protocol.Sensor{},
				StorageHealthy: true,
			}
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reporter.Close)
	if err := reporter.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	spare, err := registry.Mint(0, "delete fixture")
	if err != nil {
		t.Fatal(err)
	}
	harness := newConsoleHarness(t, func(opts *console.Options) {
		opts.FleetHub = registry
		opts.FleetStatus = func() protocol.Status {
			return protocol.Status{
				Hub: protocol.HubStatus{
					Enabled: true,
					Listen:  machine.Listener.Addr().String(),
				},
			}
		}
	})
	return harness, registry, reporter.Status().NodeID, spare.ID
}

func TestEnabledFleetAuthorizationAndMutations(t *testing.T) {
	harness, registry, nodeID, tokenID := fleetHarness(t)
	fixtures := []struct {
		method string
		path   string
		role   string
		body   string
		want   int
	}{
		{
			method: "GET",
			path:   "/api/v1/fleet",
			role:   "viewer",
			want:   200,
		},
		{
			method: "GET",
			path:   "/api/v1/fleet/nodes?status=online",
			role:   "viewer",
			want:   200,
		},
		{
			method: "GET",
			path:   "/api/v1/fleet/nodes/" + nodeID,
			role:   "viewer",
			want:   200,
		},
		{
			method: "POST",
			path:   "/api/v1/fleet/nodes/" + nodeID + "/revoke",
			role:   "admin",
			want:   200,
		},
		{
			method: "GET",
			path:   "/api/v1/fleet/enrollment-tokens",
			role:   "admin",
			want:   200,
		},
		{
			method: "POST",
			path:   "/api/v1/fleet/enrollment-tokens",
			role:   "admin",
			body:   `{}`,
			want:   201,
		},
		{
			method: "DELETE",
			path:   "/api/v1/fleet/enrollment-tokens/" + tokenID,
			role:   "admin",
			want:   204,
		},
	}
	for _, fixture := range fixtures {
		for _, role := range []string{"none", "viewer", "analyst", "admin"} {
			t.Run(fixture.method+fixture.path+"/"+role, func(t *testing.T) {
				token := "synthetic-" + role
				want := fixture.want
				if role == "none" {
					token = ""
					want = 401
				} else if fixture.role == "admin" && role != "admin" {
					want = 403
				}
				response := harness.request(t, apiRequest{
					method: fixture.method,
					path:   fixture.path,
					token:  token,
					body:   fixture.body,
				})
				requireStatus(t, response, want)
				if fixture.path == "/api/v1/fleet/enrollment-tokens" && fixture.method == "GET" && want == 200 &&
					(strings.Contains(string(response.body), "digest") || strings.Contains(string(response.body), `"token":`)) {
					t.Fatal("token listing exposed secret material")
				}
			})
		}
	}
	node, err := registry.Node(nodeID)
	if err != nil || node.Status != "revoked" {
		t.Fatal("revocation did not persist")
	}
	auditResponse := harness.request(t, apiRequest{
		method: "GET",
		path:   "/api/v1/audit",
		token:  "synthetic-admin",
	})
	for _, action := range []string{"fleet.token.create", "fleet.token.delete", "fleet.node.revoke"} {
		if !strings.Contains(string(auditResponse.body), action) {
			t.Fatalf("missing audit action %s", action)
		}
	}
}

func TestFleetCSRFAndStrictBodies(t *testing.T) {
	harness, _, nodeID, tokenID := fleetHarness(t)
	cookie, csrf := harness.login(t, nil)
	for _, fixture := range []struct {
		method string
		path   string
		body   string
	}{
		{
			method: "POST",
			path:   "/api/v1/fleet/enrollment-tokens",
			body:   `{}`,
		},
		{
			method: "DELETE",
			path:   "/api/v1/fleet/enrollment-tokens/" + tokenID,
		},
		{
			method: "POST",
			path:   "/api/v1/fleet/nodes/" + nodeID + "/revoke",
		},
	} {
		requireStatus(t, harness.request(t, apiRequest{
			method: fixture.method,
			path:   fixture.path,
			body:   fixture.body,
			cookie: cookie,
		}), 403)
		requireStatus(t, harness.request(t, apiRequest{
			method: fixture.method,
			path:   fixture.path,
			body:   fixture.body,
			cookie: cookie,
			csrf:   csrf.CSRFToken,
			origin: "https://evil.invalid",
		}), 403)
	}
	for _, body := range []string{
		`{"ttl_seconds":86401}`, `{"ttl_seconds":-1}`, `{"ttl_seconds":1,"ttl_seconds":2}`,
		`{"token":"inline"}`, `{"note":"` + strings.Repeat("x", 257) + `"}`, `null`,
	} {
		requireStatus(t, harness.request(t, apiRequest{
			method: "POST",
			path:   "/api/v1/fleet/enrollment-tokens",
			body:   body,
			token:  "synthetic-admin",
		}), 400)
	}
	good := harness.request(t, apiRequest{
		method: "POST",
		path:   "/api/v1/fleet/enrollment-tokens",
		body:   `{"ttl_seconds":60,"note":"synthetic test"}`,
		cookie: cookie,
		csrf:   csrf.CSRFToken,
	})
	requireStatus(t, good, 201)
	var minted hub.Minted
	if err := json.Unmarshal(good.body, &minted); err != nil || len(minted.Token) != 64 {
		t.Fatal("invalid mint response")
	}
	for _, path := range []string{
		"/api/v1/fleet?typo=1", "/api/v1/fleet/nodes?status=bogus", "/api/v1/fleet/nodes?status=online&status=stale",
		"/api/v1/fleet/enrollment-tokens?token=secret",
	} {
		requireStatus(t, harness.request(t, apiRequest{
			method: "GET",
			path:   path,
			token:  "synthetic-admin",
		}), 400)
	}
}
