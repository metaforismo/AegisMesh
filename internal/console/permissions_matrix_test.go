package console_test

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"
)

// builtinRouteAccess pins, for every registered route, the least built-in role
// that passes the authorization gate ("none" = unauthenticated route). It was
// recorded from the rank-based behaviour before permissions replaced role
// ranks; the permission refactor must keep every row identical.
var builtinRouteAccess = map[string]string{
	"GET /api/v1/meta":                                     "none",
	"GET /api/v1/auth/oidc/login":                          "none",
	"GET /api/v1/auth/oidc/callback":                       "none",
	"POST /api/v1/session":                                 "none",
	"GET /api/v1/session":                                  "viewer",
	"DELETE /api/v1/session":                               "viewer",
	"POST /api/v1/session/tenant":                          "viewer",
	"GET /api/v1/me":                                       "viewer",
	"GET /api/v1/me/preferences":                           "viewer",
	"PUT /api/v1/me/preferences":                           "viewer",
	"GET /api/v1/me/sessions":                              "viewer",
	"DELETE /api/v1/me/sessions/{handle}":                  "viewer",
	"GET /api/v1/me/keys":                                  "viewer",
	"POST /api/v1/me/keys":                                 "viewer",
	"DELETE /api/v1/me/keys/{key_id}":                      "viewer",
	"GET /api/v1/overview":                                 "viewer",
	"GET /api/v1/events":                                   "viewer",
	"GET /api/v1/events/stream":                            "viewer",
	"GET /api/v1/events/{id}":                              "viewer",
	"GET /api/v1/sources":                                  "viewer",
	"GET /api/v1/sources/{source}":                         "viewer",
	"GET /api/v1/sensors":                                  "viewer",
	"GET /api/v1/rules":                                    "viewer",
	"GET /api/v1/recommendations":                          "viewer",
	"GET /api/v1/node":                                     "viewer",
	"GET /api/v1/digest":                                   "viewer",
	"GET /api/v1/decoys":                                   "viewer",
	"GET /api/v1/honeytokens":                              "viewer",
	"GET /api/v1/sessions":                                 "viewer",
	"GET /api/v1/sessions/{id}":                            "viewer",
	"GET /api/v1/campaigns":                                "viewer",
	"GET /api/v1/campaigns/{id}":                           "viewer",
	"GET /api/v1/posture":                                  "viewer",
	"GET /api/v1/coverage":                                 "viewer",
	"GET /api/v1/investigations":                           "viewer",
	"GET /api/v1/investigations/{id}":                      "viewer",
	"GET /api/v1/fleet":                                    "viewer",
	"GET /api/v1/fleet/nodes":                              "viewer",
	"GET /api/v1/fleet/nodes/{id}":                         "viewer",
	"GET /api/v1/export/events":                            "analyst",
	"GET /api/v1/export/indicators":                        "analyst",
	"GET /api/v1/sessions/{id}/report":                     "analyst",
	"GET /api/v1/investigations/{id}/report":               "analyst",
	"POST /api/v1/investigations":                          "analyst",
	"PATCH /api/v1/investigations/{id}":                    "analyst",
	"POST /api/v1/investigations/{id}/notes":               "analyst",
	"PUT /api/v1/investigations/{id}/events/{event_id}":    "analyst",
	"DELETE /api/v1/investigations/{id}/events/{event_id}": "analyst",
	"GET /api/v1/audit":                                    "admin",
	"GET /api/v1/audit/verify":                             "admin",
	"POST /api/v1/fleet/nodes/{id}/revoke":                 "admin",
	"GET /api/v1/fleet/enrollment-tokens":                  "admin",
	"POST /api/v1/fleet/enrollment-tokens":                 "admin",
	"DELETE /api/v1/fleet/enrollment-tokens/{id}":          "admin",
	"GET /api/v1/admin/accounts":                           "admin",
	"POST /api/v1/admin/accounts":                          "admin",
	"GET /api/v1/admin/accounts/{id}":                      "admin",
	"PATCH /api/v1/admin/accounts/{id}":                    "admin",
	"POST /api/v1/admin/accounts/{id}/keys":                "admin",
	"DELETE /api/v1/admin/accounts/{id}/keys/{key_id}":     "admin",
	"GET /api/v1/admin/sessions":                           "admin",
	"DELETE /api/v1/admin/sessions/{handle}":               "admin",
	"GET /api/v1/admin/settings":                           "admin",
	"GET /api/v1/admin/audit/export":                       "admin",
	"GET /api/v1/system":                                   "admin",
	// Round 6 routes (permissions, roles, editable settings, accepted posture risks).
	"GET /api/v1/permissions":                  "viewer",
	"GET /api/v1/admin/settings/history":       "admin",
	"PUT /api/v1/admin/settings/{key}":         "admin",
	"DELETE /api/v1/admin/settings/{key}":      "admin",
	"GET /api/v1/admin/roles":                  "admin",
	"POST /api/v1/admin/roles":                 "admin",
	"GET /api/v1/admin/roles/{id}":             "admin",
	"PATCH /api/v1/admin/roles/{id}":           "admin",
	"DELETE /api/v1/admin/roles/{id}":          "admin",
	"POST /api/v1/posture/{check_id}/accept":   "admin",
	"DELETE /api/v1/posture/{check_id}/accept": "admin",
}

var roleRank = map[string]int{"none": 0, "viewer": 1, "analyst": 2, "admin": 3}

// TestBuiltinRoleRouteMatrix sends a real request for every registered route as
// each built-in role and checks that exactly the pinned roles pass the gate.
func TestBuiltinRoleRouteMatrix(t *testing.T) {
	h := newConsoleHarness(t, nil)
	registered := map[string]bool{}
	for _, route := range h.server.RoutesForTest() {
		registered[route.Pattern] = true
	}
	missing := []string{}
	for pattern := range builtinRouteAccess {
		if !registered[pattern] {
			missing = append(missing, pattern)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("pinned routes no longer registered: %v", missing)
	}
	for pattern := range registered {
		if _, ok := builtinRouteAccess[pattern]; !ok {
			t.Fatalf("new route needs a pinned built-in access row: %s", pattern)
		}
	}
	replacer := strings.NewReplacer(
		"{event_id}", h.eventID, "{source}", "127.0.0.1", "{handle}", "ses_0000000000000000",
		"{key_id}", "key_000000000000", "{id}", "x0", "{check_id}", "POS-007", "{key}", "console.organization_name",
	)
	for pattern, least := range builtinRouteAccess {
		method, path, _ := strings.Cut(pattern, " ")
		path = replacer.Replace(path)
		for _, role := range []string{"viewer", "analyst", "admin"} {
			t.Run(pattern+"/"+role, func(t *testing.T) {
				h.clock.advance(time.Minute)
				input := apiRequest{method: method, path: path, token: "synthetic-" + role}
				if method == "POST" || method == "PATCH" || method == "PUT" {
					input.body = `{}`
				}
				response := h.request(t, input)
				denied := response.status == 403 && roleDenial(response.body)
				if want := roleRank[role] < roleRank[least]; denied != want {
					t.Fatalf("%s as %s: denied=%v want %v (status %d body %s)", pattern, role, denied, want,
						response.status, response.body)
				}
			})
		}
	}
}

func roleDenial(body []byte) bool {
	var decoded struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	return json.Unmarshal(body, &decoded) == nil && decoded.Error.Code == "forbidden" &&
		strings.Contains(decoded.Error.Message, "does not grant")
}
