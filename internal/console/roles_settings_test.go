package console_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console"
	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/console/permission"
	"github.com/metaforismo/aegismesh/internal/posture"
)

type roleJSON struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Builtin     bool     `json:"builtin"`
	Permissions []string `json:"permissions"`
	Assigned    struct {
		Managed int `json:"managed"`
		Config  int `json:"config"`
		OIDC    int `json:"oidc"`
	} `json:"assigned"`
}

type errorJSON struct {
	Error struct {
		Code string `json:"code"`
	} `json:"error"`
}

// editingOn enables settings editing and supplies configuration posture facts
// (no honeytokens, so POS-007 needs attention).
func editingOn(opts *console.Options) {
	opts.Config.SettingsEditing = config.SettingsEditingConsole
	opts.Posture = &posture.Facts{
		ConsoleEnabled: true, ConsoleListen: "127.0.0.1:9120", TokenLogin: true,
		OperatorRoles:    map[string]int{"admin": 1, "analyst": 1, "viewer": 1},
		DetectionEnabled: true, CorrelationEnabled: true, SettingsEditing: config.SettingsEditingConsole,
	}
}

func requireCode(t *testing.T, response apiResponse, status int, code string) {
	t.Helper()
	requireStatus(t, response, status)
	if got := decode[errorJSON](t, response).Error.Code; got != code {
		t.Fatalf("code = %q; want %q; body %s", got, code, response.body)
	}
}

func createRole(t *testing.T, h *consoleHarness, token, body string) roleJSON {
	t.Helper()
	response := h.request(t, apiRequest{method: "POST", path: "/api/v1/admin/roles", token: token, body: body})
	requireStatus(t, response, 201)
	return decode[roleJSON](t, response)
}

// principalWithRole creates a managed account holding role and returns a usable key.
func principalWithRole(t *testing.T, h *consoleHarness, name, kind, role string) (accountJSON, string) {
	t.Helper()
	account := createAccount(t, h, "synthetic-admin",
		`{"name":"`+name+`","kind":"`+kind+`","role":"`+role+`","tenants":["default"]}`)
	return account, createKey(t, h, "synthetic-admin", account.ID).Token
}

func loginWith(t *testing.T, h *consoleHarness, token string) (*http.Cookie, auth.Session) {
	t.Helper()
	response := h.request(t, apiRequest{method: "POST", path: "/api/v1/session", body: `{"token":"` + token + `"}`})
	requireStatus(t, response, 200)
	return response.cookies[0], decode[auth.Session](t, response)
}

// TestCustomRoleGrantsExactlyItsPermissions sends a real request for every
// registered route with a custom role's key and checks the gate passes exactly
// the routes whose permission the role holds.
func TestCustomRoleGrantsExactlyItsPermissions(t *testing.T) {
	h := newConsoleHarness(t, editingOn)
	perms := []string{permission.AuditRead, permission.EvidenceExport, permission.InvestigationsRead, permission.SystemRead}
	role := createRole(t, h, "synthetic-admin", `{"name":"Auditor","description":"Reads audit and system","permissions":["system.read","audit.read","investigations.read","evidence.export"]}`)
	if !slices.Equal(role.Permissions, []string{"audit.read", "evidence.export", "investigations.read", "system.read"}) || role.Builtin {
		t.Fatalf("role = %+v", role)
	}
	_, token := principalWithRole(t, h, "Auditor One", "person", role.ID)

	me := decode[map[string]any](t, h.request(t, apiRequest{method: "GET", path: "/api/v1/me", token: token}))
	if me["role"] != role.ID || me["role_name"] != "Auditor" || len(me["permissions"].([]any)) != 4 ||
		me["capabilities"].(map[string]any)["administer"] != true || me["capabilities"].(map[string]any)["manage_own_keys"] != false {
		t.Fatalf("me = %v", me)
	}

	replacer := strings.NewReplacer("{event_id}", h.eventID, "{source}", "127.0.0.1", "{handle}", "ses_0000000000000000",
		"{key_id}", "key_000000000000", "{id}", "x0", "{check_id}", "POS-007", "{key}", "console.organization_name")
	for _, route := range h.server.RoutesForTest() {
		if route.Permission == "" {
			continue
		}
		method, path, _ := strings.Cut(route.Pattern, " ")
		path = replacer.Replace(path)
		t.Run(route.Pattern, func(t *testing.T) {
			input := apiRequest{method: method, path: path, token: token}
			if method == "POST" || method == "PATCH" || method == "PUT" {
				input.body = `{}`
			}
			response := h.request(t, input)
			denied := response.status == 403 && roleDenial(response.body)
			want := route.Permission != "authenticated" && !slices.Contains(perms, route.Permission)
			if denied != want {
				t.Fatalf("%s: denied=%v want %v (%d %s)", route.Pattern, denied, want, response.status, response.body)
			}
		})
	}

	permissions := decode[struct {
		Version int               `json:"version"`
		Items   []permission.Info `json:"items"`
	}](t, h.request(t, apiRequest{method: "GET", path: "/api/v1/permissions", token: token}))
	if permissions.Version != 1 || len(permissions.Items) != 18 || permissions.Items[0].ID != "evidence.read" {
		t.Fatalf("catalogue = %+v", permissions)
	}
}

func TestRoleEditAppliesAtNextRequestAndEndsStreams(t *testing.T) {
	const heartbeat = 100 * time.Millisecond
	t.Cleanup(console.SetStreamHeartbeatForTest(heartbeat))
	h := newConsoleHarness(t, nil)
	role := createRole(t, h, "synthetic-admin", `{"name":"Reader","permissions":["evidence.read","analysis.read"]}`)
	_, token := principalWithRole(t, h, "Stream Service", "service", role.ID)
	cookie, session := loginWith(t, h, token)
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/events", token: token}), 200)
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/events", cookie: cookie}), 200)
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/investigations", cookie: cookie}), 403)
	stream := openStream(t, h, token)

	patched := h.request(t, apiRequest{method: "PATCH", path: "/api/v1/admin/roles/" + role.ID, token: "synthetic-admin",
		body: `{"permissions":["analysis.read","investigations.read"]}`})
	requireStatus(t, patched, 200)
	// Both the bearer key and the existing cookie session use the new set at once.
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/events", token: token}), 403)
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/events", cookie: cookie}), 403)
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/investigations", cookie: cookie, csrf: session.CSRFToken}), 200)
	select {
	case <-stream:
	case <-time.After(30 * heartbeat):
		t.Fatal("stream outlived removal of evidence.read")
	}

	records := h.request(t, apiRequest{method: "GET", path: "/api/v1/audit?action=role.update", token: "synthetic-admin"})
	requireStatus(t, records, 200)
	if !strings.Contains(string(records.body), "removed=evidence.read") {
		t.Fatalf("audit = %s", records.body)
	}
}

func TestRoleRulesBuiltinInUseAndLastAdmin(t *testing.T) {
	h := newConsoleHarness(t, nil)
	listed := decode[struct {
		Items  []roleJSON     `json:"items"`
		Limits map[string]int `json:"limits"`
	}](t, h.request(t, apiRequest{method: "GET", path: "/api/v1/admin/roles", token: "synthetic-admin"}))
	if len(listed.Items) != 3 || !listed.Items[2].Builtin || listed.Items[2].ID != "admin" || listed.Items[2].Assigned.Config != 1 ||
		len(listed.Items[2].Permissions) != 18 || listed.Limits["max_roles"] != 32 {
		t.Fatalf("roles = %+v", listed)
	}
	requireCode(t, h.request(t, apiRequest{method: "PATCH", path: "/api/v1/admin/roles/admin", token: "synthetic-admin",
		body: `{"name":"Root"}`}), 409, "builtin")
	requireCode(t, h.request(t, apiRequest{method: "DELETE", path: "/api/v1/admin/roles/viewer", token: "synthetic-admin"}), 409, "builtin")
	requireCode(t, h.request(t, apiRequest{method: "POST", path: "/api/v1/admin/roles", token: "synthetic-admin",
		body: `{"name":"Shadow","permissions":["roles.manage"]}`}), 400, "invalid_argument")
	requireCode(t, h.request(t, apiRequest{method: "POST", path: "/api/v1/admin/roles", token: "synthetic-admin",
		body: `{"name":"viewer","permissions":[]}`}), 409, "conflict")
	requireCode(t, h.request(t, apiRequest{method: "POST", path: "/api/v1/admin/roles", token: "synthetic-admin",
		body: `{"name":"Root","permissions":["root"]}`}), 400, "invalid_argument")

	owner := createRole(t, h, "synthetic-admin", `{"name":"Owner","permissions":`+mustJSON(permission.Builtin("admin"))+`}`)
	account, _ := principalWithRole(t, h, "Owner One", "person", owner.ID)
	requireCode(t, h.request(t, apiRequest{method: "DELETE", path: "/api/v1/admin/roles/" + owner.ID, token: "synthetic-admin"}), 409, "in_use")
	got := decode[roleJSON](t, h.request(t, apiRequest{method: "GET", path: "/api/v1/admin/roles/" + owner.ID, token: "synthetic-admin"}))
	if got.Assigned.Managed != 1 {
		t.Fatalf("assigned = %+v", got.Assigned)
	}
	// A config admin remains, so the custom role may lose its administration permissions.
	requireStatus(t, h.request(t, apiRequest{method: "PATCH", path: "/api/v1/admin/roles/" + owner.ID, token: "synthetic-admin",
		body: `{"permissions":["evidence.read"]}`}), 200)
	requireStatus(t, h.request(t, apiRequest{method: "PATCH", path: "/api/v1/admin/accounts/" + account.ID, token: "synthetic-admin",
		body: `{"role":"viewer"}`}), 200)
	requireStatus(t, h.request(t, apiRequest{method: "DELETE", path: "/api/v1/admin/roles/" + owner.ID, token: "synthetic-admin"}), 204)
}

// TestLastAdminAcrossRolesOverHTTP starts a console whose only administrator is
// a managed account holding a custom role, then tries to remove that capability.
func TestLastAdminAcrossRolesOverHTTP(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "console")
	seed := newConsoleHarness(t, func(opts *console.Options) { opts.StateDir = stateDir })
	owner := createRole(t, seed, "synthetic-admin", `{"name":"Owner","permissions":`+mustJSON(permission.Builtin("admin"))+`}`)
	account, token := principalWithRole(t, seed, "Owner One", "person", owner.ID)
	requireStatus(t, seed.request(t, apiRequest{method: "GET", path: "/api/v1/admin/accounts", token: token}), 200)
	seed.close(t)

	h := newConsoleHarness(t, func(opts *console.Options) {
		opts.StateDir = stateDir
		opts.Config.Operators = slices.DeleteFunc(opts.Config.Operators, func(op config.Operator) bool { return op.Role == "admin" })
	})
	requireCode(t, h.request(t, apiRequest{method: "PATCH", path: "/api/v1/admin/roles/" + owner.ID, token: token,
		body: `{"permissions":["accounts.manage","accounts.read","evidence.read"]}`}), 409, "last_admin")
	requireCode(t, h.request(t, apiRequest{method: "PATCH", path: "/api/v1/admin/accounts/" + account.ID, token: token,
		body: `{"role":"analyst"}`}), 409, "last_admin")
	// A second administrator under the built-in admin role makes the change safe.
	second := createAccount(t, h, token, `{"name":"Second","kind":"person","role":"admin","tenants":["default"]}`)
	createKey(t, h, token, second.ID)
	requireStatus(t, h.request(t, apiRequest{method: "PATCH", path: "/api/v1/admin/roles/" + owner.ID, token: token,
		body: `{"permissions":["accounts.manage","accounts.read","evidence.read"]}`}), 200)
}

// TestNoEscalationThroughAdministration exercises each path by which a
// partial administrator could otherwise reach permissions it does not hold.
func TestNoEscalationThroughAdministration(t *testing.T) {
	h := newConsoleHarness(t, nil)
	viewerPerms := permission.Builtin("viewer")
	manager := createRole(t, h, "synthetic-admin", `{"name":"Account manager","permissions":`+
		mustJSON(append(slices.Clone(viewerPerms), "accounts.read", "accounts.manage", "roles.manage", "sessions.manage"))+`}`)
	_, token := principalWithRole(t, h, "Manager One", "person", manager.ID)
	admin, _ := principalWithRole(t, h, "Real Admin", "person", "admin")
	adminKey := createKey(t, h, "synthetic-admin", admin.ID)
	plain, _ := principalWithRole(t, h, "Plain Viewer", "person", "viewer")

	for _, attempt := range []struct {
		name, method, path, body string
	}{
		{"create an admin account", "POST", "/api/v1/admin/accounts", `{"name":"Sock","kind":"person","role":"admin","tenants":["default"]}`},
		{"promote someone to admin", "PATCH", "/api/v1/admin/accounts/" + plain.ID, `{"role":"admin"}`},
		{"disable an admin", "PATCH", "/api/v1/admin/accounts/" + admin.ID, `{"status":"disabled"}`},
		{"mint a key for an admin", "POST", "/api/v1/admin/accounts/" + admin.ID + "/keys", `{"label":"stolen"}`},
		{"revoke an admin key", "DELETE", "/api/v1/admin/accounts/" + admin.ID + "/keys/" + adminKey.Key.ID, ""},
		{"create a wider role", "POST", "/api/v1/admin/roles", `{"name":"Wider","permissions":["audit.read","evidence.read"]}`},
		{"widen its own role", "PATCH", "/api/v1/admin/roles/" + manager.ID, `{"permissions":` +
			mustJSON(append(slices.Clone(viewerPerms), "accounts.read", "accounts.manage", "roles.manage", "sessions.manage", "settings.manage", "settings.read")) + `}`},
	} {
		t.Run(attempt.name, func(t *testing.T) {
			requireCode(t, h.request(t, apiRequest{method: attempt.method, path: attempt.path, token: token, body: attempt.body}),
				403, "exceeds_own_permissions")
		})
	}
	// Ending a more privileged principal's session is refused too.
	_, adminSession := loginWith(t, h, "synthetic-admin")
	sessions := decode[struct {
		Items []auth.SessionInfo `json:"items"`
	}](t, h.request(t, apiRequest{method: "GET", path: "/api/v1/admin/sessions", token: token}))
	handle := ""
	for _, info := range sessions.Items {
		if info.AccountID == adminSession.Principal.ID {
			handle = info.Handle
		}
	}
	requireCode(t, h.request(t, apiRequest{method: "DELETE", path: "/api/v1/admin/sessions/" + handle, token: token}), 403, "exceeds_own_permissions")

	// Within its own permissions the manager works normally.
	created := createAccount(t, h, token, `{"name":"New Viewer","kind":"person","role":"viewer","tenants":["default"]}`)
	createKey(t, h, token, created.ID)
	narrow := createRole(t, h, token, `{"name":"Narrow","permissions":["evidence.read"]}`)
	requireStatus(t, h.request(t, apiRequest{method: "PATCH", path: "/api/v1/admin/accounts/" + created.ID, token: token,
		body: `{"role":"` + narrow.ID + `"}`}), 200)
	records := h.request(t, apiRequest{method: "GET", path: "/api/v1/audit?action=account.create", token: "synthetic-admin"})
	if !strings.Contains(string(records.body), "exceeds_own_permissions") {
		t.Fatalf("refusal not audited: %s", records.body)
	}
}

func TestSettingsEditingLifecycle(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "console")
	h := newConsoleHarness(t, func(opts *console.Options) {
		editingOn(opts)
		opts.StateDir = stateDir
		opts.Config.SessionTTLSeconds = 3600
	})
	cookie, session := loginWith(t, h, "synthetic-admin")
	put := func(key, body string, csrf bool) apiResponse {
		input := apiRequest{method: "PUT", path: "/api/v1/admin/settings/" + key, cookie: cookie, body: body}
		if csrf {
			input.csrf = session.CSRFToken
		}
		return h.request(t, input)
	}
	requireStatus(t, put("console.organization_name", `{"value":"Example SOC","reason":"Branding"}`, false), 403)
	requireCode(t, h.request(t, apiRequest{method: "PUT", path: "/api/v1/admin/settings/console.organization_name",
		token: "synthetic-analyst", body: `{"value":"x","reason":"y"}`}), 403, "forbidden")
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/admin/settings/history", token: "synthetic-viewer"}), 403)

	for _, key := range []string{"console.listen", "storage.encryption", "posture.accepted", "console.settings_editing", "no.such.key"} {
		requireCode(t, put(key, `{"value":"x","reason":"try"}`, true), 409, "not_editable")
	}
	requireCode(t, put("console.session_ttl_seconds", `{"value":"7200","reason":"string for a number"}`, true), 400, "invalid_argument")
	requireCode(t, put("console.session_ttl_seconds", `{"value":600,"reason":"below the console minimum"}`, true), 400, "invalid_argument")
	requireCode(t, put("console.session_ttl_seconds", `{"value":7200}`, true), 400, "invalid_argument")
	requireCode(t, put("console.key_max_days", `{"value":30,"reason":"below the default"}`, true), 400, "invalid_argument")

	item := decode[map[string]any](t, put("console.organization_name", `{"value":"Example SOC","reason":"Branding"}`, true))
	if item["effective"] != "Example SOC" || item["file_value"] != "" || item["overridden"] != true || item["source"] != "console" ||
		item["applies"] != "live" || item["editable"] != true {
		t.Fatalf("item = %v", item)
	}
	put("console.sign_in_banner", `{"value":"Authorized use only.\nActivity is logged.","reason":"Legal notice"}`, true)
	meta := decode[map[string]any](t, h.request(t, apiRequest{method: "GET", path: "/api/v1/meta"}))
	if meta["organization_name"] != "Example SOC" || meta["sign_in_banner"] != "Authorized use only.\nActivity is logged." {
		t.Fatalf("meta = %v", meta)
	}

	// Live: new sessions take the new lifetime, the idle timeout applies at once,
	// and key limits apply to new keys.
	requireStatus(t, put("console.session_ttl_seconds", `{"value":900,"reason":"Shorter sessions"}`, true), 200)
	_, short := loginWith(t, h, "synthetic-viewer")
	if got := short.ExpiresAt.Sub(h.clock.now()); got < 899*time.Second || got > 900*time.Second {
		t.Fatalf("new session lifetime = %v", got)
	}
	requireStatus(t, put("console.key_default_days", `{"value":14,"reason":"Short keys"}`, true), 200)
	requireStatus(t, put("console.key_max_days", `{"value":30,"reason":"Short keys"}`, true), 200)
	account := createAccount(t, h, "synthetic-admin", `{"name":"Limited","kind":"service","role":"viewer","tenants":["default"]}`)
	requireCode(t, h.request(t, apiRequest{method: "POST", path: "/api/v1/admin/accounts/" + account.ID + "/keys",
		token: "synthetic-admin", body: `{"label":"long","expires_in_days":31}`}), 400, "invalid_argument")
	defaulted := decode[struct {
		Key struct {
			ExpiresAt time.Time `json:"expires_at"`
		} `json:"key"`
	}](t, h.request(t, apiRequest{method: "POST", path: "/api/v1/admin/accounts/" + account.ID + "/keys",
		token: "synthetic-admin", body: `{"label":"default"}`}))
	if got := defaulted.Key.ExpiresAt.Sub(h.clock.now()).Round(time.Hour); got != 14*24*time.Hour {
		t.Fatalf("default key lifetime = %v", got)
	}
	requireStatus(t, put("console.session_idle_seconds", `{"value":300,"reason":"Idle policy"}`, true), 200)
	h.clock.advance(301 * time.Second)
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/session", cookie: cookie}), 401)
	cookie, session = loginWith(t, h, "synthetic-admin")

	reverted := decode[map[string]any](t, h.request(t, apiRequest{method: "DELETE",
		path: "/api/v1/admin/settings/console.organization_name", cookie: cookie, csrf: session.CSRFToken}))
	if reverted["overridden"] != false || reverted["effective"] != "" {
		t.Fatalf("reverted = %v", reverted)
	}
	history := decode[struct {
		Items []map[string]any `json:"items"`
	}](t, h.request(t, apiRequest{method: "GET", path: "/api/v1/admin/settings/history", token: "synthetic-admin"}))
	if len(history.Items) != 7 || history.Items[0]["key"] != "console.organization_name" || history.Items[0]["to"] != "" ||
		history.Items[0]["from"] != "Example SOC" || history.Items[len(history.Items)-1]["reason"] != "Branding" ||
		history.Items[0]["actor_id"] != "cfg:admin" {
		t.Fatalf("history = %v", history.Items)
	}
	records := string(h.request(t, apiRequest{method: "GET", path: "/api/v1/audit?action=settings.update", token: "synthetic-admin"}).body)
	if !strings.Contains(records, `from=\"3600\" to=\"900\"`) || !strings.Contains(records, `reason=\"Shorter sessions\"`) {
		t.Fatalf("settings audit = %s", records)
	}
	if !strings.Contains(string(h.request(t, apiRequest{method: "GET", path: "/api/v1/audit?action=settings.revert", token: "synthetic-admin"}).body),
		"console.organization_name") {
		t.Fatal("revert not audited")
	}

	// The overlay survives a restart and is applied again.
	h.close(t)
	again := newConsoleHarness(t, func(opts *console.Options) {
		editingOn(opts)
		opts.StateDir = stateDir
		opts.Config.SessionTTLSeconds = 3600
	})
	_, restarted := loginWith(t, again, "synthetic-viewer")
	if got := restarted.ExpiresAt.Sub(again.clock.now()); got > 900*time.Second {
		t.Fatalf("overlay not applied after restart: %v", got)
	}
	meta = decode[map[string]any](t, again.request(t, apiRequest{method: "GET", path: "/api/v1/meta"}))
	if meta["sign_in_banner"] != "Authorized use only.\nActivity is logged." || meta["organization_name"] != "" {
		t.Fatalf("meta after restart = %v", meta)
	}
}

func TestEditingDisabledIgnoresOverlay(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "console")
	on := newConsoleHarness(t, func(opts *console.Options) { editingOn(opts); opts.StateDir = stateDir })
	requireStatus(t, on.request(t, apiRequest{method: "PUT", path: "/api/v1/admin/settings/console.organization_name",
		token: "synthetic-admin", body: `{"value":"Stored","reason":"Before turning editing off"}`}), 200)
	on.close(t)

	h := newConsoleHarness(t, func(opts *console.Options) { opts.StateDir = stateDir })
	requireCode(t, h.request(t, apiRequest{method: "PUT", path: "/api/v1/admin/settings/console.organization_name",
		token: "synthetic-admin", body: `{"value":"x","reason":"y"}`}), 409, "editing_disabled")
	requireCode(t, h.request(t, apiRequest{method: "DELETE", path: "/api/v1/admin/settings/console.organization_name",
		token: "synthetic-admin"}), 409, "editing_disabled")
	requireCode(t, h.request(t, apiRequest{method: "POST", path: "/api/v1/posture/POS-007/accept", token: "synthetic-admin",
		body: `{"reason":"x","until":"` + h.clock.now().Add(time.Hour).UTC().Format(time.RFC3339) + `"}`}), 409, "editing_disabled")
	// With editing off the file is the only source: the stored value is not applied.
	if meta := decode[map[string]any](t, h.request(t, apiRequest{method: "GET", path: "/api/v1/meta"})); meta["organization_name"] != "" {
		t.Fatalf("overlay applied while editing is off: %v", meta)
	}
	view := decode[map[string]any](t, h.request(t, apiRequest{method: "GET", path: "/api/v1/admin/settings", token: "synthetic-admin"}))
	if view["editing"] != "off" || view["editable"] != false || !strings.Contains(view["note"].(string), "1 stored override(s) are not applied") {
		t.Fatalf("settings = %v", view)
	}
}

func TestInvalidOverlayIsIgnoredSafely(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "console")
	// A first start prepares the state directory (tenants, settings).
	newConsoleHarness(t, func(opts *console.Options) { editingOn(opts); opts.StateDir = stateDir }).close(t)
	overlay := `{"schema":"aegismesh.console.settings/v1","next_seq":1,"values":{"console.session_ttl_seconds":"5",` +
		`"console.organization_name":"Kept"},"accepted":{},"history":[]}`
	if err := os.WriteFile(filepath.Join(stateDir, "settings", "settings.json"), []byte(overlay), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	h := newConsoleHarness(t, func(opts *console.Options) {
		editingOn(opts)
		opts.StateDir = stateDir
		opts.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	})
	if !strings.Contains(logs.String(), "console settings override ignored") || !strings.Contains(logs.String(), "console.session_ttl_seconds") {
		t.Fatalf("logs = %s", logs.String())
	}
	if meta := decode[map[string]any](t, h.request(t, apiRequest{method: "GET", path: "/api/v1/meta"})); meta["organization_name"] != "Kept" {
		t.Fatalf("valid override not applied: %v", meta)
	}
	_, session := loginWith(t, h, "synthetic-viewer")
	if got := session.ExpiresAt.Sub(h.clock.now()); got != 60*time.Second {
		t.Fatalf("file TTL must apply, got %v", got)
	}
	report := decode[posture.Report](t, h.request(t, apiRequest{method: "GET", path: "/api/v1/posture", token: "synthetic-admin"}))
	if check := findCheck(report, "POS-022"); check.Status != "attention" || !strings.Contains(check.Detail, "console.session_ttl_seconds") {
		t.Fatalf("POS-022 = %+v", check)
	}
	system := string(h.request(t, apiRequest{method: "GET", path: "/api/v1/system", token: "synthetic-admin"}).body)
	if !strings.Contains(system, `"id":"settings","status":"degraded"`) {
		t.Fatalf("system = %s", system)
	}

	// A corrupt overlay is neither applied nor overwritten; the console still starts.
	h.close(t)
	if err := os.WriteFile(filepath.Join(stateDir, "settings", "settings.json"), []byte(`{"schema":`), 0o600); err != nil {
		t.Fatal(err)
	}
	broken := newConsoleHarness(t, func(opts *console.Options) { editingOn(opts); opts.StateDir = stateDir })
	requireStatus(t, broken.request(t, apiRequest{method: "PUT", path: "/api/v1/admin/settings/console.organization_name",
		token: "synthetic-admin", body: `{"value":"x","reason":"y"}`}), 503)
	if body, _ := os.ReadFile(filepath.Join(stateDir, "settings", "settings.json")); string(body) != `{"schema":` {
		t.Fatal("corrupt overlay overwritten")
	}
	report = decode[posture.Report](t, broken.request(t, apiRequest{method: "GET", path: "/api/v1/posture", token: "synthetic-admin"}))
	if check := findCheck(report, "POS-022"); check.Status != "attention" || !strings.Contains(check.Detail, "corrupt") {
		t.Fatalf("POS-022 = %+v", check)
	}
}

func TestPostureAcceptAndExpire(t *testing.T) {
	h := newConsoleHarness(t, editingOn)
	until := h.clock.now().Add(time.Hour).UTC().Format(time.RFC3339)
	accept := func(id, body string) apiResponse {
		return h.request(t, apiRequest{method: "POST", path: "/api/v1/posture/" + id + "/accept", token: "synthetic-admin", body: body})
	}
	requireCode(t, accept("POS-007", `{"until":"`+until+`"}`), 400, "invalid_argument")
	requireCode(t, accept("POS-007", `{"reason":"too long","until":"`+h.clock.now().Add(181*24*time.Hour).UTC().Format(time.RFC3339)+`"}`), 400, "invalid_argument")
	requireCode(t, accept("POS-001", `{"reason":"not attention","until":"`+until+`"}`), 409, "conflict")
	requireCode(t, accept("POS-999", `{"reason":"unknown","until":"`+until+`"}`), 404, "not_found")
	requireCode(t, h.request(t, apiRequest{method: "POST", path: "/api/v1/posture/POS-007/accept", token: "synthetic-analyst",
		body: `{"reason":"x","until":"` + until + `"}`}), 403, "forbidden")

	accepted := decode[posture.Check](t, accept("POS-007", `{"reason":"Lab node without honeytokens","until":"`+until+`"}`))
	if accepted.Status != "accepted" || accepted.Accepted == nil || accepted.Accepted.By != "cfg:admin" || accepted.Accepted.Until != until {
		t.Fatalf("accepted = %+v", accepted)
	}
	report := decode[posture.Report](t, h.request(t, apiRequest{method: "GET", path: "/api/v1/posture", token: "synthetic-viewer"}))
	if check := findCheck(report, "POS-007"); check.Status != "accepted" || report.Summary.Accepted != 1 || report.Acceptances != "applied" {
		t.Fatalf("report = %+v %+v", report.Summary, check)
	}
	settingsView := string(h.request(t, apiRequest{method: "GET", path: "/api/v1/admin/settings", token: "synthetic-admin"}).body)
	if !strings.Contains(settingsView, `"key":"posture.accepted","label":"Accepted posture risks","value":"1 accepted"`) {
		t.Fatalf("settings = %s", settingsView)
	}

	// Past its expiry the acceptance is ignored and the check needs attention again.
	h.clock.advance(2 * time.Hour)
	report = decode[posture.Report](t, h.request(t, apiRequest{method: "GET", path: "/api/v1/posture", token: "synthetic-viewer"}))
	if check := findCheck(report, "POS-007"); check.Status != "attention" || check.Accepted != nil || report.Summary.Accepted != 0 {
		t.Fatalf("expired acceptance applied: %+v", check)
	}
	requireCode(t, h.request(t, apiRequest{method: "DELETE", path: "/api/v1/posture/POS-007/accept", token: "synthetic-admin"}), 404, "not_found")

	again := h.clock.now().Add(time.Hour).UTC().Format(time.RFC3339)
	requireStatus(t, accept("POS-007", `{"reason":"Again","until":"`+again+`"}`), 200)
	requireStatus(t, h.request(t, apiRequest{method: "DELETE", path: "/api/v1/posture/POS-007/accept", token: "synthetic-admin"}), 204)
	records := string(h.request(t, apiRequest{method: "GET", path: "/api/v1/audit?action=posture.accept", token: "synthetic-admin"}).body)
	if !strings.Contains(records, "POS-007") || !strings.Contains(records, `reason=\"Lab node without honeytokens\"`) {
		t.Fatalf("audit = %s", records)
	}
	if !strings.Contains(string(h.request(t, apiRequest{method: "GET", path: "/api/v1/audit?action=posture.unaccept", token: "synthetic-admin"}).body), "POS-007") {
		t.Fatal("unaccept not audited")
	}
}

func TestServiceAccountHighRiskPosture(t *testing.T) {
	h := newConsoleHarness(t, editingOn)
	role := createRole(t, h, "synthetic-admin", `{"name":"Automation","permissions":["accounts.manage","accounts.read","evidence.read"]}`)
	principalWithRole(t, h, "ci-bot", "service", role.ID)
	report := decode[posture.Report](t, h.request(t, apiRequest{method: "GET", path: "/api/v1/posture", token: "synthetic-admin"}))
	if check := findCheck(report, "POS-021"); check.Status != "attention" || !strings.Contains(check.Detail, "ci-bot (Automation)") {
		t.Fatalf("POS-021 = %+v", check)
	}
	if check := findCheck(report, "POS-020"); check.Status != "info" || !strings.Contains(check.Detail, "roles: admin") {
		t.Fatalf("POS-020 = %+v", check)
	}
}

func findCheck(report posture.Report, id string) posture.Check {
	for _, check := range report.Checks {
		if check.ID == id {
			return check
		}
	}
	return posture.Check{}
}

func mustJSON(value any) string {
	body, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(body)
}
