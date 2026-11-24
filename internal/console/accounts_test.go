package console_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console"
	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/testutil/oidctest"
)

type keyCreated struct {
	Key struct {
		ID     string `json:"id"`
		Prefix string `json:"prefix"`
		Status string `json:"status"`
	} `json:"key"`
	Token string `json:"token"`
}

type accountJSON struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Source         string   `json:"source"`
	Role           string   `json:"role"`
	Status         string   `json:"status"`
	Tenants        []string `json:"tenants"`
	ActiveKeys     int      `json:"active_keys"`
	ActiveSessions int      `json:"active_sessions"`
}

func decode[T any](t *testing.T, response apiResponse) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(response.body, &value); err != nil {
		t.Fatalf("decode %s: %v", response.body, err)
	}
	return value
}

func createAccount(t *testing.T, h *consoleHarness, token, body string) accountJSON {
	t.Helper()
	response := h.request(t, apiRequest{method: "POST", path: "/api/v1/admin/accounts", token: token, body: body})
	requireStatus(t, response, 201)
	return decode[accountJSON](t, response)
}

func createKey(t *testing.T, h *consoleHarness, token, accountID string) keyCreated {
	t.Helper()
	response := h.request(t, apiRequest{method: "POST", path: "/api/v1/admin/accounts/" + accountID + "/keys",
		token: token, body: `{"label":"integration","expires_in_days":30}`})
	requireStatus(t, response, 201)
	return decode[keyCreated](t, response)
}

func TestManagedAccountKeyLifecycle(t *testing.T) {
	h := newConsoleHarness(t, nil)
	account := createAccount(t, h, "synthetic-admin", `{"name":"SIEM pull","kind":"service","role":"analyst","tenants":["default"]}`)
	if !strings.HasPrefix(account.ID, "acc_") || account.Source != "managed" || account.Status != "active" {
		t.Fatalf("account = %+v", account)
	}
	key := createKey(t, h, "synthetic-admin", account.ID)
	if !strings.HasPrefix(key.Token, "amk_") || len(key.Token) != 47 || key.Key.Prefix != key.Token[:8] {
		t.Fatalf("key = %+v", key.Key)
	}

	me := decode[map[string]any](t, h.request(t, apiRequest{method: "GET", path: "/api/v1/me", token: key.Token}))
	capabilities := me["capabilities"].(map[string]any)
	if me["id"] != account.ID || me["source"] != "managed" || me["kind"] != "service" || me["role"] != "analyst" ||
		capabilities["manage_own_keys"] != true || capabilities["administer"] != false || me["created_at"] == nil {
		t.Fatalf("me = %v", me)
	}
	// Analyst grants apply; admin routes do not.
	requireStatus(t, h.request(t, apiRequest{method: "POST", path: "/api/v1/investigations", token: key.Token,
		body: `{"title":"Managed analyst"}`}), 201)
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/admin/accounts", token: key.Token}), 403)

	// The same key opens a browser session whose expiry never exceeds the key's.
	login := h.request(t, apiRequest{method: "POST", path: "/api/v1/session", body: `{"token":"` + key.Token + `"}`})
	requireStatus(t, login, 200)
	cookie := login.cookies[0]
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/me", cookie: cookie}), 200)

	// Self-service keys: list without digests, mint and revoke.
	own := h.request(t, apiRequest{method: "POST", path: "/api/v1/me/keys", token: key.Token,
		body: `{"label":"rotation","expires_in_days":7}`})
	requireStatus(t, own, 201)
	second := decode[keyCreated](t, own)
	listed := h.request(t, apiRequest{method: "GET", path: "/api/v1/me/keys", token: second.Token})
	requireStatus(t, listed, 200)
	if strings.Contains(string(listed.body), "sha256") || strings.Contains(string(listed.body), key.Token[8:]) ||
		strings.Count(string(listed.body), `"status":"active"`) != 2 {
		t.Fatalf("own keys = %s", listed.body)
	}
	requireStatus(t, h.request(t, apiRequest{method: "DELETE", path: "/api/v1/me/keys/" + second.Key.ID, token: key.Token}), 204)
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/me", token: second.Token}), 401)

	// Disabling cuts off the key and the browser session immediately.
	requireStatus(t, h.request(t, apiRequest{method: "PATCH", path: "/api/v1/admin/accounts/" + account.ID,
		token: "synthetic-admin", body: `{"status":"disabled"}`}), 200)
	h.clock.advance(time.Minute)
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/me", token: key.Token}), 401)
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/me", cookie: cookie}), 401)
	requireStatus(t, h.request(t, apiRequest{method: "POST", path: "/api/v1/session", body: `{"token":"` + key.Token + `"}`}), 401)
	// A disabled account cannot receive keys.
	requireStatus(t, h.request(t, apiRequest{method: "POST", path: "/api/v1/admin/accounts/" + account.ID + "/keys",
		token: "synthetic-admin", body: `{"label":"x"}`}), 409)

	h.clock.advance(time.Minute)
	requireStatus(t, h.request(t, apiRequest{method: "PATCH", path: "/api/v1/admin/accounts/" + account.ID,
		token: "synthetic-admin", body: `{"status":"active"}`}), 200)
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/me", token: key.Token}), 200)
	requireStatus(t, h.request(t, apiRequest{method: "DELETE",
		path: "/api/v1/admin/accounts/" + account.ID + "/keys/" + key.Key.ID, token: "synthetic-admin"}), 204)
	h.clock.advance(time.Minute)
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/me", token: key.Token}), 401)

	detail := h.request(t, apiRequest{method: "GET", path: "/api/v1/admin/accounts/" + account.ID, token: "synthetic-admin"})
	requireStatus(t, detail, 200)
	if !strings.Contains(string(detail.body), `"status":"revoked"`) || strings.Contains(string(detail.body), "sha256") {
		t.Fatalf("detail = %s", detail.body)
	}

	// Nothing secret reaches the audit trail, in either export format.
	for _, format := range []string{"jsonl", "csv"} {
		export := h.request(t, apiRequest{method: "GET", path: "/api/v1/admin/audit/export?format=" + format, token: "synthetic-admin"})
		requireStatus(t, export, 200)
		body := string(export.body)
		for _, secret := range []string{key.Token, key.Token[8:], second.Token[8:], auth.Digest(key.Token),
			auth.Digest(second.Token), cookie.Value, "synthetic-admin", auth.Digest("synthetic-admin")} {
			if strings.Contains(body, secret) {
				t.Fatalf("%s audit export contains secret material", format)
			}
		}
		for _, action := range []string{"account.create", "key.create", "key.revoke", "account.update", "audit.export"} {
			if !strings.Contains(body, action) {
				t.Fatalf("%s audit export lacks %s: %s", format, action, body)
			}
		}
		if !strings.Contains(export.header.Get("Content-Disposition"), "attachment") {
			t.Fatal("audit export is not an attachment")
		}
	}
}

func TestLastAdminGuardOverHTTP(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "console")
	first := newConsoleHarness(t, func(opts *console.Options) { opts.StateDir = stateDir })
	admin := createAccount(t, first, "synthetic-admin", `{"name":"Managed Admin","kind":"person","role":"admin","tenants":["default"]}`)
	key := createKey(t, first, "synthetic-admin", admin.ID)
	if err := first.server.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Restart without any config-file admin: the managed admin is now the last one.
	h := newConsoleHarness(t, func(opts *console.Options) {
		opts.StateDir = stateDir
		opts.Config.Operators = []config.Operator{{Name: "viewer", Role: "viewer", TokenSHA256: auth.Digest("synthetic-viewer")}}
	})
	for _, body := range []string{`{"role":"analyst"}`, `{"status":"disabled"}`} {
		response := h.request(t, apiRequest{method: "PATCH", path: "/api/v1/admin/accounts/" + admin.ID, token: key.Token, body: body})
		requireStatus(t, response, 409)
		if !strings.Contains(string(response.body), `"code":"last_admin"`) {
			t.Fatalf("body = %s", response.body)
		}
	}
	requireStatus(t, h.request(t, apiRequest{method: "DELETE", path: "/api/v1/me/keys/" + key.Key.ID, token: key.Token}), 409)
	// Config operators are read-only here.
	notManaged := h.request(t, apiRequest{method: "PATCH", path: "/api/v1/admin/accounts/cfg:viewer", token: key.Token, body: `{"role":"admin"}`})
	requireStatus(t, notManaged, 409)
	if !strings.Contains(string(notManaged.body), `"code":"not_managed"`) {
		t.Fatalf("body = %s", notManaged.body)
	}
	requireStatus(t, h.request(t, apiRequest{method: "POST", path: "/api/v1/admin/accounts/cfg:viewer/keys", token: key.Token, body: `{"label":"x"}`}), 409)
	// A second usable admin lifts the guard.
	other := createAccount(t, h, key.Token, `{"name":"Second Admin","kind":"person","role":"admin","tenants":["default"]}`)
	createKey(t, h, key.Token, other.ID)
	requireStatus(t, h.request(t, apiRequest{method: "PATCH", path: "/api/v1/admin/accounts/" + admin.ID, token: key.Token, body: `{"role":"viewer"}`}), 200)
	// The role change revoked the old grant's sessions, and the key now carries viewer rights.
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/admin/accounts", token: key.Token}), 403)
}

func TestAccountValidationAndRoleDenials(t *testing.T) {
	h := newConsoleHarness(t, nil)
	for _, body := range []string{
		`{"name":"","kind":"person","role":"viewer","tenants":["default"]}`,
		`{"name":"x","kind":"person","role":"owner","tenants":["default"]}`,
		`{"name":"x","kind":"robot","role":"viewer","tenants":["default"]}`,
		`{"name":"x","kind":"person","role":"viewer","tenants":["bravo"]}`,
		`{"name":"x","kind":"person","role":"viewer","tenants":["default"],"extra":1}`,
		`{"name":"x","name":"y","kind":"person","role":"viewer","tenants":["default"]}`,
	} {
		requireStatus(t, h.request(t, apiRequest{method: "POST", path: "/api/v1/admin/accounts", token: "synthetic-admin", body: body}), 400)
	}
	requireStatus(t, h.request(t, apiRequest{method: "POST", path: "/api/v1/admin/accounts", token: "synthetic-admin",
		body: `{"name":"ADMIN","kind":"person","role":"viewer","tenants":["default"]}`}), 409)
	account := createAccount(t, h, "synthetic-admin", `{"name":"Viewer Person","kind":"person","role":"viewer","tenants":["default"]}`)
	for _, body := range []string{`{"label":""}`, `{"label":"x","expires_in_days":366}`, `{"label":"x","expires_in_days":-1}`} {
		requireStatus(t, h.request(t, apiRequest{method: "POST", path: "/api/v1/admin/accounts/" + account.ID + "/keys",
			token: "synthetic-admin", body: body}), 400)
	}
	requireStatus(t, h.request(t, apiRequest{method: "PATCH", path: "/api/v1/admin/accounts/" + account.ID,
		token: "synthetic-admin", body: `{}`}), 400)
	for _, token := range []string{"synthetic-viewer", "synthetic-analyst"} {
		for _, request := range []apiRequest{
			{method: "GET", path: "/api/v1/admin/accounts"},
			{method: "POST", path: "/api/v1/admin/accounts", body: `{"name":"x","kind":"person","role":"admin","tenants":["default"]}`},
			{method: "GET", path: "/api/v1/admin/settings"},
			{method: "GET", path: "/api/v1/system"},
			{method: "GET", path: "/api/v1/admin/audit/export"},
		} {
			request.token = token
			requireStatus(t, h.request(t, request), 403)
		}
	}
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/admin/audit/export?format=xml", token: "synthetic-admin"}), 400)
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/admin/audit/export?since=yesterday", token: "synthetic-admin"}), 400)
}

func TestKeyAuthenticationIsThrottled(t *testing.T) {
	h := newConsoleHarness(t, nil)
	for range 10 {
		requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/me", token: "amk_" + strings.Repeat("A", 43)}), 401)
	}
	response := h.request(t, apiRequest{method: "GET", path: "/api/v1/me", token: "amk_" + strings.Repeat("B", 43)})
	requireStatus(t, response, 429)
	if response.header.Get("Retry-After") != "60" {
		t.Fatal("missing Retry-After")
	}
}

func TestCookieMutationsRequireCSRFAndPreferencesValidate(t *testing.T) {
	h := newConsoleHarness(t, nil)
	cookie, session := h.login(t, nil)
	create := apiRequest{method: "POST", path: "/api/v1/admin/accounts", cookie: cookie,
		body: `{"name":"CSRF Probe","kind":"person","role":"viewer","tenants":["default"]}`}
	requireStatus(t, h.request(t, create), 403)
	create.csrf, create.origin = session.CSRFToken, "http://evil.invalid"
	requireStatus(t, h.request(t, create), 403)
	create.origin = ""
	requireStatus(t, h.request(t, create), 201)

	requireStatus(t, h.request(t, apiRequest{method: "PUT", path: "/api/v1/me/preferences", cookie: cookie, body: `{"theme":"dark"}`}), 403)
	for _, body := range []string{`{"theme":"neon"}`, `{"colour":"red"}`, `{"timezone":"Europe/Rome"}`, `[]`, `{"theme":1}`} {
		requireStatus(t, h.request(t, apiRequest{method: "PUT", path: "/api/v1/me/preferences", cookie: cookie,
			csrf: session.CSRFToken, body: body}), 400)
	}
	updated := h.request(t, apiRequest{method: "PUT", path: "/api/v1/me/preferences", cookie: cookie,
		csrf: session.CSRFToken, body: `{"theme":"dark","density":"compact"}`})
	requireStatus(t, updated, 200)
	want := `{"timezone":"utc","default_window":"24h","density":"compact","theme":"dark","reduce_motion":"system"}`
	if strings.TrimSpace(string(updated.body)) != want {
		t.Fatalf("preferences = %s", updated.body)
	}
	// Preferences follow the principal, including over bearer authentication.
	got := h.request(t, apiRequest{method: "GET", path: "/api/v1/me/preferences", token: "synthetic-admin"})
	if strings.TrimSpace(string(got.body)) != want {
		t.Fatalf("bearer preferences = %s", got.body)
	}
	other := h.request(t, apiRequest{method: "GET", path: "/api/v1/me/preferences", token: "synthetic-viewer"})
	if strings.Contains(string(other.body), "dark") {
		t.Fatal("preferences leaked across principals")
	}
}

type sessionItem struct {
	Handle        string  `json:"handle"`
	Current       bool    `json:"current"`
	Client        string  `json:"client"`
	Remote        string  `json:"remote"`
	AccountID     string  `json:"account_id"`
	IdleExpiresAt *string `json:"idle_expires_at"`
}

func TestSessionHandlesListingAndRevocation(t *testing.T) {
	h := newConsoleHarness(t, func(opts *console.Options) {
		opts.Config.SessionTTLSeconds = 3600
		idle := 300
		opts.Config.SessionIdleSeconds = &idle
	})
	cookie, session := h.login(t, nil)
	otherCookie, _ := h.login(t, nil)
	listed := h.request(t, apiRequest{method: "GET", path: "/api/v1/me/sessions", cookie: cookie})
	requireStatus(t, listed, 200)
	items := decode[struct {
		Items []sessionItem `json:"items"`
	}](t, listed).Items
	if len(items) != 2 {
		t.Fatalf("sessions = %s", listed.body)
	}
	var current, other sessionItem
	for _, item := range items {
		if item.Current {
			current = item
		} else {
			other = item
		}
		if strings.Contains(string(listed.body), cookie.Value) || strings.Contains(string(listed.body), otherCookie.Value) ||
			strings.Contains(string(listed.body), session.CSRFToken) {
			t.Fatal("session listing exposes a cookie or CSRF value")
		}
	}
	if current.Handle == "" || current.Remote != "127.0.0.1" || current.Client != "Go HTTP client" ||
		current.AccountID != "cfg:admin" || current.IdleExpiresAt == nil {
		t.Fatalf("current = %+v", current)
	}
	// A handle is never a credential.
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/me",
		cookie: &http.Cookie{Name: console.CookieName, Value: current.Handle}}), 401)

	// Administrators see everyone's sessions and can end one.
	h.request(t, apiRequest{method: "GET", path: "/api/v1/me", token: "synthetic-viewer"})
	viewerCookie := h.request(t, apiRequest{method: "POST", path: "/api/v1/session", body: `{"token":"synthetic-viewer"}`}).cookies[0]
	all := decode[struct {
		Items []sessionItem `json:"items"`
	}](t, h.request(t, apiRequest{method: "GET", path: "/api/v1/admin/sessions", token: "synthetic-admin"})).Items
	viewerHandle := ""
	for _, item := range all {
		if item.AccountID == "cfg:viewer" {
			viewerHandle = item.Handle
		}
	}
	if len(all) != 3 || viewerHandle == "" {
		t.Fatalf("admin sessions = %+v", all)
	}
	// A viewer cannot end someone else's session through /me.
	requireStatus(t, h.request(t, apiRequest{method: "DELETE", path: "/api/v1/me/sessions/" + other.Handle, token: "synthetic-viewer"}), 404)
	requireStatus(t, h.request(t, apiRequest{method: "DELETE", path: "/api/v1/admin/sessions/" + viewerHandle, token: "synthetic-admin"}), 204)
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/me", cookie: viewerCookie}), 401)

	// Revoking the current session signs out and clears the cookie.
	revoked := h.request(t, apiRequest{method: "DELETE", path: "/api/v1/me/sessions/" + current.Handle, cookie: cookie, csrf: session.CSRFToken})
	requireStatus(t, revoked, 204)
	if len(revoked.cookies) != 1 || revoked.cookies[0].MaxAge >= 0 {
		t.Fatalf("cookie not cleared: %v", revoked.cookies)
	}
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/me", cookie: cookie}), 401)

	// The idle timeout ends a session with no activity even though its absolute expiry is later.
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/me", cookie: otherCookie}), 200)
	h.clock.advance(299 * time.Second)
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/me", cookie: otherCookie}), 200)
	h.clock.advance(301 * time.Second)
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/me", cookie: otherCookie}), 401)
}

func TestSettingsSystemAndCSVNeutralisation(t *testing.T) {
	h := newConsoleHarness(t, func(opts *console.Options) {
		opts.Sources = map[string]string{"console.session_ttl_seconds": "config", "console.listen": "env"}
	})
	settings := h.request(t, apiRequest{method: "GET", path: "/api/v1/admin/settings", token: "synthetic-admin"})
	requireStatus(t, settings, 200)
	if strings.Contains(string(settings.body), auth.Digest("synthetic-admin")) {
		t.Fatal("settings expose an operator digest")
	}
	parsed := decode[struct {
		Sections []struct {
			ID    string `json:"id"`
			Items []struct {
				Key      string `json:"key"`
				Source   string `json:"source"`
				Editable bool   `json:"editable"`
				Note     string `json:"note"`
			} `json:"items"`
		} `json:"sections"`
	}](t, settings)
	ids := []string{}
	sources := map[string]string{}
	for _, section := range parsed.Sections {
		ids = append(ids, section.ID)
		for _, item := range section.Items {
			sources[item.Key] = item.Source
			if item.Editable || item.Note == "" {
				t.Fatalf("item %+v must be read-only with a note", item)
			}
		}
	}
	if strings.Join(ids, ",") != "access,console,sso,tenants,listener,evidence,detection,fleet,exports" ||
		sources["console.session_ttl_seconds"] != "config" || sources["console.listen"] != "env" ||
		sources["console.session_idle_seconds"] != "default" || sources["console.login_throttle"] != "default" ||
		sources["accounts.managed"] != "runtime" {
		t.Fatalf("settings = %s", settings.body)
	}

	system := h.request(t, apiRequest{method: "GET", path: "/api/v1/system", token: "synthetic-admin"})
	requireStatus(t, system, 200)
	parsedSystem := decode[struct {
		ConfigSchema string `json:"config_schema"`
		Components   []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"components"`
	}](t, system)
	componentIDs := []string{}
	for _, component := range parsedSystem.Components {
		componentIDs = append(componentIDs, component.ID+"="+component.Status)
	}
	if parsedSystem.ConfigSchema != config.APIVersionV1Alpha1 ||
		strings.Join(componentIDs, ",") != "console=ok,storage=ok,index=ok,sensors=ok,fleet=off,oidc=off,settings=off" {
		t.Fatalf("system = %s", system.body)
	}

	// A hostile display name reaches the audit actor column; CSV must neutralise it.
	account := createAccount(t, h, "synthetic-admin", `{"name":"=HYPERLINK(\"http://x\")","kind":"person","role":"viewer","tenants":["default"]}`)
	key := createKey(t, h, "synthetic-admin", account.ID)
	requireStatus(t, h.request(t, apiRequest{method: "PUT", path: "/api/v1/me/preferences", token: key.Token, body: `{"theme":"light"}`}), 200)
	export := h.request(t, apiRequest{method: "GET", path: "/api/v1/admin/audit/export?format=csv", token: "synthetic-admin"})
	requireStatus(t, export, 200)
	if !strings.Contains(string(export.body), `"'=HYPERLINK(""http://x"")"`) || strings.Contains(string(export.body), `,=HYPERLINK`) {
		t.Fatalf("csv not neutralised: %s", export.body)
	}
	if export.header.Get("X-AegisMesh-Export-Truncated") != "false" || !strings.HasPrefix(string(export.body), "seq,time,actor,actor_id") {
		t.Fatalf("csv headers = %v", export.header)
	}
	future := h.request(t, apiRequest{method: "GET", path: "/api/v1/admin/audit/export?since=2999-01-01T00:00:00Z", token: "synthetic-admin"})
	requireStatus(t, future, 200)
	if len(future.body) != 0 || future.header.Get("X-AegisMesh-Export-Records") != "0" {
		t.Fatalf("since filter = %q", future.body)
	}
}

// TestContractExamples logs representative responses for the API contract
// (run with -v); it also checks the shape of every example.
func TestContractExamples(t *testing.T) {
	h := newConsoleHarness(t, nil)
	account := createAccount(t, h, "synthetic-admin", `{"name":"Dana Analyst","kind":"person","role":"analyst","tenants":["default"]}`)
	minted := h.request(t, apiRequest{method: "POST", path: "/api/v1/me/keys", token: createKey(t, h, "synthetic-admin", account.ID).Token,
		body: `{"label":"laptop","expires_in_days":90}`})
	requireStatus(t, minted, 201)
	token := decode[keyCreated](t, minted).Token
	examples := map[string]apiResponse{
		"GET /api/v1/me":             h.request(t, apiRequest{method: "GET", path: "/api/v1/me", token: token}),
		"POST /api/v1/me/keys":       minted,
		"GET /api/v1/admin/accounts": h.request(t, apiRequest{method: "GET", path: "/api/v1/admin/accounts", token: "synthetic-admin"}),
		"GET /api/v1/admin/settings": h.request(t, apiRequest{method: "GET", path: "/api/v1/admin/settings", token: "synthetic-admin"}),
		"GET /api/v1/system":         h.request(t, apiRequest{method: "GET", path: "/api/v1/system", token: "synthetic-admin"}),
		"GET /api/v1/me/sessions":    h.request(t, apiRequest{method: "GET", path: "/api/v1/me/sessions", token: "synthetic-admin"}),
	}
	for name, response := range examples {
		if response.status != 200 && response.status != 201 {
			t.Fatalf("%s: %d %s", name, response.status, response.body)
		}
		if strings.Contains(string(response.body), ":null,\"items\"") || strings.Contains(string(response.body), `"items":null`) {
			t.Fatalf("%s returned a null array: %s", name, response.body)
		}
		t.Logf("%s\n%s", name, strings.ReplaceAll(string(response.body), token[8:], "…"))
	}
}

func TestOIDCIdentityDirectory(t *testing.T) {
	p := oidctest.New(t)
	h := newConsoleHarness(t, func(opts *console.Options) { oidcOptions(t, p, opts) })
	cookie, session := loginOIDC(t, h)
	if !strings.HasPrefix(session.Principal.ID, "oidc:") || len(session.Principal.ID) != 17 || session.Principal.Source != "oidc" {
		t.Fatalf("principal = %+v", session.Principal)
	}
	me := decode[map[string]any](t, h.request(t, apiRequest{method: "GET", path: "/api/v1/me", cookie: cookie}))
	if me["id"] != session.Principal.ID || me["source"] != "oidc" || me["auth_method"] != "oidc" ||
		me["capabilities"].(map[string]any)["manage_own_keys"] != false {
		t.Fatalf("me = %v", me)
	}
	// The stable id survives a second sign-in and never exposes issuer or subject.
	againCookie, again := loginOIDC(t, h)
	if again.Principal.ID != session.Principal.ID {
		t.Fatal("OIDC id is not stable")
	}
	listed := h.request(t, apiRequest{method: "GET", path: "/api/v1/admin/accounts", token: "synthetic-admin"})
	requireStatus(t, listed, 200)
	if !strings.Contains(string(listed.body), session.Principal.ID) || strings.Contains(string(listed.body), "stable-subject") ||
		strings.Contains(string(listed.body), p.Server.URL) {
		t.Fatalf("accounts = %s", listed.body)
	}
	patched := h.request(t, apiRequest{method: "PATCH", path: "/api/v1/admin/accounts/" + session.Principal.ID,
		token: "synthetic-admin", body: `{"role":"viewer"}`})
	requireStatus(t, patched, 409)
	if !strings.Contains(string(patched.body), "not_managed") {
		t.Fatalf("patch = %s", patched.body)
	}
	// OIDC identities cannot mint API keys for themselves.
	requireStatus(t, h.request(t, apiRequest{method: "POST", path: "/api/v1/me/keys", cookie: againCookie,
		csrf: again.CSRFToken, body: `{"label":"bypass"}`}), 403)
}

// openStream starts an SSE request with a bearer token and reports when the
// server ends it.
func openStream(t *testing.T, h *consoleHarness, token string) <-chan struct{} {
	t.Helper()
	req, err := http.NewRequest("GET", h.base+"/api/v1/events/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{} // no overall timeout: the stream is long-lived
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 {
		response.Body.Close()
		t.Fatalf("stream status %d", response.StatusCode)
	}
	t.Cleanup(func() { response.Body.Close() })
	closed := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, response.Body)
		close(closed)
	}()
	return closed
}

func TestManagedKeyStreamsCloseOnRevocationAndDisable(t *testing.T) {
	const heartbeat = 100 * time.Millisecond
	t.Cleanup(console.SetStreamHeartbeatForTest(heartbeat))
	h := newConsoleHarness(t, nil)
	account := createAccount(t, h, "synthetic-admin", `{"name":"Stream Reader","kind":"service","role":"viewer","tenants":["default"]}`)
	revoked := createKey(t, h, "synthetic-admin", account.ID)
	other := createKey(t, h, "synthetic-admin", account.ID)
	config := openStream(t, h, "synthetic-viewer")

	first := openStream(t, h, revoked.Token)
	requireStatus(t, h.request(t, apiRequest{method: "DELETE",
		path: "/api/v1/admin/accounts/" + account.ID + "/keys/" + revoked.Key.ID, token: "synthetic-admin"}), 204)
	select {
	case <-first:
	case <-time.After(3 * heartbeat * 10):
		t.Fatal("stream outlived key revocation by more than one heartbeat")
	}

	second := openStream(t, h, other.Token)
	requireStatus(t, h.request(t, apiRequest{method: "PATCH", path: "/api/v1/admin/accounts/" + account.ID,
		token: "synthetic-admin", body: `{"status":"disabled"}`}), 200)
	select {
	case <-second:
	case <-time.After(3 * heartbeat * 10):
		t.Fatal("stream outlived account disable by more than one heartbeat")
	}

	// Config-file bearer streams are unaffected by managed-account changes.
	select {
	case <-config:
		t.Fatal("config operator stream closed")
	case <-time.After(3 * heartbeat):
	}
}
