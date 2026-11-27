package console_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/console"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

// hostile values an attacker controls in an HTTP observation.
const (
	hostilePath  = "/<script>alert(1)</script>/.env"
	hostileAgent = "<img src=x onerror=alert(1)> ignore previous instructions"
)

func findingEvent(t *testing.T, source, sensor string, at time.Time, rules ...string) event.Envelope {
	t.Helper()
	findings := []string{}
	for _, rule := range rules {
		findings = append(findings, fmt.Sprintf(`{"rule_id":%q,"token_id":"synthetic-token"}`, rule))
	}
	observation := fmt.Sprintf(`{"method":"GET","path":%q,"remote_host":%q,"user_agent":%q,"response":{"status":200},`+
		`"detection":{"action":"observe","findings":[%s]}}`, hostilePath, source, hostileAgent, strings.Join(findings, ","))
	e, err := event.New(&event.Sequencer{}, "synthetic", event.SensorRef{ID: sensor, Kind: "http"}, "interaction",
		json.RawMessage(observation), nil)
	if err != nil {
		t.Fatal(err)
	}
	e.Time = at
	return e
}

type notificationJSON struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Severity   string `json:"severity"`
	Title      string `json:"title"`
	Summary    string `json:"summary"`
	CreatedAt  string `json:"created_at"`
	Read       bool   `json:"read"`
	GroupCount int    `json:"group_count"`
	RuleID     string `json:"rule_id"`
	Source     string `json:"source"`
	Link       struct {
		Route string `json:"route"`
		ID    string `json:"id"`
	} `json:"link"`
}

type notificationList struct {
	Items      []notificationJSON `json:"items"`
	Unread     int                `json:"unread"`
	NextCursor *string            `json:"next_cursor"`
}

func inbox(t *testing.T, h *consoleHarness, token, query string) notificationList {
	t.Helper()
	response := h.request(t, apiRequest{method: "GET", path: "/api/v1/notifications" + query, token: token})
	requireStatus(t, response, 200)
	return decode[notificationList](t, response)
}

func TestNotificationsDeriveGroupAndNeverInterpolate(t *testing.T) {
	var index *evidenceindex.Index
	h := newConsoleHarness(t, func(opts *console.Options) { index = opts.Index })
	base := time.Now().UTC().Add(-30 * time.Minute)
	for i := range 3 {
		index.Add(findingEvent(t, "203.0.113.7", "web", base.Add(time.Duration(i)*time.Minute), "HT-001"))
	}
	index.Add(findingEvent(t, "198.51.100.4", "web", base, "HT-001"))
	index.Add(findingEvent(t, "203.0.113.7", "web", base, "AGT-001"))
	h.server.DeriveNotificationsForTest()
	h.server.DeriveNotificationsForTest() // a second pass derives nothing new

	raw := h.request(t, apiRequest{method: "GET", path: "/api/v1/notifications?limit=200", token: "synthetic-viewer"})
	requireStatus(t, raw, 200)
	for _, hostile := range []string{"<script", "onerror", "ignore previous", ".env", "<img"} {
		if strings.Contains(string(raw.body), hostile) {
			t.Fatalf("attacker text %q reached the inbox: %s", hostile, raw.body)
		}
	}
	replays := inbox(t, h, "synthetic-viewer", "?kind=honeytoken_replay")
	if len(replays.Items) != 2 {
		t.Fatalf("replays = %+v", replays.Items)
	}
	grouped := replays.Items[0]
	if grouped.Source != "203.0.113.7" {
		grouped = replays.Items[1]
	}
	if grouped.GroupCount != 3 || grouped.Severity != "critical" || grouped.Title != "Planted decoy credential seen inbound" ||
		grouped.Link.Route != "event" || len(grouped.Link.ID) != 32 || grouped.RuleID != "HT-001" ||
		grouped.Summary != "HT-001 matched 3 observations from source 203.0.113.7 on sensor web. The marker is operator-owned; its use is an observation, not proof of who used it." {
		t.Fatalf("grouped = %+v", grouped)
	}
	canary := inbox(t, h, "synthetic-viewer", "?kind=agent_canary")
	if len(canary.Items) != 1 || canary.Items[0].Severity != "high" {
		t.Fatalf("canary = %+v", canary.Items)
	}

	// Read state: mark one read, then all.
	before := inbox(t, h, "synthetic-viewer", "").Unread
	read := h.request(t, apiRequest{method: "POST", path: "/api/v1/notifications/read", token: "synthetic-viewer",
		body: `{"ids":["` + grouped.ID + `"]}`})
	requireStatus(t, read, 200)
	if got := decode[map[string]int](t, read)["unread"]; got != before-1 {
		t.Fatalf("unread after one read = %d; before %d", got, before)
	}
	for _, item := range inbox(t, h, "synthetic-viewer", "?unread=1").Items {
		if item.ID == grouped.ID {
			t.Fatal("read item listed as unread")
		}
	}
	if got := inbox(t, h, "synthetic-admin", "").Unread; got != before {
		t.Fatalf("read state leaked to another principal: %d", got)
	}
	for _, body := range []string{`{}`, `{"ids":[]}`, `{"ids":["x"]}`, `{"all":true,"ids":["ntf_0000000000000000"]}`,
		`{"all":true,"before":"yesterday"}`, `{"all":false}`} {
		requireStatus(t, h.request(t, apiRequest{method: "POST", path: "/api/v1/notifications/read", token: "synthetic-viewer", body: body}), 400)
	}
	all := h.request(t, apiRequest{method: "POST", path: "/api/v1/notifications/read", token: "synthetic-viewer", body: `{"all":true}`})
	if requireStatus(t, all, 200); decode[map[string]int](t, all)["unread"] != 0 {
		t.Fatalf("mark all = %s", all.body)
	}
	for _, query := range []string{"?kind=nope", "?severity=low", "?unread=2", "?cursor=zz", "?limit=0", "?limit=201", "?other=1"} {
		requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/notifications" + query, token: "synthetic-viewer"}), 400)
	}
	records := h.request(t, apiRequest{method: "GET", path: "/api/v1/audit?action=notification.read", token: "synthetic-admin"})
	if !strings.Contains(string(records.body), "ids=1") || !strings.Contains(string(records.body), "all before=") {
		t.Fatalf("audit = %s", records.body)
	}
}

func TestNotificationRateLimitBoundsInbox(t *testing.T) {
	var index *evidenceindex.Index
	h := newConsoleHarness(t, func(opts *console.Options) { index = opts.Index })
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Minute)
	// A scan from 150 sources inside one minute.
	for i := range 150 {
		index.Add(findingEvent(t, fmt.Sprintf("198.51.100.%d", i), "web", base.Add(time.Duration(i)*100*time.Millisecond), "HT-001"))
	}
	h.server.DeriveNotificationsForTest()
	items := inbox(t, h, "synthetic-viewer", "?kind=honeytoken_replay&limit=200").Items
	overflow := 0
	for _, item := range items {
		if item.Title == "More notifications than the inbox limit" {
			overflow++
			if item.GroupCount != 130 || !strings.HasPrefix(item.Summary, "130 decoy credential notifications were folded") {
				t.Fatalf("overflow = %+v", item)
			}
		}
	}
	if len(items) != 21 || overflow != 1 {
		t.Fatalf("items = %d overflow = %d", len(items), overflow)
	}
}

func TestNotificationPermissionsAndAccountSecurity(t *testing.T) {
	var index *evidenceindex.Index
	h := newConsoleHarness(t, func(opts *console.Options) { index = opts.Index })
	index.Add(findingEvent(t, "203.0.113.7", "web", time.Now().UTC().Add(-time.Minute), "HT-001"))
	h.server.DeriveNotificationsForTest()

	role := createRole(t, h, "synthetic-admin", `{"name":"Posture only","permissions":["analysis.read"]}`)
	account, token := principalWithRole(t, h, "Posture Reader", "person", role.ID)
	// Notifications need only authentication; evidence items need evidence.read.
	if items := inbox(t, h, token, "?kind=honeytoken_replay").Items; len(items) != 0 {
		t.Fatalf("evidence item visible without evidence.read: %+v", items)
	}
	if items := inbox(t, h, "synthetic-viewer", "?kind=honeytoken_replay").Items; len(items) != 1 {
		t.Fatalf("viewer items = %+v", items)
	}
	// The key minted by an administrator notifies the affected principal only.
	mine := inbox(t, h, token, "?kind=account_security").Items
	if len(mine) != 1 || mine[0].Title != "API key created for your account" || !strings.HasPrefix(mine[0].Summary, "An administrator") ||
		mine[0].Link.Route != "settings" || mine[0].Link.ID != "keys" {
		t.Fatalf("account items = %+v", mine)
	}
	for _, other := range []string{"synthetic-admin", "synthetic-viewer"} {
		if items := inbox(t, h, other, "?kind=account_security").Items; len(items) != 0 {
			t.Fatalf("%s sees another principal's account_security: %+v", other, items)
		}
	}
	requireStatus(t, h.request(t, apiRequest{method: "PATCH", path: "/api/v1/admin/accounts/" + account.ID,
		token: "synthetic-admin", body: `{"role":"viewer"}`}), 200)
	second := createKey(t, h, "synthetic-admin", account.ID)
	requireStatus(t, h.request(t, apiRequest{method: "DELETE", path: "/api/v1/admin/accounts/" + account.ID + "/keys/" + second.Key.ID,
		token: "synthetic-admin"}), 204)
	titles := []string{}
	for _, item := range inbox(t, h, token, "?kind=account_security").Items {
		titles = append(titles, item.Title)
	}
	if strings.Join(titles, "|") != "API key revoked on your account|Your role was changed|API key created for your account" {
		t.Fatalf("account titles = %v", titles)
	}

	// A session ended by an administrator notifies its owner; ending one's own does not.
	_, _ = loginWith(t, h, "synthetic-viewer")
	sessions := decode[struct {
		Items []struct {
			Handle    string `json:"handle"`
			AccountID string `json:"account_id"`
		} `json:"items"`
	}](t, h.request(t, apiRequest{method: "GET", path: "/api/v1/admin/sessions", token: "synthetic-admin"}))
	handle := ""
	for _, item := range sessions.Items {
		if item.AccountID == "cfg:viewer" {
			handle = item.Handle
		}
	}
	if handle == "" {
		t.Fatalf("viewer session not listed: %+v", sessions)
	}
	requireStatus(t, h.request(t, apiRequest{method: "DELETE", path: "/api/v1/admin/sessions/" + handle, token: "synthetic-admin"}), 204)
	revoked := inbox(t, h, "synthetic-viewer", "?kind=account_security").Items
	if len(revoked) != 1 || revoked[0].Title != "One of your sessions was ended" || revoked[0].Severity != "high" {
		t.Fatalf("session revoke items = %+v", revoked)
	}
}

func TestNotificationPreferences(t *testing.T) {
	var index *evidenceindex.Index
	h := newConsoleHarness(t, func(opts *console.Options) { index = opts.Index })
	index.Add(findingEvent(t, "203.0.113.7", "web", time.Now().UTC().Add(-time.Minute), "AGT-001"))
	index.Add(findingEvent(t, "203.0.113.8", "web", time.Now().UTC().Add(-time.Minute), "HT-001"))
	h.server.DeriveNotificationsForTest()
	path := "/api/v1/me/notification-preferences"
	defaults := decode[map[string]any](t, h.request(t, apiRequest{method: "GET", path: path, token: "synthetic-viewer"}))
	if defaults["min_severity"] != "info" || len(defaults["kinds"].(map[string]any)) != 7 {
		t.Fatalf("defaults = %v", defaults)
	}
	put := h.request(t, apiRequest{method: "PUT", path: path, token: "synthetic-viewer",
		body: `{"kinds":{"agent_canary":false},"min_severity":"high"}`})
	requireStatus(t, put, 200)
	merged := decode[map[string]any](t, put)
	if merged["kinds"].(map[string]any)["agent_canary"] != false || merged["kinds"].(map[string]any)["honeytoken_replay"] != true {
		t.Fatalf("merge = %s", put.body)
	}
	if items := inbox(t, h, "synthetic-viewer", "?kind=agent_canary").Items; len(items) != 0 {
		t.Fatal("disabled kind listed")
	}
	if items := inbox(t, h, "synthetic-viewer", "?kind=honeytoken_replay").Items; len(items) != 1 {
		t.Fatal("enabled kind hidden")
	}
	for _, body := range []string{`{"kinds":{"nope":true}}`, `{"kinds":{"account_security":false}}`, `{"min_severity":"low"}`, `{"extra":1}`} {
		requireStatus(t, h.request(t, apiRequest{method: "PUT", path: path, token: "synthetic-viewer", body: body}), 400)
	}
	records := h.request(t, apiRequest{method: "GET", path: "/api/v1/audit?action=notification.preferences", token: "synthetic-admin"})
	if !strings.Contains(string(records.body), "kinds_enabled=6 min_severity=high") {
		t.Fatalf("audit = %s", records.body)
	}
}

func TestNotificationReadStateAndHighWaterAcrossRestart(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "console")
	base := time.Now().UTC().Add(-2 * time.Hour)
	retained := []event.Envelope{}
	for i := range 4 {
		retained = append(retained, findingEvent(t, fmt.Sprintf("203.0.113.%d", i+1), "web", base.Add(time.Duration(i)*time.Minute), "HT-001"))
	}
	first := newConsoleHarness(t, func(opts *console.Options) {
		opts.StateDir = stateDir
		for _, e := range retained {
			opts.Index.Add(e)
		}
	})
	first.server.DeriveNotificationsForTest()
	if got := len(inbox(t, first, "synthetic-admin", "?kind=honeytoken_replay").Items); got != 4 {
		t.Fatalf("first run items = %d", got)
	}
	requireStatus(t, first.request(t, apiRequest{method: "POST", path: "/api/v1/notifications/read", token: "synthetic-admin", body: `{"all":true}`}), 200)
	first.close(t)

	// The restarted runtime backfills the same retained evidence plus one new observation.
	second := newConsoleHarness(t, func(opts *console.Options) {
		opts.StateDir = stateDir
		for _, e := range retained {
			opts.Index.Add(e)
		}
		// Newer than everything the first run derived (including the harness's own event).
		opts.Index.Add(findingEvent(t, "198.51.100.9", "web", time.Now().UTC(), "HT-001"))
	})
	second.server.DeriveNotificationsForTest()
	items := inbox(t, second, "synthetic-admin", "?kind=honeytoken_replay")
	if len(items.Items) != 5 {
		t.Fatalf("items after restart = %d; old observations re-derived or new one missed: %+v", len(items.Items), items.Items)
	}
	unread := inbox(t, second, "synthetic-admin", "?kind=honeytoken_replay&unread=1").Items
	if len(unread) != 1 || unread[0].Source != "198.51.100.9" {
		t.Fatalf("unread after restart = %+v", unread)
	}
	if got := len(inbox(t, second, "synthetic-viewer", "?kind=honeytoken_replay&unread=1").Items); got != 5 {
		t.Fatalf("viewer unread = %d", got)
	}
}

func TestNotificationsNeverCrossTenants(t *testing.T) {
	var local, bravo *evidenceindex.Index
	h := newConsoleHarness(t, func(opts *console.Options) {
		opts.Config.Tenants = []string{"default", "bravo"}
		opts.Config.Operators[0].Tenants = []string{"bravo"} // synthetic-viewer
		local = opts.Index
		var err error
		bravo, err = evidenceindex.New(1000, opts.Meter)
		if err != nil {
			t.Fatal(err)
		}
		opts.TenantIndexes = map[string]*evidenceindex.Index{"bravo": bravo}
	})
	now := time.Now().UTC().Add(-time.Minute)
	local.Add(findingEvent(t, "203.0.113.1", "web", now, "HT-001"))
	bravo.Add(findingEvent(t, "198.51.100.2", "web", now, "HT-001"))
	h.server.DeriveNotificationsForTest()
	for token, want := range map[string]string{"synthetic-viewer": "198.51.100.2", "synthetic-admin": "203.0.113.1"} {
		items := inbox(t, h, token, "?kind=honeytoken_replay").Items
		if len(items) != 1 || items[0].Source != want {
			t.Fatalf("%s sees %+v; want only %s", token, items, want)
		}
	}
}

type sseFrame struct{ kind, data string }

func openNotificationStream(t *testing.T, h *consoleHarness, token string) (<-chan sseFrame, <-chan struct{}) {
	t.Helper()
	req, err := http.NewRequest("GET", h.base+"/api/v1/notifications/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	response, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || response.Header.Get("Content-Type") != "text/event-stream" {
		response.Body.Close()
		t.Fatalf("stream status %d", response.StatusCode)
	}
	t.Cleanup(func() { response.Body.Close() })
	frames, closed := make(chan sseFrame, 64), make(chan struct{})
	go func() {
		defer close(closed)
		scanner := bufio.NewScanner(response.Body)
		kind := ""
		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				kind = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				select {
				case frames <- sseFrame{kind, strings.TrimPrefix(line, "data: ")}:
				default:
				}
			}
		}
	}()
	return frames, closed
}

// next returns the next frame of kind, skipping others, or fails after wait.
func next(t *testing.T, frames <-chan sseFrame, kind string, wait time.Duration) (sseFrame, bool) {
	t.Helper()
	deadline := time.After(wait)
	for {
		select {
		case frame := <-frames:
			if frame.kind == kind {
				return frame, true
			}
		case <-deadline:
			return sseFrame{}, false
		}
	}
}

func TestNotificationStreamDeliveryAndClosure(t *testing.T) {
	const heartbeat = 100 * time.Millisecond
	t.Cleanup(console.SetStreamHeartbeatForTest(heartbeat))
	var index *evidenceindex.Index
	h := newConsoleHarness(t, func(opts *console.Options) { index = opts.Index })
	role := createRole(t, h, "synthetic-admin", `{"name":"Watcher","permissions":["evidence.read"]}`)
	account, token := principalWithRole(t, h, "Watcher One", "service", role.ID)
	frames, closed := openNotificationStream(t, h, token)
	if frame, ok := next(t, frames, "unread", 2*time.Second); !ok || !strings.HasPrefix(frame.data, `{"unread":`) {
		t.Fatal("no initial unread frame")
	}

	index.Add(findingEvent(t, "203.0.113.7", "web", time.Now().UTC(), "HT-001"))
	h.server.DeriveNotificationsForTest()
	frame, ok := next(t, frames, "notification", 2*time.Second)
	if !ok {
		t.Fatal("notification not delivered")
	}
	var delivered map[string]any
	if err := json.Unmarshal([]byte(frame.data), &delivered); err != nil {
		t.Fatal(err)
	}
	if delivered["kind"] != "honeytoken_replay" || delivered["title"] != "Planted decoy credential seen inbound" ||
		delivered["id"] == nil || delivered["created_at"] == nil || strings.Contains(frame.data, "<script") {
		t.Fatalf("frame = %s", frame.data)
	}
	if _, ok := next(t, frames, "unread", time.Second); !ok {
		t.Fatal("unread update missing")
	}

	// Removing evidence.read stops delivery of evidence items at once.
	requireStatus(t, h.request(t, apiRequest{method: "PATCH", path: "/api/v1/admin/roles/" + role.ID, token: "synthetic-admin",
		body: `{"permissions":["analysis.read"]}`}), 200)
	index.Add(findingEvent(t, "198.51.100.8", "web", time.Now().UTC(), "HT-001"))
	h.server.DeriveNotificationsForTest()
	if frame, ok := next(t, frames, "notification", 5*heartbeat); ok && strings.Contains(frame.data, "honeytoken") {
		t.Fatalf("evidence notification delivered after permission loss: %s", frame.data)
	}
	if _, ok := next(t, frames, "heartbeat", 5*heartbeat); !ok {
		t.Fatal("stream stopped heartbeating")
	}
	// Revoking the key ends the stream at the next heartbeat.
	keys := decode[struct {
		Keys []struct {
			ID string `json:"id"`
		} `json:"keys"`
	}](t, h.request(t, apiRequest{method: "GET", path: "/api/v1/admin/accounts/" + account.ID, token: "synthetic-admin"}))
	for _, key := range keys.Keys {
		requireStatus(t, h.request(t, apiRequest{method: "DELETE", path: "/api/v1/admin/accounts/" + account.ID + "/keys/" + key.ID,
			token: "synthetic-admin"}), 204)
	}
	select {
	case <-closed:
	case <-time.After(30 * heartbeat):
		t.Fatal("notification stream outlived key revocation")
	}
}
