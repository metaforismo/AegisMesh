package console_test

import (
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/console"
)

type activityJSON struct {
	ActorID   string `json:"actor_id"`
	ActorName string `json:"actor_name"`
	Kind      string `json:"kind"`
	Detail    string `json:"detail"`
}

type workspaceJSON struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Origin *struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	} `json:"origin"`
	Assignee     *string  `json:"assignee"`
	AssigneeName *string  `json:"assignee_name"`
	EventIDs     []string `json:"event_ids"`
	Notes        []struct {
		Text string `json:"text"`
	} `json:"notes"`
	Events []struct {
		ID     string `json:"id"`
		Source string `json:"source"`
	} `json:"events"`
	Activity []activityJSON `json:"activity"`
	Summary  struct {
		Sources       int      `json:"sources"`
		Sensors       []string `json:"sensors"`
		FirstSeen     *string  `json:"first_seen"`
		LastSeen      *string  `json:"last_seen"`
		MaxSeverity   string   `json:"max_severity"`
		RuleIDs       []string `json:"rule_ids"`
		IndexedEvents int      `json:"indexed_events"`
		MissingEvents int      `json:"missing_events"`
	} `json:"summary"`
}

func activityKinds(activity []activityJSON) string {
	kinds := []string{}
	for _, entry := range activity {
		kinds = append(kinds, entry.Kind)
	}
	return strings.Join(kinds, ",")
}

func campaignHarness(t *testing.T) (*consoleHarness, string) {
	t.Helper()
	base := time.Now().UTC().Add(-20 * time.Minute).Truncate(time.Second)
	h := newConsoleHarness(t, func(opts *console.Options) {
		addSteps(t, opts.Index, base, probe("192.0.2.10", 0, 8))
		addSteps(t, opts.Index, base, probe("198.51.100.20", 2*time.Minute, 0))
	})
	list := decode[struct {
		Items []struct {
			ID         string `json:"id"`
			EventCount int    `json:"event_count"`
		} `json:"items"`
	}](t, h.request(t, apiRequest{method: "GET", path: "/api/v1/campaigns", token: "synthetic-viewer"}))
	if len(list.Items) != 1 || list.Items[0].EventCount != 14 {
		t.Fatalf("campaigns = %+v", list)
	}
	return h, list.Items[0].ID
}

func TestCampaignToInvestigation(t *testing.T) {
	h, id := campaignHarness(t)
	detail := decode[struct {
		EventCount     int      `json:"event_count"`
		EventIDsSample []string `json:"event_ids_sample"`
	}](t, h.request(t, apiRequest{method: "GET", path: "/api/v1/campaigns/" + id, token: "synthetic-viewer"}))
	if detail.EventCount != 14 || len(detail.EventIDsSample) != 14 {
		t.Fatalf("campaign detail sample = %+v", detail)
	}

	path := "/api/v1/campaigns/" + id + "/investigation"
	for _, body := range []string{`{"max_events":0}`, `{"max_events":201}`, `{"priority":"urgent"}`, `{"title":""}`, `{"other":1}`} {
		requireStatus(t, h.request(t, apiRequest{method: "POST", path: path, token: "synthetic-analyst", body: body}), 400)
	}
	requireStatus(t, h.request(t, apiRequest{method: "POST", path: path, token: "synthetic-viewer", body: `{}`}), 403)
	requireStatus(t, h.request(t, apiRequest{method: "POST", path: "/api/v1/campaigns/cmp_000000000000/investigation",
		token: "synthetic-analyst", body: `{}`}), 404)
	requireStatus(t, h.request(t, apiRequest{method: "POST", path: "/api/v1/campaigns/not-an-id/investigation",
		token: "synthetic-analyst", body: `{}`}), 400)

	created := h.request(t, apiRequest{method: "POST", path: path, token: "synthetic-analyst", body: `{"max_events":3,"priority":"high"}`})
	requireStatus(t, created, 201)
	got := decode[workspaceJSON](t, created)
	if got.Origin == nil || got.Origin.Kind != "campaign" || got.Origin.ID != id || len(got.EventIDs) != 3 || len(got.Events) != 3 {
		t.Fatalf("created = %s", created.body)
	}
	// Newest per session first: both member sessions are represented in three events.
	sources := map[string]bool{}
	for _, e := range got.Events {
		sources[e.Source] = true
	}
	if len(sources) != 2 || got.Summary.Sources != 2 || got.Summary.IndexedEvents != 3 || got.Summary.FirstSeen == nil {
		t.Fatalf("attachment not spread across sessions: %s", created.body)
	}
	note := got.Notes[0].Text
	if len(got.Notes) != 1 || !strings.HasPrefix(note, "Opened from campaign "+id+". Basis: same_step_sequence, same_client_family.") ||
		!strings.Contains(note, "3 attached, newest per session first, limit 3") || !strings.Contains(note, "does not prove a shared operator") ||
		strings.Contains(note, "/v1/models") || strings.Contains(note, "OpenAI") {
		t.Fatalf("note = %q", note)
	}
	if activityKinds(got.Activity) != "created,attach,note" || got.Activity[0].ActorID != "cfg:analyst" ||
		got.Activity[0].Detail != "created from campaign "+id || got.Activity[1].Detail != "attached 3 events from campaign "+id {
		t.Fatalf("activity = %+v", got.Activity)
	}
	// Double submission creates a second investigation (documented; the console disables the button).
	requireStatus(t, h.request(t, apiRequest{method: "POST", path: path, token: "synthetic-analyst", body: `{}`}), 201)
	records := h.request(t, apiRequest{method: "GET", path: "/api/v1/audit?action=investigation.create", token: "synthetic-admin"})
	if strings.Count(string(records.body), `"outcome":"ok","remote":"127.0.0.1","detail":"origin=campaign:`+id) != 2 ||
		!strings.Contains(string(records.body), "events=3") {
		t.Fatalf("audit = %s", records.body)
	}

	// Session → investigation uses the same body and bounds.
	sessions := decode[struct {
		Items []struct {
			ID     string `json:"id"`
			Source string `json:"source"`
		} `json:"sessions"`
	}](t, h.request(t, apiRequest{method: "GET", path: "/api/v1/sessions?window=24h&source=192.0.2.10", token: "synthetic-viewer"}))
	session := sessions.Items[0]
	fromSession := h.request(t, apiRequest{method: "POST", path: "/api/v1/sessions/" + session.ID + "/investigation",
		token: "synthetic-analyst", body: `{"title":"Probe follow-up"}`})
	requireStatus(t, fromSession, 201)
	s := decode[workspaceJSON](t, fromSession)
	if s.Origin == nil || s.Origin.Kind != "session" || s.Title != "Probe follow-up" || len(s.EventIDs) == 0 ||
		!strings.HasPrefix(s.Notes[0].Text, "Opened from session "+session.ID+" (source "+session.Source+").") {
		t.Fatalf("session investigation = %s", fromSession.body)
	}
	requireStatus(t, h.request(t, apiRequest{method: "POST", path: "/api/v1/sessions/" + strings.Repeat("0", 32) + "/investigation",
		token: "synthetic-analyst", body: `{}`}), 404)

	// The campaign is announced once in the inbox.
	h.server.DeriveNotificationsForTest()
	h.server.DeriveNotificationsForTest()
	campaigns := inbox(t, h, "synthetic-viewer", "?kind=new_campaign").Items
	if len(campaigns) != 1 || campaigns[0].Link.Route != "campaign" || campaigns[0].Link.ID != id ||
		!strings.Contains(campaigns[0].Summary, "2 sessions from 2 sources") {
		t.Fatalf("new_campaign = %+v", campaigns)
	}
}

func TestAssigneeActivityAndListFilters(t *testing.T) {
	h := newConsoleHarness(t, nil)
	created := h.request(t, apiRequest{method: "POST", path: "/api/v1/investigations", token: "synthetic-analyst",
		body: `{"title":"Workspace","event_ids":["` + h.eventID + `"]}`})
	requireStatus(t, created, 201)
	id := decode[workspaceJSON](t, created).ID
	path := "/api/v1/investigations/" + id

	assignees := decode[struct {
		Assignees []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Kind string `json:"kind"`
		} `json:"assignees"`
	}](t, h.request(t, apiRequest{method: "GET", path: "/api/v1/investigations/assignees", token: "synthetic-analyst"}))
	ids := []string{}
	for _, a := range assignees.Assignees {
		ids = append(ids, a.ID)
	}
	if strings.Join(ids, ",") != "cfg:admin,cfg:analyst,cfg:viewer" {
		t.Fatalf("assignees = %v", ids)
	}
	role := createRole(t, h, "synthetic-admin", `{"name":"No cases","permissions":["evidence.read"]}`)
	noCases, _ := principalWithRole(t, h, "No Cases", "person", role.ID)

	for _, body := range []string{`{"assignee":"cfg:nobody"}`, `{"assignee":"` + noCases.ID + `"}`, `{"assignee":7}`, `{"assignee":"../x"}`} {
		requireStatus(t, h.request(t, apiRequest{method: "PATCH", path: path, token: "synthetic-analyst", body: body}), 400)
	}
	assigned := h.request(t, apiRequest{method: "PATCH", path: path, token: "synthetic-analyst", body: `{"assignee":"cfg:viewer","status":"monitoring"}`})
	requireStatus(t, assigned, 200)
	got := decode[workspaceJSON](t, assigned)
	if got.Assignee == nil || *got.Assignee != "cfg:viewer" || got.AssigneeName == nil || *got.AssigneeName != "viewer" {
		t.Fatalf("assigned = %s", assigned.body)
	}
	if activityKinds(got.Activity) != "created,status,assignee" || got.Activity[1].Detail != "open → monitoring" ||
		got.Activity[2].Detail != "assigned to viewer (cfg:viewer)" {
		t.Fatalf("activity = %+v", got.Activity)
	}
	// The assignee is notified in this tenant; the actor and others are not.
	mine := inbox(t, h, "synthetic-viewer", "?kind=assignment").Items
	if len(mine) != 1 || mine[0].Link.Route != "investigation" || mine[0].Link.ID != id || mine[0].Title != "Investigation assigned to you" {
		t.Fatalf("assignment items = %+v", mine)
	}
	if items := inbox(t, h, "synthetic-analyst", "?kind=assignment").Items; len(items) != 0 {
		t.Fatal("assignment visible to the actor")
	}

	list := func(token, query string) []map[string]any {
		t.Helper()
		response := h.request(t, apiRequest{method: "GET", path: "/api/v1/investigations" + query, token: token})
		requireStatus(t, response, 200)
		return decode[struct {
			Investigations []map[string]any `json:"investigations"`
		}](t, response).Investigations
	}
	if items := list("synthetic-viewer", "?assignee=me"); len(items) != 1 || items[0]["event_count"] != float64(1) ||
		items[0]["assignee"] != "cfg:viewer" || items[0]["activity"] != nil || items[0]["max_severity"] != "" {
		t.Fatalf("assignee=me = %+v", items)
	}
	if items := list("synthetic-analyst", "?assignee=me"); len(items) != 0 {
		t.Fatal("assignee=me leaked")
	}
	if items := list("synthetic-analyst", "?assignee=cfg:viewer&status=monitoring"); len(items) != 1 {
		t.Fatal("assignee id filter")
	}
	if items := list("synthetic-analyst", "?assignee=none"); len(items) != 0 {
		t.Fatal("assignee=none")
	}
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/investigations?assignee=bad", token: "synthetic-viewer"}), 400)

	unassigned := h.request(t, apiRequest{method: "PATCH", path: path, token: "synthetic-analyst", body: `{"assignee":null}`})
	requireStatus(t, unassigned, 200)
	got = decode[workspaceJSON](t, unassigned)
	if got.Assignee != nil || got.AssigneeName != nil || got.Activity[len(got.Activity)-1].Detail != "unassigned" {
		t.Fatalf("unassigned = %s", unassigned.body)
	}
	requireStatus(t, h.request(t, apiRequest{method: "POST", path: path + "/notes", token: "synthetic-analyst", body: `{"text":"Checked"}`}), 201)
	requireStatus(t, h.request(t, apiRequest{method: "DELETE", path: path + "/events/" + h.eventID, token: "synthetic-analyst"}), 200)
	final := decode[workspaceJSON](t, h.request(t, apiRequest{method: "GET", path: path, token: "synthetic-viewer"}))
	if activityKinds(final.Activity) != "created,status,assignee,assignee,note,detach" || final.Summary.IndexedEvents != 0 ||
		final.Summary.FirstSeen != nil || final.Summary.Sensors == nil || final.Summary.RuleIDs == nil {
		t.Fatalf("final = %+v", final)
	}
	records := string(h.request(t, apiRequest{method: "GET", path: "/api/v1/audit?action=investigation.assign", token: "synthetic-admin"}).body)
	if !strings.Contains(records, "assignee=cfg:viewer") || !strings.Contains(records, "assignee=none") || !strings.Contains(records, `"denied"`) {
		t.Fatalf("assign audit = %s", records)
	}
}

func TestPostureNotifications(t *testing.T) {
	h := newConsoleHarness(t, editingOn)
	h.server.DeriveNotificationsForTest()
	items := inbox(t, h, "synthetic-viewer", "?kind=posture_attention").Items
	found := false
	for _, item := range items {
		if item.Link.ID == "POS-007" && item.Title == "Posture check needs attention" {
			found = true
		}
	}
	if !found {
		t.Fatalf("POS-007 attention not notified: %+v", items)
	}
	h.server.DeriveNotificationsForTest()
	if again := inbox(t, h, "synthetic-viewer", "?kind=posture_attention").Items; len(again) != len(items) {
		t.Fatal("posture re-notified without a change")
	}
	until := h.clock.now().Add(72 * time.Hour).UTC().Format(time.RFC3339)
	requireStatus(t, h.request(t, apiRequest{method: "POST", path: "/api/v1/posture/POS-007/accept", token: "synthetic-admin",
		body: `{"reason":"Tokens planted next sprint","until":"` + until + `"}`}), 200)
	h.server.DeriveNotificationsForTest()
	expiring := 0
	for _, item := range inbox(t, h, "synthetic-viewer", "?kind=posture_attention").Items {
		if item.Title == "Posture acceptance expires soon" && strings.Contains(item.Summary, "POS-007 expires at "+until) {
			expiring++
		}
	}
	if expiring != 1 {
		t.Fatal("expiring acceptance not notified exactly once")
	}
	// Viewers without analysis.read do not see posture items.
	role := createRole(t, h, "synthetic-admin", `{"name":"Evidence only","permissions":["evidence.read"]}`)
	_, token := principalWithRole(t, h, "Evidence Only", "person", role.ID)
	if items := inbox(t, h, token, "?kind=posture_attention").Items; len(items) != 0 {
		t.Fatal("posture item visible without analysis.read")
	}
}
