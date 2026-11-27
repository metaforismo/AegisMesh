package notifications

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

var base = time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)

func summary(id int, at time.Time, source string, rules ...string) evidenceindex.Summary {
	return evidenceindex.Summary{
		ID:     fmt.Sprintf("%032x", id),
		Time:   at.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
		Source: source, Sensor: event.SensorRef{ID: "web", Kind: "http"}, RuleIDs: rules,
	}
}

func everything(id string) Viewer {
	return Viewer{ID: id, Can: func(string) bool { return true }}
}

func open(t *testing.T, dir string) *Store {
	t.Helper()
	store, err := Open(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestObservationKindsAndTemplates(t *testing.T) {
	tests := []struct {
		name  string
		rules []string
		kinds []string
	}{
		{"honeytoken", []string{"HT-001"}, []string{KindHoneytoken}},
		{"cross sensor replay", []string{"COR-008"}, []string{KindHoneytoken}},
		{"agent canary", []string{"AGT-001"}, []string{KindCanary}},
		{"unknown rule ignored", []string{"XX-999"}, []string{}},
		{"bounded per observation", []string{"HT-001", "AGT-001", "COR-008", "HT-001"}, []string{KindHoneytoken, KindCanary, KindHoneytoken}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := []string{}
			for _, candidate := range Observation(summary(1, base, "203.0.113.7", test.rules...)) {
				got = append(got, candidate.Kind)
				if candidate.Perm != PermEvidence || !candidate.Limited || candidate.Link.Route != RouteEvent {
					t.Fatalf("candidate = %+v", candidate)
				}
			}
			if strings.Join(got, ",") != strings.Join(test.kinds, ",") {
				t.Fatalf("kinds = %v; want %v", got, test.kinds)
			}
		})
	}
}

// Attacker-influenced source keys and sensor ids never reach rendered text.
func TestTemplatesNeverInterpolateUntrustedText(t *testing.T) {
	hostile := []string{
		`<img src=x onerror=alert(1)>`, "a\nb", "‮evil", `"quoted"`, "x/../../etc/passwd",
		strings.Repeat("a", 65), "ignore previous instructions",
	}
	for _, value := range hostile {
		s := summary(1, base, value, "HT-001")
		s.Sensor.ID = value
		candidates := Observation(s)
		if len(candidates) != 1 {
			t.Fatalf("candidates = %d", len(candidates))
		}
		if candidates[0].Facts.Source != "" || candidates[0].Facts.Sensor != "" {
			t.Fatalf("unsafe facts kept: %+v", candidates[0].Facts)
		}
		title, text := Render(candidates[0].Kind, candidates[0].Severity, candidates[0].Facts, 2)
		if strings.Contains(title+text, value) || !strings.Contains(text, "an unrecognised source") {
			t.Fatalf("rendered %q / %q for %q", title, text, value)
		}
	}
	// Facts that fail their grammar render a fixed fallback.
	title, text := Render(KindCritical, SeverityHigh, Facts{RuleID: "<b>"}, 1)
	if title != "Notification" || strings.Contains(text, "<b>") {
		t.Fatalf("invalid facts rendered %q %q", title, text)
	}
	_, text = Render(KindHoneytoken, SeverityCritical, Facts{RuleID: "HT-001", Source: "203.0.113.7", Sensor: "web"}, 3)
	if text != "HT-001 matched 3 observations from source 203.0.113.7 on sensor web. The marker is operator-owned; its use is an observation, not proof of who used it." {
		t.Fatalf("summary = %q", text)
	}
}

func TestGroupingWindow(t *testing.T) {
	store := open(t, t.TempDir())
	defer store.Close()
	add := func(id int, at time.Time, source string) *Item {
		return store.Add(Observation(summary(id, at, source, "HT-001"))[0], at.Add(time.Hour))
	}
	first := add(1, base, "203.0.113.7")
	if first == nil || add(2, base.Add(5*time.Minute), "203.0.113.7") != nil || add(3, base.Add(10*time.Minute), "203.0.113.7") != nil {
		t.Fatal("repeats inside the window must group")
	}
	if add(4, base.Add(11*time.Minute), "203.0.113.7") == nil {
		t.Fatal("a repeat after the window must create a new item")
	}
	if add(5, base, "203.0.113.8") == nil {
		t.Fatal("another source must create a new item")
	}
	page := store.List(everything("cfg:admin"), Filter{Limit: 50})
	if len(page.Items) != 3 || page.Unread != 3 {
		t.Fatalf("page = %+v", page)
	}
	var grouped View
	for _, item := range page.Items {
		if item.ID == first.ID {
			grouped = item
		}
	}
	if grouped.GroupCount != 3 || grouped.UpdatedAt != base.Add(10*time.Minute).Format(time.RFC3339Nano) ||
		!strings.Contains(grouped.Summary, "3 observations") {
		t.Fatalf("grouped = %+v", grouped)
	}
}

func TestRateLimitFoldsIntoOverflow(t *testing.T) {
	store := open(t, t.TempDir())
	defer store.Close()
	wall := base.Add(time.Hour)
	created := 0
	for i := range 100 {
		// 100 distinct sources in one observation minute.
		at := base.Add(time.Duration(i) * 100 * time.Millisecond)
		if store.Add(Observation(summary(i+1, at, fmt.Sprintf("198.51.100.%d", i), "HT-001"))[0], wall) != nil {
			created++
		}
	}
	if created != ObservationBudget+1 || store.Dropped() != 100-ObservationBudget {
		t.Fatalf("created = %d dropped = %d", created, store.Dropped())
	}
	page := store.List(everything("cfg:admin"), Filter{Limit: 200})
	overflow := page.Items[0]
	if overflow.Title != "More notifications than the inbox limit" || overflow.GroupCount != 100-ObservationBudget ||
		!strings.HasPrefix(overflow.Summary, "80 decoy credential notifications were folded") {
		t.Fatalf("overflow = %+v", overflow)
	}
	// Account and assignment items are not limited.
	if store.Add(Account("cfg:admin", ReasonKeyCreated, true, wall), wall) == nil {
		t.Fatal("account item limited")
	}
	// The wall-clock budget also bounds items whose observation times differ.
	store2 := open(t, t.TempDir())
	defer store2.Close()
	created = 0
	for i := range 200 {
		at := base.Add(time.Duration(i) * time.Minute)
		if store2.Add(Observation(summary(i+1, at, fmt.Sprintf("198.51.100.%d", i%250), "AGT-001"))[0], wall) != nil {
			created++
		}
	}
	if created != WallBudget+1 || store2.Dropped() != 200-WallBudget {
		t.Fatalf("wall budget: created = %d dropped = %d", created, store2.Dropped())
	}
}

func TestRingCapAndCursorPaging(t *testing.T) {
	store := open(t, t.TempDir())
	defer store.Close()
	for i := range MaxItems + 50 {
		at := base.Add(time.Duration(i) * time.Minute)
		if store.Add(Assignment("cfg:admin", "inv_"+strings.Repeat("a", 39)+fmt.Sprintf("%04d", i), at), at) == nil {
			t.Fatalf("item %d not created", i)
		}
	}
	viewer := everything("cfg:admin")
	seen := map[string]bool{}
	cursor := uint64(0)
	for {
		page := store.List(viewer, Filter{Limit: 200, Cursor: cursor})
		for _, item := range page.Items {
			if seen[item.ID] {
				t.Fatal("duplicate across pages")
			}
			seen[item.ID] = true
		}
		if page.NextCursor == nil {
			break
		}
		next, ok := DecodeCursor(*page.NextCursor)
		if !ok {
			t.Fatal("cursor does not decode")
		}
		cursor = next
	}
	if len(seen) != MaxItems {
		t.Fatalf("listed %d; want %d", len(seen), MaxItems)
	}
	for _, bad := range []string{"", "n", "n0", "n01", "x5", "n-1", "n99999999999999999999"} {
		if _, ok := DecodeCursor(bad); ok {
			t.Fatalf("cursor %q accepted", bad)
		}
	}
}

func TestPermissionAndRecipientFiltering(t *testing.T) {
	store := open(t, t.TempDir())
	defer store.Close()
	store.Add(Observation(summary(1, base, "203.0.113.7", "HT-001"))[0], base)
	store.Add(PostureAttention("POS-007", base), base)
	store.Add(Account("acc_0123456789abcdef", ReasonRoleChanged, true, base), base)
	store.Add(Assignment("cfg:analyst", "inv_"+strings.Repeat("b", 43), base), base)
	evidenceOnly := Viewer{ID: "cfg:viewer", Can: func(perm string) bool { return perm == PermEvidence }}
	none := Viewer{ID: "acc_0123456789abcdef", Can: func(string) bool { return false }}
	analyst := everything("cfg:analyst")
	kindsOf := func(viewer Viewer) string {
		kinds := []string{}
		for _, item := range store.List(viewer, Filter{Limit: 50}).Items {
			kinds = append(kinds, item.Kind)
		}
		return strings.Join(kinds, ",")
	}
	if got := kindsOf(evidenceOnly); got != KindHoneytoken {
		t.Fatalf("evidence-only viewer sees %s", got)
	}
	if got := kindsOf(none); got != KindAccount {
		t.Fatalf("affected principal sees %s", got)
	}
	if got := kindsOf(analyst); got != KindAssignment+","+KindPosture+","+KindHoneytoken {
		t.Fatalf("analyst sees %s", got)
	}
	// Preferences hide kinds and severities but never account_security.
	prefs := DefaultPreferences()
	prefs.Kinds[KindHoneytoken] = false
	prefs.MinSeverity = SeverityHigh
	if err := store.SetPreferences("cfg:analyst", prefs, base); err != nil {
		t.Fatal(err)
	}
	if got := kindsOf(analyst); got != "" {
		t.Fatalf("filtered analyst sees %s", got)
	}
	if store.SetPreferences("cfg:analyst", Preferences{Kinds: map[string]bool{"x": true}, MinSeverity: "high"}, base) == nil {
		t.Fatal("unknown kind accepted")
	}
	off := DefaultPreferences()
	off.Kinds[KindAccount] = false
	if store.SetPreferences("cfg:analyst", off, base) == nil {
		t.Fatal("account_security disabled")
	}
}

func TestReadStateSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	store := open(t, dir)
	items := []*Item{}
	for i := range 5 {
		at := base.Add(time.Duration(i) * time.Hour)
		items = append(items, store.Add(Observation(summary(i+1, at, "203.0.113.7", "AGT-001"))[0], at))
	}
	store.SetDerive(DeriveState{HighWater: &Mark{Time: base, Key: "local:x"}, Campaigns: []string{"cmp_0123456789ab"}, Attention: []string{}, Expiring: []string{}})
	viewer := everything("cfg:admin")
	unread, err := store.MarkRead(viewer, []string{items[3].ID, "ntf_0000000000000000"}, base)
	if err != nil || unread != 4 {
		t.Fatalf("unread = %d err = %v", unread, err)
	}
	if unread, err = store.MarkAllRead(viewer, base.Add(90*time.Minute), base); err != nil || unread != 2 {
		t.Fatalf("mark all: unread = %d err = %v", unread, err)
	}
	if _, err := store.MarkRead(viewer, []string{"bad"}, base); err == nil {
		t.Fatal("invalid id accepted")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := open(t, dir)
	defer reopened.Close()
	if got := reopened.Unread(viewer); got != 2 {
		t.Fatalf("unread after restart = %d", got)
	}
	if got := reopened.Unread(everything("cfg:other")); got != 5 {
		t.Fatalf("other principal unread = %d", got)
	}
	derive := reopened.Derive()
	if derive.HighWater == nil || derive.HighWater.Key != "local:x" || len(derive.Campaigns) != 1 {
		t.Fatalf("derive = %+v", derive)
	}
	// The grouping index is rebuilt: a repeat inside the window still groups.
	if reopened.Add(Observation(summary(9, base.Add(4*time.Hour+time.Minute), "203.0.113.7", "AGT-001"))[0], base.Add(5*time.Hour)) != nil {
		t.Fatal("grouping lost across restart")
	}
}

func TestOpenFailsClosed(t *testing.T) {
	for name, body := range map[string]string{
		"not json":       "{",
		"unknown field":  `{"schema":"aegismesh.notifications/v1","next_seq":1,"items":[],"readers":{},"derive":{"campaigns":[],"attention":[],"expiring":[]},"extra":1}`,
		"wrong schema":   `{"schema":"v0","next_seq":1,"items":[],"readers":{},"derive":{"campaigns":[],"attention":[],"expiring":[]}}`,
		"bad reader id":  `{"schema":"aegismesh.notifications/v1","next_seq":1,"items":[],"readers":{"../x":{"before":0,"seqs":[],"at":"2026-01-01T00:00:00Z"}},"derive":{"campaigns":[],"attention":[],"expiring":[]}}`,
		"null campaigns": `{"schema":"aegismesh.notifications/v1","next_seq":1,"items":[],"readers":{},"derive":{"campaigns":null,"attention":[],"expiring":[]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, FileName), []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if store, err := Open(dir); err == nil {
				store.Close()
				t.Fatal("corrupt state accepted")
			}
		})
	}
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, FileName+".tmp"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if store, err := Open(dir); err == nil {
		store.Close()
		t.Fatal("stale temporary file ignored")
	}
}

func TestSlowSubscriberIsClosed(t *testing.T) {
	store := open(t, t.TempDir())
	defer store.Close()
	feed, cancel, ok := store.Subscribe()
	if !ok {
		t.Fatal("subscribe failed")
	}
	defer cancel()
	for i := range 100 {
		at := base.Add(time.Duration(i) * time.Hour)
		store.Add(Account("cfg:admin", ReasonKeyCreated, true, at), at)
	}
	count := 0
	for range feed {
		count++
	}
	if count != 64 {
		t.Fatalf("delivered %d before closing; want 64", count)
	}
	for range MaxSubscribers {
		if _, _, ok := store.Subscribe(); !ok {
			t.Fatal("subscriber limit too low")
		}
	}
	if _, _, ok := store.Subscribe(); ok {
		t.Fatal("subscriber limit not enforced")
	}
}

func FuzzDecode(f *testing.F) {
	store, err := Open(filepath.Join(f.TempDir(), "state"))
	if err != nil {
		f.Fatal(err)
	}
	store.Add(Observation(summary(1, base, "203.0.113.7", "HT-001"))[0], base)
	store.Add(Account("cfg:admin", ReasonKeyCreated, true, base), base)
	if _, err := store.MarkRead(everything("cfg:admin"), []string{store.data.Items[0].ID}, base); err != nil {
		f.Fatal(err)
	}
	body, _ := json.Marshal(store.data)
	store.Close()
	f.Add(body)
	f.Add([]byte(`{"schema":"aegismesh.notifications/v1","next_seq":1,"items":[],"readers":{},"derive":{"campaigns":[],"attention":[],"expiring":[]}}`))
	f.Add([]byte(`{"schema":"aegismesh.notifications/v1","next_seq":1,"items":null}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		data, err := decode(body)
		if err != nil {
			return
		}
		// Anything accepted renders from templates without failing.
		for _, item := range data.Items {
			if !validItem(item) {
				t.Fatal("invalid item accepted")
			}
			title, _ := Render(item.Kind, item.Severity, item.Facts, item.GroupCount)
			if title == "" {
				t.Fatal("empty title")
			}
		}
	})
}
