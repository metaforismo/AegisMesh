package investigations

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const legacySnapshot = `{"inv_legacy":{"id":"inv_legacy","title":"Before round 8","status":"open","priority":"medium",` +
	`"created_at":"2026-11-01T10:00:00Z","updated_at":"2026-11-01T10:00:00Z","created_by":"alice",` +
	`"event_ids":["00000000000000000000000000000001"],"notes":[{"id":"note_x","time":"2026-11-01T10:00:00Z","author":"alice","text":"kept"}]}}`

func TestLegacySnapshotMigratesToSchemaV2(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "investigations.json")
	if err := os.WriteFile(file, []byte(legacySnapshot), 0600); err != nil {
		t.Fatal(err)
	}
	count, err := ReadOpenCount(dir)
	if err != nil || count == nil || *count != 1 {
		t.Fatalf("legacy open count = %v, %v", count, err)
	}
	store, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Get("inv_legacy")
	if err != nil || got.Origin != nil || got.Assignee != nil || got.Activity == nil || len(got.Activity) != 0 || len(got.Notes) != 1 {
		t.Fatalf("migrated = %+v, %v", got, err)
	}
	// Reading never rewrites; the first change persists the versioned schema.
	if body, _ := os.ReadFile(file); string(body) != legacySnapshot {
		t.Fatal("open rewrote the legacy snapshot")
	}
	status := "closed"
	if _, _, err := store.PatchBy("inv_legacy", Patch{Status: &status}, Actor{ID: "cfg:alice", Name: "alice"}); err != nil {
		t.Fatal(err)
	}
	store.Close()
	body, _ := os.ReadFile(file)
	if !bytes.HasPrefix(body, []byte(`{"schema":"aegismesh.investigations/v2","items":{`)) {
		t.Fatalf("persisted = %s", body)
	}
	count, err = ReadOpenCount(dir)
	if err != nil || *count != 0 {
		t.Fatalf("v2 open count = %v, %v", *count, err)
	}
	reopened, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, _ = reopened.Get("inv_legacy")
	if len(got.Activity) != 1 || got.Activity[0].Kind != ActivityStatus || got.Activity[0].Detail != "open → closed" ||
		got.Activity[0].ActorID != "cfg:alice" {
		t.Fatalf("activity = %+v", got.Activity)
	}
}

func TestSchemaV2IsStrict(t *testing.T) {
	valid := `{"schema":"aegismesh.investigations/v2","items":{}}`
	if _, err := decode([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"unknown top field":   `{"schema":"aegismesh.investigations/v2","items":{},"x":1}`,
		"future schema":       `{"schema":"aegismesh.investigations/v3","items":{}}`,
		"null items":          `{"schema":"aegismesh.investigations/v2","items":null}`,
		"bad origin":          strings.Replace(v2Item, `"origin":null`, `"origin":{"kind":"file","id":"/etc/passwd"}`, 1),
		"bad assignee":        strings.Replace(v2Item, `"assignee":null`, `"assignee":"../x"`, 1),
		"assignee no name":    strings.Replace(v2Item, `"assignee":null`, `"assignee":"cfg:alice"`, 1),
		"bad activity kind":   strings.Replace(v2Item, `"kind":"created"`, `"kind":"exec"`, 1),
		"control in activity": strings.Replace(v2Item, `"detail":"created"`, `"detail":"a\u0007b"`, 1),
		"unknown item field":  strings.Replace(v2Item, `"origin":null`, `"origin":null,"shell":"rm"`, 1),
	} {
		if _, err := decode([]byte(body)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := decode([]byte(v2Item)); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
}

const v2Item = `{"schema":"aegismesh.investigations/v2","items":{"inv_a":{"id":"inv_a","title":"T","status":"open","priority":"low",` +
	`"created_at":"2026-11-01T10:00:00Z","updated_at":"2026-11-01T10:00:00Z","created_by":"alice","event_ids":[],` +
	`"origin":null,"assignee":null,"assignee_name":null,` +
	`"activity":[{"at":"2026-11-01T10:00:00Z","actor_id":"cfg:alice","actor_name":"alice","kind":"created","detail":"created"}]}}}`

func TestActivityIsBoundedAndSeeded(t *testing.T) {
	store, _ := openStore(t)
	actor := Actor{ID: "cfg:alice", Name: "alice\u0007"}
	seeded, err := store.CreateBy(Create{Title: "From campaign", EventIDs: eventIDs(2)}, Actor{ID: "cfg:alice", Name: "alice"},
		&Seed{Origin: Origin{Kind: OriginCampaign, ID: "cmp_0123456789ab"}, Note: "fixed template", AttachDetail: "attached 2 events from campaign cmp_0123456789ab"})
	if err != nil || seeded.Origin == nil || len(seeded.Notes) != 1 || len(seeded.Activity) != 3 {
		t.Fatalf("seeded = %+v, %v", seeded, err)
	}
	for i := range MaxActivity + 5 {
		priority := []string{"low", "high"}[i%2]
		if _, _, err := store.PatchBy(seeded.ID, Patch{Priority: &priority}, actor); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := store.Get(seeded.ID)
	if len(got.Activity) != MaxActivity || !got.ActivityTruncated || got.Activity[len(got.Activity)-1].ActorName != "alice" {
		t.Fatalf("activity len %d truncated %v last %+v", len(got.Activity), got.ActivityTruncated, got.Activity[len(got.Activity)-1])
	}
	// Idempotent changes record nothing.
	same := got.Priority
	after, _, _ := store.PatchBy(seeded.ID, Patch{Priority: &same}, actor)
	if len(after.Activity) != MaxActivity || after.Activity[len(after.Activity)-1].At != got.Activity[len(got.Activity)-1].At {
		t.Fatal("no-op patch recorded activity")
	}
	// Assignment validation is grammar-level here; the console checks principals.
	if _, _, err := store.PatchBy(seeded.ID, Patch{Assign: &Actor{ID: "bad id", Name: "x"}}, actor); !errors.Is(err, ErrInvalid) {
		t.Fatal("bad assignee id accepted")
	}
	body, _ := json.Marshal(after)
	if !strings.Contains(string(body), `"origin":{"kind":"campaign","id":"cmp_0123456789ab"}`) {
		t.Fatalf("origin json = %s", body)
	}
}

func FuzzDecodeSnapshot(f *testing.F) {
	f.Add([]byte(legacySnapshot))
	f.Add([]byte(v2Item))
	f.Add([]byte(`{"schema":"aegismesh.investigations/v2","items":{}}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		items, err := decode(body)
		if err != nil {
			return
		}
		for id, item := range items {
			if id != item.ID || validate(item) != nil || item.Activity == nil {
				t.Fatal("invalid record accepted")
			}
		}
	})
}
