package investigations

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/console/stateio"
)

func openStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	store, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	return store, dir
}

func eventIDs(count int) []string {
	ids := make([]string, count)
	for index := range ids {
		ids[index] = fmt.Sprintf("%032x", index)
	}
	return ids
}

func TestCreateValidation(t *testing.T) {
	cases := []struct {
		name  string
		input Create
		want  error
	}{
		{
			name:  "empty title",
			input: Create{},
			want:  ErrInvalid,
		},
		{
			name:  "one rune",
			input: Create{Title: "é"},
		},
		{
			name:  "200 runes",
			input: Create{Title: strings.Repeat("é", 200)},
		},
		{
			name:  "201 runes",
			input: Create{Title: strings.Repeat("é", 201)},
			want:  ErrInvalid,
		},
		{
			name:  "invalid UTF8",
			input: Create{Title: string([]byte{0xff})},
			want:  ErrInvalid,
		},
		{
			name: "low priority",
			input: Create{
				Title:    "x",
				Priority: "low",
			},
		},
		{
			name: "medium priority",
			input: Create{
				Title:    "x",
				Priority: "medium",
			},
		},
		{
			name: "high priority",
			input: Create{
				Title:    "x",
				Priority: "high",
			},
		},
		{
			name: "invalid priority",
			input: Create{
				Title:    "x",
				Priority: "urgent",
			},
			want: ErrInvalid,
		},
		{
			name: "200 events",
			input: Create{
				Title:    "x",
				EventIDs: eventIDs(200),
			},
		},
		{
			name: "201 events",
			input: Create{
				Title:    "x",
				EventIDs: eventIDs(201),
			},
			want: ErrInvalid,
		},
		{
			name: "duplicate events",
			input: Create{
				Title: "x",
				EventIDs: []string{
					eventIDs(1)[0],
					eventIDs(1)[0],
				},
			},
			want: ErrInvalid,
		},
		{
			name: "invalid event id",
			input: Create{
				Title:    "x",
				EventIDs: []string{"../bad"},
			},
			want: ErrInvalid,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			store, _ := openStore(t)
			_, err := store.Create(testCase.input, "alice")
			if !errors.Is(err, testCase.want) {
				t.Fatalf("Create error = %v; want %v", err, testCase.want)
			}
		})
	}
}

func TestPatchValidation(t *testing.T) {
	cases := []struct {
		name  string
		field string
		value string
		want  error
	}{
		{
			name: "empty patch",
			want: ErrInvalid,
		},
		{
			name:  "empty title",
			field: "title",
			want:  ErrInvalid,
		},
		{
			name:  "maximum title",
			field: "title",
			value: strings.Repeat("é", 200),
		},
		{
			name:  "oversized title",
			field: "title",
			value: strings.Repeat("é", 201),
			want:  ErrInvalid,
		},
		{
			name:  "open",
			field: "status",
			value: "open",
		},
		{
			name:  "monitoring",
			field: "status",
			value: "monitoring",
		},
		{
			name:  "closed",
			field: "status",
			value: "closed",
		},
		{
			name:  "invalid status",
			field: "status",
			value: "deleted",
			want:  ErrInvalid,
		},
		{
			name:  "invalid priority",
			field: "priority",
			value: "urgent",
			want:  ErrInvalid,
		},
		{
			name:  "low",
			field: "priority",
			value: "low",
		},
		{
			name:  "medium",
			field: "priority",
			value: "medium",
		},
		{
			name:  "high",
			field: "priority",
			value: "high",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			store, _ := openStore(t)
			original, err := store.Create(Create{Title: "Original"}, "alice")
			if err != nil {
				t.Fatal(err)
			}
			patch := Patch{}
			switch testCase.field {
			case "title":
				patch.Title = &testCase.value
			case "status":
				patch.Status = &testCase.value
			case "priority":
				patch.Priority = &testCase.value
			}
			_, err = store.Patch(original.ID, patch)
			if !errors.Is(err, testCase.want) {
				t.Fatalf("Patch error = %v; want %v", err, testCase.want)
			}
			if err != nil {
				persisted, err := store.Get(original.ID)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(persisted, original) {
					t.Fatal("rejected patch changed state")
				}
			}
		})
	}
}

func TestNoteAndAttachmentLimits(t *testing.T) {
	store, _ := openStore(t)
	investigation, err := store.Create(Create{
		Title:    "Quota fixture",
		EventIDs: eventIDs(200),
	}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	for _, testCase := range []struct {
		name string
		text string
		want error
	}{
		{
			name: "empty",
			want: ErrInvalid,
		},
		{
			name: "one rune",
			text: "é",
		},
		{
			name: "4000 runes",
			text: strings.Repeat("é", 4000),
		},
		{
			name: "4001 runes",
			text: strings.Repeat("é", 4001),
			want: ErrInvalid,
		},
		{
			name: "invalid UTF8",
			text: string([]byte{0xff}),
			want: ErrInvalid,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := store.AddNote(investigation.ID, testCase.text, "alice")
			if !errors.Is(err, testCase.want) {
				t.Fatalf("AddNote error = %v; want %v", err, testCase.want)
			}
		})
	}
	for count := 2; count < MaxNotes; count++ {
		if _, err := store.AddNote(investigation.ID, "note", "alice"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.AddNote(investigation.ID, "over quota", "alice"); !errors.Is(err, ErrLimit) {
		t.Fatalf("note count limit: %v", err)
	}
	for _, testCase := range []struct {
		name    string
		eventID string
		attach  bool
		want    error
	}{
		{
			name:    "201st event",
			eventID: eventIDs(201)[200],
			attach:  true,
			want:    ErrLimit,
		},
		{
			name:    "duplicate attach is idempotent",
			eventID: eventIDs(1)[0],
			attach:  true,
		},
		{
			name:    "invalid attach",
			eventID: "../bad",
			attach:  true,
			want:    ErrInvalid,
		},
		{
			name:    "invalid detach",
			eventID: "../bad",
			want:    ErrInvalid,
		},
		{
			name:    "detach",
			eventID: eventIDs(1)[0],
		},
		{
			name:    "reattach after detach",
			eventID: eventIDs(1)[0],
			attach:  true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := store.Attach(investigation.ID, testCase.eventID, testCase.attach)
			if !errors.Is(err, testCase.want) {
				t.Fatalf("Attach error = %v; want %v", err, testCase.want)
			}
		})
	}
}

func writeSnapshot(t *testing.T, dir string, items map[string]Investigation) []byte {
	t.Helper()
	body, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "investigations.json"), body, 0600); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestInvestigationCountLimit(t *testing.T) {
	store, dir := openStore(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	items := make(map[string]Investigation, MaxInvestigations)
	for index := range MaxInvestigations {
		id := fmt.Sprintf("inv_%d", index)
		items[id] = Investigation{
			ID:       id,
			Title:    "Synthetic",
			Status:   "open",
			Priority: "medium",
		}
	}
	writeSnapshot(t, dir, items)
	store, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if len(store.List("")) != MaxInvestigations {
		t.Fatal("fixture did not reach investigation count limit")
	}
	if _, err := store.Create(Create{Title: "Over quota"}, "alice"); !errors.Is(err, ErrLimit) {
		t.Fatalf("investigation count limit: %v", err)
	}
}

func TestEncodedStateByteLimit(t *testing.T) {
	store, dir := openStore(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	items := map[string]Investigation{
		"inv_target": {
			ID:       "inv_target",
			Title:    "Target",
			Status:   "open",
			Priority: "medium",
		},
	}
	for index := range 84 {
		id := fmt.Sprintf("inv_%d", index)
		investigation := Investigation{
			ID:       id,
			Title:    "Synthetic",
			Status:   "open",
			Priority: "medium",
		}
		for range MaxNotes {
			investigation.Notes = append(investigation.Notes, Note{Text: strings.Repeat("a", 4000)})
		}
		items[id] = investigation
	}
	encoded, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	excess := len(encoded) - (stateio.MaxStateBytes - 1024)
	if excess <= 0 {
		t.Fatal("byte quota fixture too small")
	}
	for id, investigation := range items {
		for index := range investigation.Notes {
			reduction := min(excess, len(investigation.Notes[index].Text)-1)
			investigation.Notes[index].Text = investigation.Notes[index].Text[:4000-reduction]
			excess -= reduction
			if excess == 0 {
				break
			}
		}
		items[id] = investigation
		if excess == 0 {
			break
		}
	}
	original := writeSnapshot(t, dir, items)
	if len(original) != stateio.MaxStateBytes-1024 {
		t.Fatalf("snapshot size = %d", len(original))
	}
	store, err = New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.AddNote("inv_target", strings.Repeat("a", 4000), "alice"); !errors.Is(err, ErrLimit) {
		t.Fatalf("encoded state byte limit: %v", err)
	}
	after, err := os.ReadFile(filepath.Join(dir, "investigations.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(original) {
		t.Fatal("over-quota write changed persisted state")
	}
	target, err := store.Get("inv_target")
	if err != nil || len(target.Notes) != 0 {
		t.Fatal("over-quota write changed in-memory state")
	}
}

func TestFailedAtomicWritePreservesSnapshot(t *testing.T) {
	store, dir := openStore(t)
	original, err := store.Create(Create{Title: "Before failure"}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(dir, "investigations.json.tmp")
	if err := os.WriteFile(temporary, []byte("synthetic interrupted write"), 0600); err != nil {
		t.Fatal(err)
	}
	changed := "After failure"
	if _, err := store.Patch(original.ID, Patch{Title: &changed}); err == nil {
		t.Fatal("stale temporary file was overwritten")
	}
	current, err := store.Get(original.ID)
	if err != nil || !reflect.DeepEqual(current, original) {
		t.Fatal("failed persistence changed in-memory state")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := New(dir); err == nil {
		reopened.Close()
		t.Fatal("stale temporary file did not fail closed")
	} else if !strings.Contains(err.Error(), "inspect stale temporary state") {
		t.Fatalf("unactionable error: %v", err)
	}
	// Simulate operator inspection and recovery of this test-owned temporary file.
	if err := os.Remove(temporary); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restored, err := reopened.Get(original.ID)
	if err != nil || !reflect.DeepEqual(restored, original) {
		t.Fatal("restart did not retain last atomic snapshot")
	}
}

func TestCorruptedStateFailsClosed(t *testing.T) {
	for _, testCase := range []struct {
		name string
		body string
	}{
		{
			name: "truncated JSON",
			body: `{"inv_x":`,
		},
		{
			name: "null",
			body: `null`,
		},
		{
			name: "array",
			body: `[]`,
		},
		{
			name: "invalid record",
			body: `{"inv_x":{"id":"inv_x","title":"x","status":"deleted","priority":"medium"}}`,
		},
		{
			name: "mismatched id",
			body: `{"inv_x":{"id":"inv_y","title":"x","status":"open","priority":"medium"}}`,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			store, dir := openStore(t)
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "investigations.json"), []byte(testCase.body), 0600); err != nil {
				t.Fatal(err)
			}
			if reopened, err := New(dir); err == nil {
				reopened.Close()
				t.Fatal("corrupted state accepted")
			} else if !strings.Contains(err.Error(), "investigations.json") || !strings.Contains(err.Error(), "inspect state") {
				t.Fatalf("unactionable corruption error: %v", err)
			}
		})
	}
}
