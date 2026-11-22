package investigations

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicPersistenceAndBounds(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	store, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	id := strings.Repeat("a", 32)
	investigation, err := store.Create(Create{
		Title:    "Review observed request",
		EventIDs: []string{id},
	}, "alice")
	if err != nil {
		t.Fatal(err)
	}

	if _, err = store.Create(Create{Title: strings.Repeat("é", 201)}, "alice"); err == nil {
		t.Fatal("title cap")
	}

	if _, err = store.Attach(investigation.ID, "../bad", true); err == nil {
		t.Fatal("bad id")
	}

	if _, err = store.AddNote(investigation.ID, strings.Repeat("a", 4001), "alice"); err == nil {
		t.Fatal("note cap")
	}

	for range MaxNotes {
		if _, err = store.AddNote(investigation.ID, "operator observation", "alice"); err != nil {
			t.Fatal(err)
		}
	}

	if _, err = store.AddNote(investigation.ID, "over quota", "alice"); err != ErrLimit {
		t.Fatalf("note quota: %v", err)
	}

	priority := "high"
	if _, err = store.Patch(investigation.ID, Patch{Priority: &priority}); err != nil {
		t.Fatal(err)
	}

	store.Close()
	store, err = New(dir)
	if err != nil {
		t.Fatal(err)
	}

	defer store.Close()

	investigation, err = store.Get(investigation.ID)
	if err != nil ||
		investigation.Priority != "high" ||
		len(investigation.Notes) != MaxNotes ||
		len(investigation.EventIDs) != 1 {
		t.Fatalf("%+v %v", investigation, err)
	}

	if len(store.List("")[0].Notes) != 0 {
		t.Fatal("notes exposed in list")
	}

	investigation.EventIDs[0] = "mutated"
	again, _ := store.Get(investigation.ID)
	if again.EventIDs[0] != id {
		t.Fatal("returned alias modified state")
	}
}

func TestReadOpenCountDoesNotWriteAndRejectsBadState(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, title := range []string{"one", "two"} {
		if _, err := store.Create(Create{Title: title}, "synthetic"); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	count, err := ReadOpenCount(dir)
	if err != nil || count == nil || *count != 2 {
		t.Fatal(count, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "investigations.json.tmp"), []byte("incomplete"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadOpenCount(dir); err == nil {
		t.Fatal("accepted interrupted state")
	}
}
