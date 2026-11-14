package stateio

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateStateAndAtomicReplace(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	root, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	defer root.Close()

	if err = Atomic(root, "state.json", []byte(`{"version":1}`)); err != nil {
		t.Fatal(err)
	}

	if err = Atomic(root, "state.json", []byte(`{"version":2}`)); err != nil {
		t.Fatal(err)
	}

	body, err := Read(root, "state.json", 100)
	if err != nil || string(body) != `{"version":2}` {
		t.Fatalf("%s %v", body, err)
	}

	if _, err = Read(root, "state.json", 2); err == nil {
		t.Fatal("read byte cap")
	}

	st, _ := os.Stat(filepath.Join(dir, "state.json"))
	if st.Mode().Perm() != 0600 {
		t.Fatal(st.Mode())
	}

	if err = os.WriteFile(filepath.Join(dir, "stale.tmp"), []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}

	if err = Atomic(root, "stale", []byte("new")); err == nil {
		t.Fatal("stale temp overwritten")
	}

	body, _ = os.ReadFile(filepath.Join(dir, "stale.tmp"))
	if string(body) != "preserve" {
		t.Fatal("stale temp removed")
	}
}
