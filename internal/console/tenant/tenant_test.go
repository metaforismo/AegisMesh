package tenant

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMigrationResumesAtomicRename(t *testing.T) {
	for _, crash := range []string{"", "renamed", "prepared", "moved"} {
		dir := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		original := []byte("existing hash chain and annotations")
		if err := os.WriteFile(filepath.Join(dir, "audit.jsonl"), original, 0600); err != nil {
			t.Fatal(err)
		}
		if crash != "" {
			_, err := prepare(dir, []string{"default", "bravo"}, func(step string) error {
				if step == crash {
					return errors.New("simulated crash")
				}
				return nil
			})
			if err == nil {
				t.Fatal("crash hook was not reached")
			}
		}
		paths, err := Prepare(dir, []string{"default", "bravo"})
		if err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(filepath.Join(paths[Default], "audit.jsonl"))
		if err != nil || string(body) != string(original) {
			t.Fatalf("migration lost bytes: %s %v", body, err)
		}
		if _, err := Prepare(dir, []string{"default", "bravo"}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(dir + ".tenant-migration"); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("migration still pending")
		}
	}
}

func TestInvalidTenantNeverSelectsPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	for _, name := range []string{"../escape", "ABC", "ab", "a/b", "a..b", "a_foo", "-abc", "abc-"} {
		if _, err := Prepare(dir, []string{name}); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid tenant touched filesystem")
	}
}

func FuzzTenantSlug(f *testing.F) {
	for _, seed := range []string{"default", "bravo", "../escape", "abc", "a-b", "ab", "Aegis", "abc%2f"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		parsed, err := Parse(value)
		if err == nil {
			if parsed != value || len(value) < 3 || len(value) > 64 || filepath.Base(value) != value {
				t.Fatalf("unsafe slug %q", value)
			}
			for _, r := range value {
				if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
					t.Fatal("invalid byte accepted")
				}
			}
		}
	})
}

func TestMigrationRefusesUnrelatedDirectoryBeforeRename(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "AGENTS.md")
	if err := os.WriteFile(path, []byte("keep this workspace"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(dir, []string{"default"}); err == nil {
		t.Fatal("unrelated directory migrated")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("unrelated root was moved")
	}
	if _, err := os.Stat(dir + ".tenant-migration"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("migration had side effects")
	}
}
