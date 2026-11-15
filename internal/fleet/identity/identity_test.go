package identity

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestIdentitySurvivesRestartAndFailsClosed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "agent")
	first, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Load(dir)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("identity changed: %v", err)
	}
	for path, mode := range map[string]os.FileMode{
		dir:                                 0700,
		filepath.Join(dir, "identity.seed"): 0600,
	} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("permissions %s: %v", path, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "identity.seed"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("accepted corrupt seed")
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("accepted nonprivate directory")
	}
}
