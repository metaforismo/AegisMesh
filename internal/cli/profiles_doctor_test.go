package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scaffoldWithProfile runs init with the requested profile and returns the
// workspace dir plus the mesh.yaml path. Every generated variant must load
// through the same strict path the runtime uses.
func scaffoldWithProfile(t *testing.T, profile string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	code, _, stderr := run(t, "init", "--dir", dir, "--profile", profile)
	if code != 0 {
		t.Fatalf("init --profile %s failed: %s", profile, stderr)
	}
	return dir, filepath.Join(dir, "mesh.yaml")
}

func TestInitProfilesAllLoadAndClassify(t *testing.T) {
	for _, p := range []string{"local", "ollama", "remote"} {
		t.Run(p, func(t *testing.T) {
			_, cfg := scaffoldWithProfile(t, p)

			code, out, stderr := run(t, "validate", "--config", cfg)
			if code != 0 {
				t.Fatalf("validate rejected %s scaffold: %s%s", p, out, stderr)
			}

			code, out, _ = run(t, "doctor", "--config", cfg)
			if code != 0 {
				t.Fatalf("doctor failed for %s: %q", p, out)
			}
			switch p {
			case "local":
				if !strings.Contains(out, "deterministic local provider") {
					t.Fatalf("local profile should classify as deterministic: %q", out)
				}
			case "ollama":
				if !strings.Contains(out, "loopback endpoint") {
					t.Fatalf("ollama profile should classify as loopback: %q", out)
				}
			case "remote":
				if !strings.Contains(out, "api_key_env OPENAI_API_KEY is UNSET") {
					t.Fatalf("remote profile should surface unset credential env: %q", out)
				}
			}
		})
	}
}

func TestInitRejectsUnknownProfile(t *testing.T) {
	code, _, stderr := run(t, "init", "--dir", t.TempDir(), "--profile", "claude")
	if code == 0 || !strings.Contains(stderr, "local|ollama|remote") {
		t.Fatalf("unknown profile must be refused with valid set: code=%d %q", code, stderr)
	}
}

func TestDoctorRemoteProfileKeyFileStates(t *testing.T) {
	dir := t.TempDir()
	code, _, stderr := run(t, "init", "--dir", dir, "--profile", "remote")
	if code != 0 {
		t.Fatal(stderr)
	}
	cfgPath := filepath.Join(dir, "mesh.yaml")

	// Point api_key_file at a missing relative path by swapping out the
	// env reference (the loader correctly refuses both set at once).
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	marker := "api_key_env: OPENAI_API_KEY"
	if !strings.Contains(string(raw), marker) {
		t.Fatal("remote profile template missing api_key_env line")
	}
	swapped := strings.Replace(string(raw), marker+"      # NAME of the env var holding the key — never the key itself",
		"api_key_file: ./secrets/llm.key", 1)
	if swapped == string(raw) {
		t.Fatal("remote profile template line changed; update this test")
	}
	if err := os.WriteFile(cfgPath, []byte(swapped), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := run(t, "doctor", "--config", cfgPath)
	if code != 0 || !strings.Contains(out, `api_key_file "./secrets/llm.key" not readable`) {
		t.Fatalf("missing key file must warn: code=%d %q", code, out)
	}

	keyPath := filepath.Join(dir, "secrets", "llm.key")
	os.MkdirAll(filepath.Dir(keyPath), 0o700)
	os.WriteFile(keyPath, []byte("sk-synthetic-not-a-real-key\n"), 0o600)
	code, out, _ = run(t, "doctor", "--config", cfgPath)
	if code != 0 || !strings.Contains(out, `api_key_file "./secrets/llm.key" readable`) {
		t.Fatalf("present key file should report readable: code=%d %q", code, out)
	}
	if strings.Contains(out, "sk-synthetic") {
		t.Fatal("doctor must never print key material")
	}
}
