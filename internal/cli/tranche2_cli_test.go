package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/storage"
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
	raw, _ := os.ReadFile(cfgPath)

	// Point api_key_file at a missing relative path by swapping out the
	// env reference (the loader correctly refuses both set at once).
	raw, _ = os.ReadFile(cfgPath)
	marker := "api_key_env: OPENAI_API_KEY"
	idx := strings.Index(string(raw), marker)
	if idx < 0 {
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

func TestValidateEffectiveHumanAndJSON(t *testing.T) {
	dir, cfg := scaffoldWithProfile(t, "local")

	code, out, stderr := run(t, "validate", "--config", cfg, "--effective")
	if code != 0 {
		t.Fatalf("validate --effective failed: %s%s", out, stderr)
	}
	for _, want := range []string{
		"effective policy",
		"provider: local",
		"detection: enabled",
		"actions: info=observe low=tag medium=isolate high=refuse",
		"max_input=8192B throttle=600/min",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("effective output missing %q:\n%s", want, out)
		}
	}

	var ob, eb strings.Builder
	env := &Env{Out: &ob, Err: &eb}
	app := NewApp("aegismesh", "s", &ob, &eb)
	must(app.Register(NewValidateCmd(env)))
	must(app.Register(NewInitCmd(env)))
	code = app.Run(context.Background(), []string{"validate", "--config", cfg, "--effective", "--json"})
	if code != 0 {
		t.Fatalf("--json effective failed: %q", eb.String())
	}
	var rep struct {
		EgressClass string `json:"egress_class"`
		Detection   struct {
			RulesEnabled int               `json:"rules_enabled"`
			Actions      map[string]string `json:"actions"`
		} `json:"detection"`
		Sensors []struct {
			ID      string `json:"id"`
			Kind    string `json:"kind"`
			Tools   int    `json:"mcp_tools,omitempty"`
			Fallbck bool   `json:"llm_fallback,omitempty"`
		} `json:"sensors"`
	}
	if err := json.Unmarshal([]byte(ob.String()), &rep); err != nil {
		t.Fatalf("not JSON: %q", ob.String())
	}
	if rep.Detection.RulesEnabled != 6 {
		t.Fatalf("expected all 6 rules active by default, got %d", rep.Detection.RulesEnabled)
	}
	if len(rep.Sensors) < 3 {
		t.Fatalf("expected http/tcp/mcp sensors in report: %+v", rep.Sensors)
	}
	var sawMCP bool
	for _, s := range rep.Sensors {
		if s.Kind == "mcp" && s.Tools > 0 {
			sawMCP = true
		}
	}
	if !sawMCP {
		t.Fatalf("mcp sensor must report its decoy tool count: %+v", rep.Sensors)
	}
	_ = dir
}

func TestValidateEffectiveHonorsDisabledRules(t *testing.T) {
	_, cfg := scaffoldWithProfile(t, "local")
	raw, _ := os.ReadFile(cfg)
	raw = append(raw, []byte("\ndetection:\n  disabled_rules: [OBS-001]\n")...)
	cfg2 := filepath.Join(t.TempDir(), "mesh.yaml")
	os.WriteFile(cfg2, raw, 0o600)

	code, out, _ := run(t, "validate", "--config", cfg2, "--effective")
	if code != 0 || !strings.Contains(out, "5/6 rules active") || !strings.Contains(out, "OBS-001") {
		t.Fatalf("disabled rule not reflected: code=%d\n%s", code, out)
	}

	// Unknown rule ids are a config error, caught at load time.
	bad := []byte(strings.Replace(string(raw), "OBS-001", "NOPE-999", 1))
	cfg3 := filepath.Join(t.TempDir(), "mesh.yaml")
	os.WriteFile(cfg3, bad, 0o600)
	code, _, stderr := run(t, "validate", "--config", cfg3, "--effective")
	if code == 0 || !strings.Contains(stderr+out, "unknown detection rule") {
		t.Fatalf("unknown disabled rule must fail validation: code=%d %q", code, stderr)
	}
}

// seedDetectionEvidence writes two events into a fresh store: one whose
// observation carries a PI-001 finding, one without any detection block.
func seedDetectionEvidence(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := storage.New(storage.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	seq := &event.Sequencer{}
	ref := event.SensorRef{ID: "mcp-decoy-1", Kind: "mcp", Listen: "127.0.0.1:8090"}

	withFinding, err := event.New(seq, "test-instance", ref, event.ClassificationInteraction,
		json.RawMessage(`{"tool":"canary:x","detection":{"action":"refuse","findings":[{"rule_id":"PI-001","severity":"high"}]}}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := event.New(seq, "test-instance", ref, event.ClassificationInteraction,
		json.RawMessage(`{"tool":"canary:y"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []event.Envelope{withFinding, plain} {
		if err := st.Append(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, withFinding.ID
}

func TestInspectFindingFilter(t *testing.T) {
	dir, findingID := seedDetectionEvidence(t)

	code, out, stderr := run(t, "inspect", "list", "--data-dir", dir, "--finding", "PI-001")
	if code != 0 {
		t.Fatalf("list --finding failed: %s%s", out, stderr)
	}
	if !strings.Contains(out, findingID[:8]) || strings.Count(out, "\n") > 6 {
		t.Fatalf("filter should return exactly the PI-001 event: %q", out)
	}

	// Non-matching rule yields an empty (but successful) listing.
	code, out, _ = run(t, "inspect", "list", "--data-dir", dir, "--finding", "EXF-001")
	if code != 0 || !strings.Contains(strings.ToLower(out), "no events") {
		t.Fatalf("non-matching filter should list nothing: code=%d %q", code, out)
	}

	// Unknown rule ids are rejected before touching evidence.
	code, _, stderr = run(t, "inspect", "list", "--data-dir", dir, "--finding", "ZZZ-000")
	if code == 0 || !strings.Contains(stderr, "unknown detection rule") {
		t.Fatalf("invalid rule id must be refused: code=%d %q", code, stderr)
	}

	// JSON mode carries integrity verification per row when asked.
	code, out, _ = run(t, "inspect", "list", "--data-dir", dir, "--finding", "PI-001", "--verify", "--json")
	if code != 0 {
		t.Fatal(code)
	}
	var payload struct {
		Events []struct {
			ID          string `json:"id"`
			IntegrityOK bool   `json:"integrity_ok"`
		} `json:"events"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("json list invalid: %q", out)
	}
	if len(payload.Events) != 1 || payload.Events[0].ID != findingID || !payload.Events[0].IntegrityOK {
		t.Fatalf("filtered json payload wrong: %+v", payload.Events)
	}
}

const migrationInlineKeyFixture = `protocol: http
address: ":8081"
description: "leaky source"
commands:
  - regex: "^/admin$"
    handler: "denied"
`

func TestMigrateRefusesInlineCredentialMaterial(t *testing.T) {
	src := filepath.Join(t.TempDir(), "leak.yaml")
	body := migrationInlineKeyFixture + "api_key: \"" + strings.Repeat("A1b2C3d4E5f6G7h8I9j0K1l2", 3) + "\"\n"
	os.WriteFile(src, []byte(body), 0o600)

	outDir := filepath.Join(t.TempDir(), "out")
	code, out, stderr := run(t, "migrate", "beelzebub", src, "--out", outDir)
	if code == 0 {
		t.Fatalf("inline credential must refuse import: %q", out)
	}
	msg := out + stderr
	if !strings.Contains(msg, "credential material detected at $.api_key") {
		t.Fatalf("error must name the offending path: %q", msg)
	}
	if strings.Contains(msg, strings.Repeat("A1b2", 4)) {
		t.Fatal("refusal message must never echo the secret value")
	}
	if entries, _ := os.ReadDir(outDir); len(entries) != 0 {
		t.Fatal("refused import must write nothing")
	}
}

func TestMigrateReportsCredentialReferenceWithoutCarryingIt(t *testing.T) {
	src := filepath.Join(t.TempDir(), "ref.yaml")
	os.WriteFile(src, []byte(migrationInlineKeyFixture+"token: /etc/beelzebub/auth.token\n"), 0o600)

	outDir := filepath.Join(t.TempDir(), "out")
	code, out, stderr := run(t, "migrate", "beelzebub", src, "--out", outDir, "--write")
	if code != 0 {
		t.Fatalf("path-shaped reference may import, reported: %q %q", out, stderr)
	}
	if !strings.Contains(out, "credential reference detected") {
		t.Fatalf("reference must be surfaced as unsupported note: %q", out)
	}
	generated := filepath.Join(outDir, "ref.aegismesh.yaml")
	emitted, err := os.ReadFile(generated)
	if err != nil {
		t.Fatalf("generated config missing: %v", err)
	}
	if strings.Contains(string(emitted), "/etc/beelzebub/auth.token") {
		t.Fatal("credential reference must never be carried into emitted config")
	}
}

func TestMigrateExampleFixturesRoundTrip(t *testing.T) {
	for _, name := range []string{"beelzebub-http.yaml", "beelzebub-mcp.yaml"} {
		t.Run(name, func(t *testing.T) {
			src := filepath.Join("..", "migrate", "beelzebub", "testdata", "example", name)
			if _, err := os.Stat(src); err != nil {
				t.Skipf("fixture unavailable: %v", err)
			}
			outDir := t.TempDir()
			code, out, stderr := run(t, "migrate", "beelzebub", src, "--out", outDir, "--write")
			if code != 0 {
				t.Fatalf("example fixture must migrate cleanly: %s%s", out, stderr)
			}
			generated := filepath.Join(outDir, strings.TrimSuffix(name, ".yaml")+".aegismesh.yaml")
			code, _, stderr = run(t, "validate", "--config", generated)
			if code != 0 {
				t.Fatalf("emitted config must pass strict validation: %s", stderr)
			}
		})
	}
}
