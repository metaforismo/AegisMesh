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
		t.Fatalf("--json not pure JSON: %q", ob.String())
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
