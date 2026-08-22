package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/detect"
	"github.com/metaforismo/aegismesh/internal/rulecatalog"
)

func TestRulesListHumanIsDeterministicAndComplete(t *testing.T) {
	code1, out1, _ := run(t, "rules", "list")
	code2, out2, _ := run(t, "rules", "list")
	if code1 != 0 || code2 != 0 {
		t.Fatalf("exit codes: %d %d\n%s", code1, code2, out1)
	}
	if out1 != out2 {
		t.Fatal("two runs produced different output")
	}
	all := rulecatalog.All()
	for _, e := range all {
		if !strings.Contains(out1, e.ID) || !strings.Contains(out1, e.Summary) {
			t.Fatalf("entry %s missing from table:\n%s", e.ID, out1)
		}
	}
	if !strings.Contains(out1, "PI-001") || !strings.Contains(out1, "COR-004") {
		t.Fatalf("boundary entries missing:\n%s", out1)
	}
}

func TestRulesListJSONShapeStable(t *testing.T) {
	code, out, errOut := run(t, "rules", "list", "--json")
	if code != 0 {
		t.Fatalf("%s", errOut)
	}
	var rep struct {
		Rules []rulecatalog.Entry `json:"rules"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, out)
	}
	want := rulecatalog.All()
	if len(rep.Rules) != len(want) {
		t.Fatalf("got %d rules, want %d", len(rep.Rules), len(want))
	}
	for i := range want {
		if rep.Rules[i] != want[i] {
			t.Fatalf("rule %d drifted: %+v vs %+v", i, rep.Rules[i], want[i])
		}
	}
	// Signals must marshal without a severity key at all.
	raw, _ := json.Marshal(rep.Rules[len(rep.Rules)-1])
	if strings.Contains(string(raw), "severity") {
		t.Fatalf("signal entry leaked empty severity: %s", raw)
	}
}

func TestRulesListFamilyFilter(t *testing.T) {
	code, out, _ := run(t, "rules", "list", "--family", "correlation")
	if code != 0 {
		t.Fatal(out)
	}
	if strings.Contains(out, "PI-001") || !strings.Contains(out, "COR-001") {
		t.Fatalf("correlation filter wrong:\n%s", out)
	}
	var rep struct {
		Rules []rulecatalog.Entry `json:"rules"`
	}
	code, out, _ = run(t, "rules", "list", "--family", "detection", "--json")
	if code != 0 {
		t.Fatal(out)
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Rules) == 0 || len(rep.Rules) != len(detect.KnownRuleIDs()) {
		t.Fatalf("detection filter count wrong: %d", len(rep.Rules))
	}
	for _, r := range rep.Rules {
		if r.Family != rulecatalog.FamilyDetection {
			t.Fatalf("filter leaked %s: %+v", r.ID, r)
		}
	}
}

func TestRulesListRejectsBadFamilyAndArgs(t *testing.T) {
	cases := [][]string{
		{"rules"},
		{"rules", "explain"}, // lands in 4c; must not exist yet
		{"rules", "list", "--family", "all"},
		{"rules", "list", "--family", "Detection"},
		{"rules", "list", "extra"},
	}
	for _, args := range cases {
		code, _, errOut := run(t, args...)
		if code == 0 {
			t.Fatalf("%v must fail", args)
		}
		if errOut == "" {
			t.Fatalf("%v must print an error", args)
		}
	}
}

func TestRulesListCompletionRegistration(t *testing.T) {
	_, bashOut, _ := run(t, "completion", "bash")
	if !strings.Contains(bashOut, "rules") {
		t.Fatal("bash completion missing rules command")
	}
	_, zshOut, _ := run(t, "completion", "zsh")
	if !strings.Contains(zshOut, "rules") {
		t.Fatal("zsh completion missing rules command")
	}
}
