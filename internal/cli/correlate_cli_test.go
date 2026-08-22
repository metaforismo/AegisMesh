package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func correlationConfig(t *testing.T, section string) string {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "mesh.yaml")
	body := fmt.Sprintf(`api_version: aegismesh.io/v1alpha1
%s
sensors:
  - id: http-one
    kind: http
    listen: "127.0.0.1:0"
    rules:
      - name: catch-all
        path_regex: "^/.*$"
        status: 200
        body: "ok"
`, section)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

func TestDoctorCorrelationStates(t *testing.T) {
	cases := []struct {
		name    string
		section string
		want    []string
	}{
		{
			name:    "off by default",
			section: "",
			want:    []string{"[info] correlation", "off (default)"},
		},
		{
			name: "enabled shows resolved bounds",
			section: `correlation:
  enabled: true
  window_seconds: 300
  disabled_rules: ["COR-004"]`,
			want: []string{"[ ok ] correlation", "window=300s", "disabled_rules=COR-004"},
		},
		{
			name: "disabled_rules without enabled warns",
			section: `correlation:
  disabled_rules: ["COR-001"]`,
			want: []string{"[warn] correlation", "no effect"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, _ := run(t, "doctor", "--config", correlationConfig(t, tc.section))
			if code != 0 {
				t.Fatal(out)
			}
			for _, want := range tc.want {
				if !strings.Contains(out, want) {
					t.Fatalf("missing %q in:\n%s", want, out)
				}
			}
		})
	}
}

func TestValidateEffectiveIncludesCorrelation(t *testing.T) {
	cfgPath := correlationConfig(t, `correlation:
  enabled: true
  window_seconds: 120
  disabled_rules: ["COR-001"]`)
	code, out, _ := run(t, "validate", "--config", cfgPath, "--effective")
	if code != 0 {
		t.Fatal(out)
	}
	for _, want := range []string{
		"correlation: enabled", "window=120s", "per_source_events=64",
		"disabled: COR-001",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in effective output:\n%s", want, out)
		}
	}

	code, out, _ = run(t, "validate", "--config", cfgPath, "--effective", "--json")
	if code != 0 {
		t.Fatal(out)
	}
	var rep struct {
		Correlation struct {
			Enabled       bool `json:"enabled"`
			WindowSeconds int  `json:"window_seconds"`
		} `json:"correlation"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("invalid --json output: %v\n%s", err, out)
	}
	if !rep.Correlation.Enabled || rep.Correlation.WindowSeconds != 120 {
		t.Fatalf("resolved correlation wrong in JSON: %+v", rep.Correlation)
	}
}

func TestDoctorCorrelationJSONShape(t *testing.T) {
	code, out, _ := run(t, "doctor", "--config", correlationConfig(t, ""), "--json")
	if code != 0 {
		t.Fatal(out)
	}
	var rep struct {
		Checks []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"checks"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("invalid doctor --json output: %v\n%s", err, out)
	}
	for _, ch := range rep.Checks {
		if ch.Name == "correlation" && ch.Status == "info" {
			return
		}
	}
	t.Fatalf("doctor JSON missing correlation/info check: %+v", rep.Checks)
}
