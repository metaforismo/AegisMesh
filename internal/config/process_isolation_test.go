package config

import (
	"fmt"
	"strings"
	"testing"
)

func processIsolationYAML(field string) string {
	return fmt.Sprintf(`
api_version: aegismesh.io/v1alpha1
sensors:
  - id: http-one
    kind: http
    listen: "127.0.0.1:8081"
%s
    rules:
      - name: catch-all
        path_regex: "^/.*$"
        status: 404
        body: "nope"
`, field)
}

func processIsolationJSON(field string) string {
	return fmt.Sprintf(`{"api_version":"aegismesh.io/v1alpha1","sensors":[{"id":"http-one","kind":"http","listen":"127.0.0.1:8081"%s,"rules":[{"name":"catch-all","path_regex":"^/.*$","status":404,"body":"nope"}]}]}`, field)
}

func TestProcessIsolationValuesPreserveDefault(t *testing.T) {
	cases := []struct {
		name  string
		field string
		want  bool
	}{
		{name: "omitted", want: false},
		{name: "true", field: "    process_isolation: true", want: true},
		{name: "false", field: "    process_isolation: false", want: false},
	}
	for _, tc := range cases {
		t.Run("yaml/"+tc.name, func(t *testing.T) {
			c, err := Load(writeTemp(t, "mesh.yaml", processIsolationYAML(tc.field)))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := c.Sensors[0].ProcessIsolation; got != tc.want {
				t.Fatalf("process_isolation = %v, want %v", got, tc.want)
			}
		})
		t.Run("json/"+tc.name, func(t *testing.T) {
			field := ""
			if tc.field != "" {
				field = fmt.Sprintf(",\"process_isolation\":%t", tc.want)
			}
			c, err := Load(writeTemp(t, "mesh.json", processIsolationJSON(field)))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := c.Sensors[0].ProcessIsolation; got != tc.want {
				t.Fatalf("process_isolation = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestProcessIsolationRejectsInvalidValues(t *testing.T) {
	cases := []struct {
		name      string
		yamlField string
		jsonField string
	}{
		{name: "yaml wrong type", yamlField: `    process_isolation: "true"`},
		{name: "json wrong type", jsonField: `,"process_isolation":"true"`},
		{name: "yaml null", yamlField: "    process_isolation: null"},
		{name: "json null", jsonField: `,"process_isolation":null`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.yamlField != "" {
				_, err := Load(writeTemp(t, "mesh.yaml", processIsolationYAML(tc.yamlField)))
				if err == nil {
					t.Fatal("expected process_isolation type rejection")
				}
				return
			}
			_, err := Load(writeTemp(t, "mesh.json", processIsolationJSON(tc.jsonField)))
			if err == nil {
				t.Fatal("expected process_isolation type rejection")
			}
		})
	}
}

func TestProcessIsolationRejectsDuplicateKeys(t *testing.T) {
	yamlDoc := processIsolationYAML("    process_isolation: true\n    process_isolation: false")
	if _, err := Load(writeTemp(t, "mesh.yaml", yamlDoc)); err == nil || !strings.Contains(err.Error(), "process_isolation") {
		t.Fatalf("YAML duplicate error = %v, want process_isolation rejection", err)
	}

	jsonDoc := `{"api_version":"aegismesh.io/v1alpha1","sensors":[{"id":"http-one","kind":"http","listen":"127.0.0.1:8081","process_isolation":true,"process_isolation":false,"rules":[{"name":"catch-all","path_regex":"^/.*$","status":404}]}]}`
	if _, err := Load(writeTemp(t, "mesh.json", jsonDoc)); err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("JSON duplicate error = %v, want duplicate-key rejection", err)
	}
}

func TestProcessIsolationRejectsUnknownPlacement(t *testing.T) {
	for _, tc := range []struct {
		name string
		file string
		doc  string
	}{
		{name: "yaml root", file: "mesh.yaml", doc: processIsolationYAML("") + "process_isolation: true\n"},
		{name: "json root", file: "mesh.json", doc: `{"api_version":"aegismesh.io/v1alpha1","process_isolation":true,"sensors":[{"id":"http-one","kind":"http","listen":"127.0.0.1:8081","rules":[{"name":"catch-all","path_regex":"^/.*$","status":404}]}]}`},
		{name: "yaml rule", file: "mesh.yaml", doc: `
api_version: aegismesh.io/v1alpha1
sensors:
  - id: http-one
    kind: http
    listen: "127.0.0.1:8081"
    rules:
      - process_isolation: true
        path_regex: "^/.*$"
        status: 404
`},
		{name: "json rule", file: "mesh.json", doc: `{"api_version":"aegismesh.io/v1alpha1","sensors":[{"id":"http-one","kind":"http","listen":"127.0.0.1:8081","rules":[{"process_isolation":true,"path_regex":"^/.*$","status":404}]}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load(writeTemp(t, tc.file, tc.doc)); err == nil || !strings.Contains(err.Error(), "process_isolation") {
				t.Fatalf("Load error = %v, want unknown-placement rejection", err)
			}
		})
	}
}

func TestProcessIsolationIsCommonToEverySensorKind(t *testing.T) {
	for _, kind := range []string{SensorKindHTTP, SensorKindTCP, SensorKindMCP, SensorKindSSH} {
		raw := []byte(fmt.Sprintf("sensors:\n  - id: sensor-one\n    kind: %s\n    listen: \"127.0.0.1:8081\"\n    process_isolation: true\n", kind))
		if err := CheckKindFields(raw, ".yaml"); err != nil {
			t.Fatalf("kind=%s: process_isolation rejected as kind-specific field: %v", kind, err)
		}
	}
}

func TestProcessIsolationRejectsNonLocalHTTPFallback(t *testing.T) {
	for _, provider := range []string{"ollama", "openai"} {
		doc := strings.Replace(processIsolationYAML("    process_isolation: true"), "sensors:", fmt.Sprintf("llm:\n  provider: %s\n  base_url: https://llm.example.invalid/v1\n  model: synthetic\nsensors:", provider), 1)
		doc = strings.Replace(doc, "    rules:", "    fallback:\n      enabled: true\n      system_prompt: synthetic\n    rules:", 1)
		_, err := Load(writeTemp(t, "mesh.yaml", doc))
		if err == nil || !strings.Contains(err.Error(), "process_isolation") || !strings.Contains(err.Error(), "local") {
			t.Fatalf("provider=%s error = %v, want fail-closed local-provider error", provider, err)
		}
	}
}

func TestProcessIsolationAllowsLocalOrDisabledFallback(t *testing.T) {
	cases := []struct {
		name string
		doc  string
	}{
		{name: "default local", doc: processIsolationYAML("    process_isolation: true")},
		{name: "explicit local", doc: strings.Replace(processIsolationYAML("    process_isolation: true"), "sensors:", "llm:\n  provider: local\nsensors:", 1)},
		{name: "disabled fallback remote", doc: strings.Replace(strings.Replace(processIsolationYAML("    process_isolation: true"), "sensors:", "llm:\n  provider: openai\n  base_url: https://llm.example.invalid/v1\n  model: synthetic\nsensors:", 1), "    rules:", "    fallback:\n      enabled: false\n      system_prompt: synthetic\n    rules:", 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load(writeTemp(t, "mesh.yaml", tc.doc)); err != nil {
				t.Fatalf("Load: %v", err)
			}
		})
	}
}

func TestProcessIsolationRejectsHostnameListen(t *testing.T) {
	doc := strings.Replace(processIsolationYAML("    process_isolation: true"), "127.0.0.1:8081", "decoy.internal:8081", 1)
	doc = strings.Replace(doc, "sensors:", "security:\n  allow_public_bind: true\nsensors:", 1)
	_, err := Load(writeTemp(t, "mesh.yaml", doc))
	if err == nil || !strings.Contains(err.Error(), "without DNS") {
		t.Fatalf("Load error = %v, want DNS-free address validation error", err)
	}
}
