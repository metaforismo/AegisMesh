package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const minimalValid = `
api_version: aegismesh.io/v1alpha1
sensors:
  - id: http-one
    kind: http
    listen: "127.0.0.1:8081"
    rules:
      - name: catch-all
        path_regex: "^/.*$"
        status: 404
        body: "nope"
`

func TestLoadMinimalValid(t *testing.T) {
	p := writeTemp(t, "mesh.yaml", minimalValid)
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.Sensors) != 1 || c.Sensors[0].ID != "http-one" {
		t.Fatalf("unexpected sensors: %+v", c.Sensors)
	}
	if c.Runtime.DataDir != filepath.Join(filepath.Dir(p), "data") {
		t.Fatalf("data_dir should resolve relative to config dir, got %q", c.Runtime.DataDir)
	}
	if !c.Admin.IsEnabled() {
		t.Fatal("admin should default to enabled")
	}
	if c.LLM.Provider != "local" {
		t.Fatalf("llm provider default = %q", c.LLM.Provider)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	p := writeTemp(t, "mesh.yaml", minimalValid+"\nnot_a_field: true\n")
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for unknown field")
	} else if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("error should mention unknown field: %v", err)
	}
}

func TestValidateTable(t *testing.T) {
	cases := []struct {
		name    string
		mutator func(*Config)
		wantSub string
	}{
		{"bad api_version", func(c *Config) { c.APIVersion = "x" }, "api_version"},
		{"no sensors", func(c *Config) { c.Sensors = nil }, "at least one sensor"},
		{"dup ids", func(c *Config) {
			c.Sensors = append(c.Sensors, c.Sensors[0])
		}, "duplicates"},
		{"bad kind", func(c *Config) { c.Sensors[0].Kind = "grpc" }, "http|tcp|mcp"},
		{"public bind", func(c *Config) { c.Sensors[0].Listen = "0.0.0.0:8081" }, "allow_public_bind"},
		{"privileged port", func(c *Config) { c.Sensors[0].Listen = "127.0.0.1:80" }, "allow_privileged_ports"},
		{"admin not loopback", func(c *Config) {
			on := true
			c.Security.AllowPublicBind = true
			c.Admin.Listen = "192.168.1.5:9999"
			c.Admin.Enabled = &on
		}, "must stay on loopback"},
		{"admin privileged", func(c *Config) { c.Admin.Listen = "127.0.0.1:80" }, "privileged"},
		{"bad log level", func(c *Config) { c.Logging.Level = "loud" }, "logging.level"},
		{"zero retention", func(c *Config) { c.Storage.Retention.MaxEvents = 0 }, "max_events"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeTemp(t, "mesh.yaml", minimalValid)
			c, err := Load(p)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutator(c)
			err = c.Validate()
			if err == nil {
				t.Fatalf("expected validation failure containing %q", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err, tc.wantSub)
			}
		})
	}
}

func TestPublicBindAllowedWithOptIn(t *testing.T) {
	doc := strings.Replace(minimalValid, `"127.0.0.1:8081"`, `"10.0.0.5:18081"`, 1)
	doc = strings.Replace(doc, "sensors:", "security:\n  allow_public_bind: true\nsensors:", 1)
	p := writeTemp(t, "mesh.yaml", doc)
	if _, err := Load(p); err != nil {
		t.Fatalf("explicit public bind should validate: %v", err)
	}
}

func TestHTTPRuleValidation(t *testing.T) {
	base := func(rule string) string {
		return `
api_version: aegismesh.io/v1alpha1
sensors:
  - id: h1
    kind: http
    listen: "127.0.0.1:8081"
    rules:
      - ` + rule
	}
	cases := map[string]string{
		"missing status":   `path_regex: "^/"`,
		"bad regex":        `path_regex: "(unclosed"` + "\n        status: 200",
		"long regex":       `path_regex: "` + strings.Repeat("a", 300) + `"` + "\n        status: 200",
		"both bodies":      `path_regex: "^/"` + "\n        status: 200\n        body: \"x\"\n        body_file: \"y.html\"",
		"body traversal":   `path_regex: "^/"` + "\n        status: 200\n        body_file: \"../../etc/passwd\"",
		"body absolute":    `path_regex: "^/"` + "\n        status: 200\n        body_file: \"/etc/passwd\"",
		"oversize body":    `path_regex: "^/"` + "\n        status: 200\n        body: \"" + strings.Repeat("x", MaxHTTPBodyBytes+1) + "\"",
		"too many headers": `path_regex: "^/"` + "\n        status: 200\n        headers: " + headersJSON(MaxHeaderCount+1),
	}
	for name, rule := range cases {
		t.Run(name, func(t *testing.T) {
			p := writeTemp(t, "mesh.yaml", base(rule))
			if _, err := Load(p); err == nil {
				t.Fatalf("expected failure for case %s", name)
			}
		})
	}
}

func headersJSON(n int) string {
	var sb strings.Builder
	sb.WriteString("{")
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString("X-K" + strings.Repeat("a", i) + ": v")
	}
	sb.WriteString("}")
	return sb.String()
}

func TestResolveBodyFileContainment(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "mesh.yaml")
	bodyPath := filepath.Join(dir, "pages", "ok.html")
	os.MkdirAll(filepath.Join(dir, "pages"), 0o755)
	os.WriteFile(cfgPath, []byte(minimalValid), 0o600)
	os.WriteFile(bodyPath, []byte("<html>fine</html>"), 0o600)

	c, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.ResolveBodyFile("pages/ok.html")
	if err != nil || string(b) != "<html>fine</html>" {
		t.Fatalf("ResolveBodyFile: %v (%q)", err, b)
	}
	if _, err := c.ResolveBodyFile("../outside.html"); err == nil {
		t.Fatal("traversal outside config dir must fail")
	}
}

func TestCheckKindFields(t *testing.T) {
	raw := []byte(`
sensors:
  - id: t1
    kind: tcp
    listen: "127.0.0.1:7000"
    rules:
      - path_regex: "^/"
`)
	err := CheckKindFields(raw, ".yaml")
	if err == nil || !strings.Contains(err.Error(), "does not apply") {
		t.Fatalf("expected kind/field mismatch error, got %v", err)
	}
}

func TestEnvOverrides(t *testing.T) {
	p := writeTemp(t, "mesh.yaml", minimalValid)
	t.Setenv("AEGISMESH_DATA_DIR", "/tmp/am-env-data")
	t.Setenv("AEGISMESH_LOG_LEVEL", "debug")
	t.Setenv("AEGISMESH_ADMIN_ENABLED", "false")
	t.Setenv("AEGISMESH_ADMIN_LISTEN", "127.0.0.1:9999")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Runtime.DataDir != "/tmp/am-env-data" || c.Logging.Level != "debug" ||
		c.Admin.IsEnabled() || c.Admin.Listen != "127.0.0.1:9999" {
		t.Fatalf("env overrides not applied: %+v", c)
	}
	t.Setenv("AEGISMESH_ADMIN_ENABLED", "not-a-bool")
	if _, err := Load(p); err == nil {
		t.Fatal("invalid boolean override must fail")
	}
}

func TestLLMAPIKeyNeverFromFiles(t *testing.T) {
	doc := strings.Replace(minimalValid, "sensors:",
		"llm:\n  provider: local\n  api_key: sk-SHOULD-BE-REJECTED\nsensors:", 1)
	p := writeTemp(t, "mesh.yaml", doc)
	if _, err := Load(p); err == nil {
		t.Fatal("api_key in file must be rejected (unknown field), not silently accepted")
	}
}

func TestScaffoldRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	written, err := Scaffold(dir, false)
	if err != nil || len(written) != 2 {
		t.Fatalf("first scaffold: %v %v", written, err)
	}
	if _, err := Scaffold(dir, false); err == nil {
		t.Fatal("second scaffold without --force must refuse")
	}
	written2, err := Scaffold(dir, true)
	if err != nil || len(written2) != 2 {
		t.Fatalf("--force scaffold: %v %v", written2, err)
	}
	// The generated config itself must pass our own loader.
	if _, err := Load(filepath.Join(dir, "mesh.yaml")); err != nil {
		t.Fatalf("generated demo config must validate: %v", err)
	}
}
