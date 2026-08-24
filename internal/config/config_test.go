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
		{"bad kind", func(c *Config) { c.Sensors[0].Kind = "grpc" }, "http|tcp|mcp|ssh"},
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
	outside := filepath.Join(t.TempDir(), "outside.html")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "pages", "escape.html")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := c.ResolveBodyFile("pages/escape.html"); err == nil || !strings.Contains(err.Error(), "within config directory") {
		t.Fatalf("symlink escape must fail closed, got %v", err)
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

func TestLLMProviderFieldsValidation(t *testing.T) {
	cases := []struct {
		name    string
		llmYAML string
		wantErr string
	}{
		{"ollama defaults base_url", "llm:\n  provider: ollama\n  model: llama3\nsensors:", ""},
		{"openai needs model", "llm:\n  provider: openai\n  base_url: https://api.example.com/v1\nsensors:", "llm.model"},
		{"openai needs base_url", "llm:\n  provider: openai\n  model: gpt\nsensors:", "llm.base_url"},
		{"unknown provider", "llm:\n  provider: claude\nsensors:", "local|ollama|openai"},
		{"api_key_env name shape", "llm:\n  provider: openai\n  base_url: https://x/v1\n  model: m\n  api_key_env: \"9bad\"\nsensors:", "environment variable NAME"},
		{"both secret refs", "llm:\n  provider: openai\n  base_url: https://x/v1\n  model: m\n  api_key_env: K1\n  api_key_file: key.txt\nsensors:", "not both"},
		{"timeout cap", "llm:\n  timeout_seconds: 9999\nsensors:", "timeout_seconds"},
		{"response cap", "llm:\n  max_response_bytes: 99999999999\nsensors:", "max_response_bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := strings.Replace(minimalValid, "sensors:", tc.llmYAML, 1)
			p := writeTemp(t, "mesh.yaml", doc)
			c, err := Load(p)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				if c.LLM.Provider == "ollama" && c.LLM.BaseURL != DefaultOllamaBaseURL {
					t.Fatalf("ollama default base_url = %q", c.LLM.BaseURL)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestResolveAPIKeyPrecedenceAndRefs(t *testing.T) {
	doc := strings.Replace(minimalValid, "sensors:",
		"llm:\n  provider: openai\n  base_url: https://x/v1\n  model: m\n  api_key_file: key.txt\nsensors:", 1)
	p := writeTemp(t, "mesh.yaml", doc)
	keyFile := filepath.Join(filepath.Dir(p), "key.txt")
	if err := os.WriteFile(keyFile, []byte("  file-secret-123 \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, err := c.ResolveAPIKey()
	if err != nil || got != "file-secret-123" {
		t.Fatalf("file ref resolve = %q, %v", got, err)
	}

	// env var named by api_key_env beats nothing else configured; empty var fails loudly.
	c2, _ := Load(writeTemp(t, "mesh2.yaml", strings.Replace(minimalValid, "sensors:",
		"llm:\n  provider: openai\n  base_url: https://x/v1\n  model: m\n  api_key_env: AEGIS_TEST_KEY\nsensors:", 1)))
	if _, err := c2.ResolveAPIKey(); err == nil || !strings.Contains(err.Error(), "empty or unset") {
		t.Fatalf("unset env ref = %v", err)
	}
	t.Setenv("AEGIS_TEST_KEY", "env-secret")
	if got, err := c2.ResolveAPIKey(); err != nil || got != "env-secret" {
		t.Fatalf("env ref = %q, %v", got, err)
	}

	// legacy direct override wins over the reference.
	c2.LLM.APIKey = "legacy-wins"
	if got, _ := c2.ResolveAPIKey(); got != "legacy-wins" {
		t.Fatalf("legacy override lost: %q", got)
	}

	// traversal outside the config directory is refused at load time.
	c3err := writeTemp(t, "mesh3.yaml", strings.Replace(minimalValid, "sensors:",
		"llm:\n  api_key_file: ../../etc/passwd\nsensors:", 1))
	if _, err := Load(c3err); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("traversal ref = %v", err)
	}
}

func TestDetectionSectionValidation(t *testing.T) {
	bad := writeTemp(t, "mesh.yaml", strings.Replace(minimalValid, "sensors:",
		"detection:\n  disabled_rules: [\"NOPE-1\"]\nsensors:", 1))
	if _, err := Load(bad); err == nil || !strings.Contains(err.Error(), "NOPE-1") {
		t.Fatalf("unknown disabled rule must fail with id in message: %v", err)
	}
	cap := writeTemp(t, "mesh.yaml", strings.Replace(minimalValid, "sensors:",
		"detection:\n  max_input_bytes: 100000000\nsensors:", 1))
	if _, err := Load(cap); err == nil || !strings.Contains(err.Error(), "max_input_bytes") {
		t.Fatalf("oversized max_input_bytes must fail: %v", err)
	}
	ok := writeTemp(t, "mesh.yaml", strings.Replace(minimalValid, "sensors:",
		"detection:\n  enabled: false\n  disabled_rules: [\"OBS-001\"]\nsensors:", 1))
	c, err := Load(ok)
	if err != nil {
		t.Fatalf("valid detection section rejected: %v", err)
	}
	if c.Detection.IsEnabled() {
		t.Fatal("enabled: false must be honored")
	}
	if !c.Detection.IsEnabled() && c.Detection.MaxInputBytes != DefaultDetectionMaxLen {
		t.Fatalf("default max_input_bytes = %d", c.Detection.MaxInputBytes)
	}
}

func TestMCPResourcesAndPromptsValidation(t *testing.T) {
	base := `
api_version: aegismesh.io/v1alpha1
sensors:
  - id: mcp-one
    kind: mcp
    listen: "127.0.0.1:8099"
    tools:
      - name: canary
        description: d
        result_json: '{"ok":true}'
`
	goodRes := base + "    resources:\n      - uri: decoy://db/users\n        name: users\n        text: hello\n"
	c, err := Load(writeTemp(t, "mesh.yaml", goodRes))
	if err != nil {
		t.Fatalf("valid resource rejected: %v", err)
	}
	if len(c.Sensors[0].Resources) != 1 || c.Sensors[0].Resources[0].URI != "decoy://db/users" {
		t.Fatalf("resource not loaded: %+v", c.Sensors[0].Resources)
	}
	cases := map[string]string{
		"bad uri":         base + "    resources:\n      - uri: \"no scheme\"\n        name: n\n        text: t\n",
		"dup uri":         base + "    resources:\n      - uri: decoy://a\n        name: n1\n        text: t\n      - uri: decoy://a\n        name: n2\n        text: t\n",
		"missing text":    base + "    resources:\n      - uri: decoy://a\n        name: n\n",
		"prompt no msg":   base + "    prompts:\n      - name: p1\n",
		"dup prompt":      base + "    prompts:\n      - name: p1\n        messages: [\"hi\"]\n      - name: p1\n        messages: [\"ho\"]\n",
		"bad arg name":    base + "    prompts:\n      - name: p1\n        arguments: [{name: \"-bad\"}]\n        messages: [\"hi\"]\n",
		"too many msgs":   base + "    prompts:\n      - name: p1\n        messages: [\"1\",\"2\",\"3\",\"4\",\"5\",\"6\",\"7\",\"8\",\"9\"]\n",
		"kind field leak": base + "    banner: nope\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeTemp(t, "mesh.yaml", doc)); err == nil {
				t.Fatalf("%s: expected rejection", name)
			}
		})
	}
	validPrompt := base + "    prompts:\n      - name: triage\n        description: synthetic intake script\n        arguments: [{name: host, required: true}]\n        messages: [\"Triaging {host} now.\"]\n"
	if _, err := Load(writeTemp(t, "mesh.yaml", validPrompt)); err != nil {
		t.Fatalf("valid prompt rejected: %v", err)
	}
}

func TestExtensionsSectionValidation(t *testing.T) {
	cases := []struct {
		name    string
		snippet string
		wantErr string // empty = must load
	}{
		{
			name: "disabled empty section is fine",
		},
		{
			name:    "enabled without manifests",
			snippet: "extensions:\n  enabled: true\n",
			wantErr: "at least one extensions.manifests entry",
		},
		{
			name:    "too many manifests",
			snippet: "extensions:\n  enabled: true\n  manifests: [a, b, c, d, e]\n",
			wantErr: "at most 4 extensions",
		},
		{
			name:    "duplicate manifest paths",
			snippet: "extensions:\n  enabled: true\n  manifests: [same.json, same.json]\n",
			wantErr: "duplicated",
		},
		{
			name:    "empty manifest path",
			snippet: "extensions:\n  enabled: true\n  manifests: [\"\"]\n",
			wantErr: "non-empty paths",
		},
		{
			name:    "padded manifest path",
			snippet: "extensions:\n  enabled: true\n  manifests: [\" observer.json \"]\n",
			wantErr: "surrounding whitespace",
		},
		{
			name:    "absolute manifest path",
			snippet: "extensions:\n  enabled: true\n  manifests: [/tmp/observer.json]\n",
			wantErr: "relative to the config file directory",
		},
		{
			name:    "traversing manifest path",
			snippet: "extensions:\n  enabled: true\n  manifests: [../observer.json]\n",
			wantErr: "must not traverse",
		},
		{
			name:    "normalized duplicate manifest paths",
			snippet: "extensions:\n  enabled: true\n  manifests: [observer.json, sub/../observer.json]\n",
			wantErr: "duplicated",
		},
		{
			name:    "queue size out of bounds",
			snippet: "extensions:\n  enabled: true\n  manifests: [m.json]\n  queue_size: 3\n",
			wantErr: "queue_size",
		},
		{
			name:    "flush seconds out of bounds",
			snippet: "extensions:\n  enabled: true\n  manifests: [m.json]\n  shutdown_flush_seconds: 60\n",
			wantErr: "shutdown_flush_seconds",
		},
		{
			name:    "malformed pubkey hex",
			snippet: "extensions:\n  enabled: true\n  manifests: [m.json]\n  ed25519_pubkey_hex: zznothex\n",
			wantErr: "ed25519_pubkey_hex",
		},
		{
			name:    "wrong pubkey length",
			snippet: "extensions:\n  enabled: true\n  manifests: [m.json]\n  ed25519_pubkey_hex: aabb\n",
			wantErr: "ed25519_pubkey_hex",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := minimalValid
			if tc.snippet != "" {
				raw = strings.Replace(minimalValid, "sensors:", tc.snippet+"sensors:", 1)
			}
			c, err := Load(writeTemp(t, "mesh.yaml", raw))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected success, got: %v", err)
				}
				if c.Extensions.IsEnabled() {
					t.Fatal("section absent must default to disabled")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}

	// Valid section loads with defaults applied.
	ok := writeTemp(t, "mesh.yaml", strings.Replace(minimalValid, "sensors:",
		"extensions:\n  enabled: true\n  manifests: [observer.json]\nsensors:", 1))
	c, err := Load(ok)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Extensions.IsEnabled() || c.Extensions.QueueSize != DefaultExtensionQueueSize ||
		c.Extensions.ShutdownFlushSeconds != DefaultExtensionFlushSecs {
		t.Fatalf("defaults wrong: %+v", c.Extensions)
	}
}

func TestExtensionBounds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		queue int
		flush int
		ok    bool
	}{
		{name: "queue minimum", queue: MinExtensionQueueSize, flush: DefaultExtensionFlushSecs, ok: true},
		{name: "queue below minimum", queue: MinExtensionQueueSize - 1, flush: DefaultExtensionFlushSecs},
		{name: "queue maximum", queue: MaxExtensionQueueSize, flush: DefaultExtensionFlushSecs, ok: true},
		{name: "queue above maximum", queue: MaxExtensionQueueSize + 1, flush: DefaultExtensionFlushSecs},
		{name: "flush minimum", queue: DefaultExtensionQueueSize, flush: MinExtensionFlushSecs, ok: true},
		{name: "flush zero uses default", queue: DefaultExtensionQueueSize, flush: 0, ok: true},
		{name: "flush negative", queue: DefaultExtensionQueueSize, flush: -1},
		{name: "flush maximum", queue: DefaultExtensionQueueSize, flush: MaxExtensionFlushSecs, ok: true},
		{name: "flush above maximum", queue: DefaultExtensionQueueSize, flush: MaxExtensionFlushSecs + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enabled := true
			err := ValidateExtensions(Extensions{
				Enabled:              &enabled,
				Manifests:            []string{"observer.json"},
				QueueSize:            tc.queue,
				ShutdownFlushSeconds: tc.flush,
			})
			if tc.ok && err != nil {
				t.Fatalf("expected valid bounds: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected invalid bounds")
			}
		})
	}
}

func TestResolveExtensionManifestPathContained(t *testing.T) {
	base := t.TempDir()
	manifest := filepath.Join(base, "observer.json")
	if err := os.WriteFile(manifest, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := Config{SourcePath: filepath.Join(base, "mesh.yaml")}
	got, err := c.ResolveExtensionManifestPath("observer.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "escape.json")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ResolveExtensionManifestPath("escape.json"); err == nil || !strings.Contains(err.Error(), "outside the config directory") {
		t.Fatalf("symlink escape must fail closed, got %v", err)
	}
}

func TestWebhookSectionValidation(t *testing.T) {
	cases := []struct {
		name    string
		snippet string
		wantErr string // empty = must load
	}{
		{
			name: "disabled empty section is fine",
		},
		{
			name:    "enabled without url",
			snippet: "webhook:\n  enabled: true\n",
			wantErr: "requires webhook.url",
		},
		{
			name:    "metadata endpoint permanently denied",
			snippet: "webhook:\n  enabled: true\n  url: \"http://169.254.169.254/latest\"\n  allow_loopback_http: false\n",
			wantErr: "webhook.url",
		},
		{
			name:    "cleartext http to public host denied",
			snippet: "webhook:\n  enabled: true\n  url: \"http://collector.example.com/events\"\n",
			wantErr: "webhook.url",
		},
		{
			name:    "private range denied without opt-in",
			snippet: "webhook:\n  enabled: true\n  url: \"https://10.0.0.9/events\"\n",
			wantErr: "webhook.url",
		},
		{
			name: "private range allowed with explicit opt-in",
			snippet: "security:\n  allow_private_llm_egress: true\n" +
				"webhook:\n  enabled: true\n  url: \"https://10.0.0.9/events\"\n",
		},
		{
			name:    "loopback cleartext denied without dev opt-in",
			snippet: "webhook:\n  enabled: true\n  url: \"http://127.0.0.1:9999/events\"\n",
			wantErr: "webhook.url",
		},
		{
			name:    "loopback cleartext allowed with dev opt-in",
			snippet: "webhook:\n  enabled: true\n  url: \"http://127.0.0.1:9999/events\"\n  allow_loopback_http: true\n",
		},
		{
			name: "valid https destination loads",
			snippet: "webhook:\n  enabled: true\n  url: \"https://collector.example.com/v1/events\"\n" +
				"  hmac_secret_env: WEBHOOK_HMAC\n",
		},
		{
			name:    "both secret references set",
			snippet: "webhook:\n  enabled: true\n  url: \"https://c.example.com/e\"\n  hmac_secret_env: A\n  hmac_secret_file: s.key\n",
			wantErr: "not both",
		},
		{
			name:    "malformed env name",
			snippet: "webhook:\n  enabled: true\n  url: \"https://c.example.com/e\"\n  hmac_secret_env: not-a-name\n",
			wantErr: "environment variable NAME",
		},
		{
			name:    "traversal file path",
			snippet: "webhook:\n  enabled: true\n  url: \"https://c.example.com/e\"\n  hmac_secret_file: ../secrets/key\n",
			wantErr: "hmac_secret_file",
		},
		{
			name:    "queue size out of bounds",
			snippet: "webhook:\n  enabled: true\n  url: \"https://c.example.com/e\"\n  queue_size: 3\n",
			wantErr: "queue_size",
		},
		{
			name:    "batch size out of bounds",
			snippet: "webhook:\n  enabled: true\n  url: \"https://c.example.com/e\"\n  batch_size: 100000\n",
			wantErr: "batch_size",
		},
		{
			name:    "flush interval out of bounds",
			snippet: "webhook:\n  enabled: true\n  url: \"https://c.example.com/e\"\n  flush_interval_seconds: 3600\n",
			wantErr: "flush_interval_seconds",
		},
		{
			name:    "timeout out of bounds",
			snippet: "webhook:\n  enabled: true\n  url: \"https://c.example.com/e\"\n  timeout_seconds: 0\n",
			wantErr: "",
		}, // 0 = default, applied before validation; see defaults assertion below
		{
			name:    "retries out of bounds",
			snippet: "webhook:\n  enabled: true\n  url: \"https://c.example.com/e\"\n  max_retries: 99\n",
			wantErr: "max_retries",
		},
		{
			name:    "disabled section still validates a present url",
			snippet: "webhook:\n  url: \"http://169.254.169.254/x\"\n",
			wantErr: "webhook.url",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := minimalValid
			if tc.snippet != "" {
				raw = strings.Replace(minimalValid, "sensors:", tc.snippet+"sensors:", 1)
			}
			_, err := Load(writeTemp(t, "mesh.yaml", raw))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected success, got: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}

	// Defaults applied when enabled with only a URL.
	ok := writeTemp(t, "mesh.yaml", strings.Replace(minimalValid, "sensors:",
		"webhook:\n  enabled: true\n  url: \"https://collector.example.com/v1/events\"\nsensors:", 1))
	c, err := Load(ok)
	if err != nil {
		t.Fatal(err)
	}
	w := c.Webhook
	if !w.IsEnabled() || w.QueueSize != DefaultWebhookQueueSize || w.BatchSize != DefaultWebhookBatchSize ||
		w.FlushIntervalSeconds != DefaultWebhookFlushSecs || w.TimeoutSeconds != DefaultWebhookTimeoutSecs ||
		w.MaxRetries != DefaultWebhookMaxRetries {
		t.Fatalf("defaults wrong: %+v", w)
	}
}

func TestResolveWebhookSecretPrecedenceAndRefs(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "mesh.yaml")
	base := strings.Replace(minimalValid, "sensors:",
		"webhook:\n  enabled: true\n  url: \"https://c.example.com/e\"\nsensors:", 1)

	// No reference configured: empty secret, no error (doctor reports it).
	os.WriteFile(cfgPath, []byte(base), 0o600)
	c, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := c.ResolveWebhookSecret(); err != nil || v != "" {
		t.Fatalf("no-ref case: v=%q err=%v", v, err)
	}

	// Env reference wins and must be non-empty.
	os.Setenv("AEGISMESH_TEST_WEBHOOK_HMAC", "synthetic-secret")
	defer os.Unsetenv("AEGISMESH_TEST_WEBHOOK_HMAC")
	doc := strings.Replace(base, "url:", "hmac_secret_env: AEGISMESH_TEST_WEBHOOK_HMAC\n  url:", 1)
	os.WriteFile(cfgPath, []byte(doc), 0o600)
	c, _ = Load(cfgPath)
	v, err := c.ResolveWebhookSecret()
	if err != nil || v == "" {
		t.Fatalf("env ref: v=%q err=%v", v, err)
	}

	// File reference works and enforces containment.
	os.Setenv("AEGISMESH_TEST_WEBHOOK_HMAC", "")
	keyPath := filepath.Join(dir, "wh.key")
	os.WriteFile(keyPath, []byte("file-secret-value"), 0o600)
	doc = strings.Replace(base, "url:", "hmac_secret_file: ./wh.key\n  url:", 1)
	os.WriteFile(cfgPath, []byte(doc), 0o600)
	c, _ = Load(cfgPath)
	v, err = c.ResolveWebhookSecret()
	if err != nil || v != "file-secret-value" {
		t.Fatalf("file ref: v=%q err=%v", v, err)
	}

	// Empty env value is an actionable error, never silent.
	doc = strings.Replace(base, "url:", "hmac_secret_env: AEGISMESH_TEST_WEBHOOK_HMAC\n  url:", 1)
	os.WriteFile(cfgPath, []byte(doc), 0o600)
	c, _ = Load(cfgPath)
	if _, err := c.ResolveWebhookSecret(); err == nil || !strings.Contains(err.Error(), "empty or unset") {
		t.Fatalf("empty env must fail loudly: %v", err)
	}
}
