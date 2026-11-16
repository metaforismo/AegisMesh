package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func oidcConfig() Console {
	return (Console{OIDC: OIDC{
		Enabled: true, Issuer: "https://idp.example.invalid", ClientID: "console",
		RedirectURI: "http://127.0.0.1:9120/api/v1/auth/oidc/callback",
		RoleMapping: map[string]string{"readers": "viewer"},
	}}).WithDefaults()
}

func TestIdentityValidation(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Console)
	}{
		{"token disabled without OIDC", func(c *Console) {
			c.OIDC.Enabled = false
			b := false
			c.TokenLogin = &b
		}},
		{"issuer metadata", func(c *Console) { c.OIDC.Issuer = "https://169.254.169.254" }},
		{"issuer IPv6 metadata", func(c *Console) {
			c.OIDC.Issuer = "https://[fd00:ec2::254]"
			c.OIDC.AllowPrivateEgress = true
		}},
		{"issuer private", func(c *Console) { c.OIDC.Issuer = "https://10.0.0.1" }},
		{"issuer HTTP public", func(c *Console) { c.OIDC.Issuer = "http://idp.example.invalid" }},
		{"issuer secret", func(c *Console) { c.OIDC.Issuer = "https://user:secret@idp.example.invalid" }},
		{"issuer query", func(c *Console) { c.OIDC.Issuer += "?secret=x" }},
		{"redirect path", func(c *Console) { c.OIDC.RedirectURI = "http://127.0.0.1:9120/wrong" }},
		{"redirect TLS", func(c *Console) { c.OIDC.RedirectURI = "https://127.0.0.1:9120/api/v1/auth/oidc/callback" }},
		{"secret refs", func(c *Console) {
			c.OIDC.ClientSecretEnv = "SECRET"
			c.OIDC.ClientSecretFile = "secret"
		}},
		{"secret traversal", func(c *Console) { c.OIDC.ClientSecretFile = "../secret" }},
		{"secret env", func(c *Console) { c.OIDC.ClientSecretEnv = "bad name" }},
		{"role deny", func(c *Console) { c.OIDC.RoleMapping = nil }},
		{"role invalid", func(c *Console) { c.OIDC.RoleMapping = map[string]string{"x": "root"} }},
		{"disabled label too long", func(c *Console) {
			c.OIDC.Enabled = false
			c.OIDC.DisplayName = strings.Repeat("x", 65)
		}},
		{"disabled secret traversal", func(c *Console) {
			c.OIDC.Enabled = false
			c.OIDC.ClientSecretFile = "../secret"
		}},
		{"claim too long", func(c *Console) { c.OIDC.RoleClaim = strings.Repeat("x", 65) }},
		{"label too long", func(c *Console) { c.OIDC.DisplayName = strings.Repeat("x", 65) }},
		{"tenant traversal", func(c *Console) { c.Tenants = []string{"../escape"} }},
		{"tenant duplicate", func(c *Console) { c.Tenants = []string{"default", "default"} }},
		{"local undeclared", func(c *Console) { c.LocalTenant = "unknown" }},
		{"tenant mapping", func(c *Console) { c.OIDC.TenantMapping = map[string]string{"group": "unknown"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := oidcConfig()
			test.change(&c)
			if (&Config{Console: c}).ValidateConsole() == nil {
				t.Fatal("unsafe config accepted")
			}
		})
	}
	c := oidcConfig()
	if err := (&Config{Console: c}).ValidateConsole(); err != nil {
		t.Fatal(err)
	}
	c.OIDC.Issuer = "http://127.0.0.1:1234"
	if err := (&Config{Console: c}).ValidateConsole(); err != nil {
		t.Fatal(err)
	}
	c.OIDC.Issuer = "https://10.0.0.1"
	c.OIDC.AllowPrivateEgress = true
	if err := (&Config{Console: c}).ValidateConsole(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityStrictDecodeAndEnvironment(t *testing.T) {
	for _, body := range []string{
		`{"console":{"oidc":{"client_secret":"inline"}}}`,
		`{"console":{"oidc":{"typo":true}}}`,
		`{"console":{"operators":[{"tenants":["default"],"typo":1}]}}`,
	} {
		var c Config
		if strictJSON([]byte(body), &c) == nil {
			t.Fatal("unknown field accepted")
		}
	}
	values := map[string]string{
		"LOCAL_TENANT": "bravo", "TOKEN_LOGIN": "false", "TENANTS": `["default","bravo"]`,
		"OPERATORS":    `[{"name":"viewer","role":"viewer","tenants":["bravo"],"token_sha256":"digest"}]`,
		"OIDC_ENABLED": "true", "OIDC_DISPLAY_NAME": "Example", "OIDC_ISSUER": "https://idp.example.invalid",
		"OIDC_CLIENT_ID": "console", "OIDC_REDIRECT_URI": "http://127.0.0.1:9120/api/v1/auth/oidc/callback",
		"OIDC_CLIENT_SECRET_ENV": "SECRET_REF", "OIDC_CLIENT_SECRET_FILE": "",
		"OIDC_ROLE_CLAIM": "roles", "OIDC_NAME_CLAIM": "name", "OIDC_TENANT_CLAIM": "orgs",
		"OIDC_ALLOW_PRIVATE_EGRESS": "true", "OIDC_ROLE_MAPPING": `{"group":"analyst"}`,
		"OIDC_TENANT_MAPPING": `{"org":"bravo"}`,
	}
	for key, value := range values {
		t.Setenv("AEGISMESH_CONSOLE_"+key, value)
	}
	var c Config
	c.applyDefaults()
	if err := c.consoleEnv(); err != nil {
		t.Fatal(err)
	}
	if c.Console.TokenEnabled() || c.Console.LocalTenant != "bravo" || !c.Console.OIDC.Enabled ||
		c.Console.OIDC.RoleMapping["group"] != "analyst" || c.Console.Operators[0].Tenants[0] != "bravo" {
		t.Fatalf("overrides missing: %+v", c.Console)
	}
	for key := range values {
		t.Setenv("AEGISMESH_CONSOLE_"+key, "")
	}
}

func TestOIDCSecretReference(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{SourcePath: filepath.Join(dir, "mesh.yaml"), Console: oidcConfig()}
	cfg.Console.OIDC.ClientSecretFile = "secret"
	if err := os.WriteFile(filepath.Join(dir, "secret"), []byte(" synthetic-secret "), 0600); err != nil {
		t.Fatal(err)
	}
	value, err := cfg.ResolveOIDCSecret()
	if err != nil || value != "synthetic-secret" {
		t.Fatal("private reference failed", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secret"), []byte(strings.Repeat("s", 4096)+" "), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.ResolveOIDCSecret(); err == nil {
		t.Fatal("oversized file accepted after whitespace trimming")
	}
	if err := os.Chmod(filepath.Join(dir, "secret"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.ResolveOIDCSecret(); err == nil {
		t.Fatal("public file accepted")
	}
	cfg.Console.OIDC.ClientSecretFile = ""
	cfg.Console.OIDC.ClientSecretEnv = "TEST_OIDC_SECRET"
	t.Setenv("TEST_OIDC_SECRET", "synthetic-secret")
	if value, err := cfg.ResolveOIDCSecret(); err != nil || value != "synthetic-secret" {
		t.Fatal("env reference failed", err)
	}
	t.Setenv("TEST_OIDC_SECRET", strings.Repeat("s", 4097))
	if _, err := cfg.ResolveOIDCSecret(); err == nil {
		t.Fatal("oversized secret accepted")
	}
}

func TestTenantStateRootsCannotOverlapEvidence(t *testing.T) {
	cfg := &Config{SourcePath: filepath.Join(t.TempDir(), "mesh.yaml")}
	cfg.Runtime.DataDir = filepath.Join(filepath.Dir(cfg.SourcePath), "data")
	cfg.Console.Enabled = true
	for _, root := range []string{cfg.Runtime.DataDir, filepath.Dir(cfg.Runtime.DataDir)} {
		cfg.Console.StateDir = root
		if cfg.validateTenantState() == nil {
			t.Fatal("tenant migration could move authoritative evidence")
		}
	}
	cfg.Console.StateDir = "console-state"
	cfg.Fleet.Hub.Enabled = true
	cfg.Fleet.Hub.StateDir = "console-state/hub"
	if cfg.validateTenantState() == nil {
		t.Fatal("overlapping state roots accepted")
	}
	cfg.Fleet.Hub.StateDir = "hub-state"
	if err := cfg.validateTenantState(); err != nil {
		t.Fatal(err)
	}
}
