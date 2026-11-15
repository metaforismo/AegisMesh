package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func fleetConfig(t *testing.T, fleet string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mesh.yaml")
	raw := `api_version: aegismesh.io/v1alpha1
runtime:
  instance_name: test-node
  data_dir: data
admin:
  enabled: false
sensors:
  - id: web
    kind: http
    listen: 127.0.0.1:0
    rules:
      - name: root
        path_regex: ^/$
        status: 200
        body: synthetic
` + fleet
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func TestFleetDefaultsAndValidation(t *testing.T) {
	cfg, err := fleetConfig(t, "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Fleet.Hub.Enabled || cfg.Fleet.Agent.Enabled || cfg.Fleet.Hub.Listen != "127.0.0.1:9130" ||
		cfg.Fleet.Agent.HeartbeatIntervalSeconds != 30 || cfg.FleetNodeName() != "test-node" ||
		cfg.FleetStateDir(true) == cfg.FleetStateDir(false) {
		t.Fatalf("defaults: %+v", cfg.Fleet)
	}
	for _, test := range []struct {
		name   string
		mutate func(*Config)
		ok     bool
	}{
		{
			name:   "loopback hub",
			ok:     true,
			mutate: func(c *Config) { c.Fleet.Hub.Enabled = true },
		},
		{
			name: "TLS required",
			mutate: func(c *Config) {
				c.Fleet.Hub.Enabled = true
				c.Fleet.Hub.Listen = "0.0.0.0:9130"
				c.Security.AllowPublicBind = true
			},
		},
		{
			name: "public opt-in required",
			mutate: func(c *Config) {
				c.Fleet.Hub.Enabled = true
				c.Fleet.Hub.Listen = "0.0.0.0:9130"
				c.Fleet.Hub.TLSCertFile = "cert.pem"
				c.Fleet.Hub.TLSKeyFile = "key.pem"
			},
		},
		{
			name: "public TLS",
			ok:   true,
			mutate: func(c *Config) {
				c.Fleet.Hub.Enabled = true
				c.Fleet.Hub.Listen = "0.0.0.0:9130"
				c.Security.AllowPublicBind = true
				c.Fleet.Hub.TLSCertFile = "cert.pem"
				c.Fleet.Hub.TLSKeyFile = "key.pem"
			},
		},
		{
			name:   "TLS pair",
			mutate: func(c *Config) { c.Fleet.Hub.TLSCertFile = "cert.pem" },
		},
		{
			name:   "interval low",
			mutate: func(c *Config) { c.Fleet.Agent.HeartbeatIntervalSeconds = 9 },
		},
		{
			name:   "interval high",
			mutate: func(c *Config) { c.Fleet.Agent.HeartbeatIntervalSeconds = 301 },
		},
		{
			name:   "bad name",
			mutate: func(c *Config) { c.Fleet.Agent.NodeName = "unsafe/name" },
		},
		{
			name:   "inline unknown",
			mutate: func(c *Config) { c.Fleet.Agent.EnrollmentTokenEnv = "bad name" },
		},
		{
			name: "two references",
			mutate: func(c *Config) {
				c.Fleet.Agent.EnrollmentTokenEnv = "TOKEN"
				c.Fleet.Agent.EnrollmentTokenFile = "token"
			},
		},
		{
			name:   "token traversal",
			mutate: func(c *Config) { c.Fleet.Agent.EnrollmentTokenFile = "../token" },
		},
		{
			name:   "absolute token",
			mutate: func(c *Config) { c.Fleet.Agent.EnrollmentTokenFile = "/tmp/token" },
		},
		{
			name: "state collision",
			mutate: func(c *Config) {
				c.Fleet.Hub.Enabled = true
				c.Fleet.Hub.StateDir = "same"
				c.Fleet.Agent.StateDir = "same"
			},
		},
		{
			name: "combined roles",
			mutate: func(c *Config) {
				c.Fleet.Hub.Enabled = true
				c.Fleet.Agent.Enabled = true
				c.Fleet.Agent.HubURL = "http://127.0.0.1:9130"
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := *cfg
			test.mutate(&copy)
			if err := copy.Validate(); (err == nil) != test.ok {
				t.Fatalf("validation: %v; ok=%t", err, test.ok)
			}
		})
	}
	for _, endpoint := range []struct {
		url          string
		allowPrivate bool
		ok           bool
	}{
		{
			url: "http://127.0.0.1:9130",
			ok:  true,
		},
		{
			url: "http://localhost:9130",
			ok:  true,
		},
		{
			url: "https://example.com",
			ok:  true,
		},
		{
			url:          "https://10.0.0.1",
			allowPrivate: true,
			ok:           true,
		},
		{url: "https://10.0.0.1"},
		{
			url:          "http://10.0.0.1",
			allowPrivate: true,
		},
		{url: "http://example.com"},
		{
			url:          "https://169.254.169.254",
			allowPrivate: true,
		},
		{
			url:          "https://[fe80::1]",
			allowPrivate: true,
		},
		{url: "https://example.com/path"},
		{url: "https://example.com?"},
	} {
		t.Run(endpoint.url, func(t *testing.T) {
			copy := *cfg
			copy.Fleet.Agent.Enabled = true
			copy.Fleet.Agent.HubURL = endpoint.url
			copy.Fleet.Agent.AllowPrivateEgress = endpoint.allowPrivate
			if err := copy.Validate(); (err == nil) != endpoint.ok {
				t.Fatalf("egress: %v; ok=%t", err, endpoint.ok)
			}
		})
	}
}

func TestFleetEveryFieldStrictDecodingAndEnv(t *testing.T) {
	section := `fleet:
  hub:
    enabled: false
    listen: 127.0.0.1:9138
    state_dir: hub-state
    tls_cert_file: cert.pem
    tls_key_file: key.pem
  agent:
    enabled: true
    hub_url: https://10.0.0.1:9130
    state_dir: agent-state
    node_name: another-node
    enrollment_token_file: enrollment.token
    enrollment_token_env: ""
    hub_ca_file: ca.pem
    allow_private_egress: true
    heartbeat_interval_seconds: 60
`
	cfg, err := fleetConfig(t, section)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Fleet.Agent.NodeName != "another-node" || cfg.Fleet.Agent.HeartbeatIntervalSeconds != 60 ||
		!filepath.IsAbs(cfg.Fleet.Hub.TLSKeyFile) || !filepath.IsAbs(cfg.Fleet.Agent.HubCAFile) ||
		filepath.Base(cfg.FleetStateDir(true)) != "agent-state" || filepath.Base(cfg.FleetStateDir(false)) != "hub-state" {
		t.Fatalf("resolution: %+v", cfg.Fleet)
	}
	for _, role := range []string{"hub", "agent"} {
		if _, err := fleetConfig(t, "fleet:\n  "+role+":\n    unknown: true\n"); err == nil {
			t.Fatal("accepted unknown fleet field")
		}
	}
	if _, err := fleetConfig(t, "fleet:\n  agent:\n    enrollment_token: never-inline\n"); err == nil {
		t.Fatal("accepted inline token")
	}
	// Each field has one deterministic override using its full path, including reference names only.
	overrides := map[string]string{
		"HUB_ENABLED":                      "false",
		"HUB_LISTEN":                       "127.0.0.1:9140",
		"HUB_STATE_DIR":                    "other-hub",
		"HUB_TLS_CERT_FILE":                "other-cert.pem",
		"HUB_TLS_KEY_FILE":                 "other-key.pem",
		"AGENT_ENABLED":                    "true",
		"AGENT_HUB_URL":                    "https://10.0.0.2:9130",
		"AGENT_STATE_DIR":                  "other-agent",
		"AGENT_NODE_NAME":                  "env-node",
		"AGENT_ENROLLMENT_TOKEN_FILE":      "",
		"AGENT_ENROLLMENT_TOKEN_ENV":       "SYNTHETIC_TOKEN",
		"AGENT_HUB_CA_FILE":                "other-ca.pem",
		"AGENT_ALLOW_PRIVATE_EGRESS":       "true",
		"AGENT_HEARTBEAT_INTERVAL_SECONDS": "120",
	}
	for name, value := range overrides {
		t.Setenv("AEGISMESH_FLEET_"+name, value)
	}
	cfg, err = fleetConfig(t, section)
	if err != nil {
		t.Fatal(err)
	}
	// Reflection asserts complete override coverage, so newly added fields require an explicit fixture.
	encoded, _ := json.Marshal(cfg.Fleet)
	var roles map[string]map[string]any
	if err := json.Unmarshal(encoded, &roles); err != nil {
		t.Fatal(err)
	}
	count := 0
	for role, fields := range roles {
		for name, value := range fields {
			count++
			key := strings.ToUpper(role + "_" + name)
			expected, exists := overrides[key]
			if !exists {
				t.Fatalf("missing override fixture: %s", key)
			}
			got := reflect.ValueOf(value)
			text := ""
			switch got.Kind() {
			case reflect.Bool:
				if got.Bool() {
					text = "true"
				} else {
					text = "false"
				}
			case reflect.Float64:
				if got.Float() == 120 {
					text = "120"
				}
			default:
				text = got.String()
				if strings.HasSuffix(name, "_file") && text != "" {
					text = filepath.Base(text)
				}
			}
			if text != expected {
				t.Fatalf("override %s = %s, want %s", key, text, expected)
			}
		}
	}
	if count != len(overrides) {
		t.Fatal("override schema changed")
	}
	for name, value := range map[string]string{
		"HUB_ENABLED":                      "invalid",
		"AGENT_ENABLED":                    "invalid",
		"AGENT_ALLOW_PRIVATE_EGRESS":       "invalid",
		"AGENT_HEARTBEAT_INTERVAL_SECONDS": "invalid",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("AEGISMESH_FLEET_"+name, value)
			if _, err := fleetConfig(t, ""); err == nil {
				t.Fatal("accepted malformed env override")
			}
		})
	}
}

func TestFleetCredentialReferences(t *testing.T) {
	cfg, err := fleetConfig(t, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Fleet.Agent.EnrollmentTokenFile = "enrollment.token"
	file := filepath.Join(filepath.Dir(cfg.SourcePath), "enrollment.token")
	secret := strings.Repeat("a", 64)
	if err := os.WriteFile(file, []byte(secret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if token, err := cfg.ResolveFleetToken(); err != nil || token != secret {
		t.Fatal("token file resolution failed")
	}
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.ResolveFleetToken(); err == nil {
		t.Fatal("accepted world-readable token")
	}
	cfg.Fleet.Agent.EnrollmentTokenFile = "link"
	if err := os.Symlink(file, filepath.Join(filepath.Dir(file), "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.ResolveFleetToken(); err == nil {
		t.Fatal("accepted token symlink")
	}
	cfg.Fleet.Agent.EnrollmentTokenFile = ""
	cfg.Fleet.Agent.EnrollmentTokenEnv = "SYNTHETIC_ENROLLMENT_TEST"
	t.Setenv(cfg.Fleet.Agent.EnrollmentTokenEnv, secret)
	if token, err := cfg.ResolveFleetToken(); err != nil || token != secret {
		t.Fatal("env reference failed")
	}
	t.Setenv(cfg.Fleet.Agent.EnrollmentTokenEnv, "secret-invalid")
	if _, err := cfg.ResolveFleetToken(); err == nil || strings.Contains(err.Error(), "secret-invalid") {
		t.Fatal("unsafe credential error")
	}
}

func TestFleetHubMayRunWithoutSensors(t *testing.T) {
	cfg, err := fleetConfig(t, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Sensors = nil
	if cfg.Validate() == nil {
		t.Fatal("ordinary node accepted without sensors")
	}
	cfg.Fleet.Hub.Enabled = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("inventory-only hub: %v", err)
	}
	cfg.Fleet.Hub.Enabled = false
	cfg.Fleet.Agent.Enabled = true
	cfg.Fleet.Agent.HubURL = "http://127.0.0.1:9130"
	if cfg.Validate() == nil {
		t.Fatal("agent accepted without sensors")
	}
}
