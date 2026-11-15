package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestConsoleConfig(t *testing.T) {
	for _, testCase := range []struct {
		name, block string
		bad         bool
	}{
		{
			name:  "defaults",
			block: "",
			bad:   false,
		},
		{
			name:  "enabled empty",
			block: "console:\n  enabled: true",
			bad:   true,
		},
		{
			name:  "unknown",
			block: "console:\n  typo: true",
			bad:   true,
		},
		{
			name:  "ttl low",
			block: "console:\n  session_ttl_seconds: 59",
			bad:   true,
		},
		{
			name:  "ttl high",
			block: "console:\n  session_ttl_seconds: 86401",
			bad:   true,
		},
		{
			name:  "capacity low",
			block: "console:\n  index_max_events: 999",
			bad:   true,
		},
		{
			name:  "capacity high",
			block: "console:\n  index_max_events: 500001",
			bad:   true,
		},
		{
			name:  "cert only",
			block: "console:\n  tls_cert_file: cert.pem",
			bad:   true,
		},
		{
			name:  "key only",
			block: "console:\n  tls_key_file: key.pem",
			bad:   true,
		},
		{
			name:  "bad digest",
			block: "console:\n  operators: [{name: alice, role: admin, token_sha256: abc}]",
			bad:   true,
		},
		{
			name:  "bad role",
			block: "console:\n  operators: [{name: alice, role: root, token_sha256: '" + strings.Repeat("a", 64) + "'}]",
			bad:   true,
		},
		{
			name:  "bad name",
			block: "console:\n  operators: [{name: '../alice', role: admin, token_sha256: '" + strings.Repeat("a", 64) + "'}]",
			bad:   true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			cfg, err := Load(writeTemp(t, "mesh.yaml", minimalValid+"\n"+testCase.block))
			if (err != nil) != testCase.bad {
				t.Fatalf("error=%v", err)
			}
			if testCase.name == "defaults" &&
				(cfg.Console.Enabled ||
					cfg.Console.Listen != "127.0.0.1:9120" ||
					cfg.Console.SessionTTLSeconds != 3600 ||
					cfg.Console.IndexMaxEvents != 50000 ||
					cfg.ConsoleStateDir() != filepath.Join(cfg.Runtime.DataDir, "console")) {
				t.Fatalf("defaults: %+v", cfg.Console)
			}
		})
	}

	cfg, err := Load(writeTemp(t, "mesh.yaml", minimalValid))
	if err != nil {
		t.Fatal(err)
	}

	cfg.Console.Enabled = true
	cfg.Console.Operators = []Operator{{
		Name:        "alice",
		Role:        "admin",
		TokenSHA256: strings.Repeat("a", 64),
	}}
	for _, testCase := range []struct {
		listen          string
		public, tls, ok bool
	}{
		{
			listen: "127.0.0.1:0",
			public: false,
			tls:    false,
			ok:     true,
		},
		{
			listen: "[::1]:9120",
			public: false,
			tls:    false,
			ok:     true,
		},
		{
			listen: "0.0.0.0:9120",
			public: false,
			tls:    false,
			ok:     false,
		},
		{
			listen: "0.0.0.0:9120",
			public: true,
			tls:    false,
			ok:     false,
		},
		{
			listen: "0.0.0.0:9120",
			public: true,
			tls:    true,
			ok:     true,
		},
		{
			listen: ":9120",
			public: true,
			tls:    false,
			ok:     false,
		},
		{
			listen: ":9120",
			public: false,
			tls:    true,
			ok:     false,
		},
		{
			listen: ":9120",
			public: true,
			tls:    true,
			ok:     true,
		},
		{
			listen: "localhost:80",
			public: false,
			tls:    false,
			ok:     false,
		},
	} {
		cfg.Console.Listen = testCase.listen
		cfg.Security.AllowPublicBind = testCase.public
		cfg.Console.TLSCertFile = ""
		cfg.Console.TLSKeyFile = ""
		if testCase.tls {
			cfg.Console.TLSCertFile = "cert.pem"
			cfg.Console.TLSKeyFile = "key.pem"
		}
		if err := cfg.Validate(); (err == nil) != testCase.ok {
			t.Errorf("%+v: %v", testCase, err)
		}
	}

	cfg.Console.Listen = "127.0.0.1:9120"
	cfg.Console.Operators = append(cfg.Console.Operators, cfg.Console.Operators[0])
	if cfg.Validate() == nil {
		t.Fatal("duplicate operator accepted")
	}
}

func TestConsoleEnvOverrides(t *testing.T) {
	t.Setenv("AEGISMESH_CONSOLE_LISTEN", "127.0.0.1:9999")
	t.Setenv("AEGISMESH_CONSOLE_ENABLED", "false")
	cfg, err := Load(writeTemp(t, "mesh.yaml", minimalValid))
	if err != nil || cfg.Console.Listen != "127.0.0.1:9999" || cfg.Console.Enabled {
		t.Fatalf("%+v %v", cfg, err)
	}

	t.Setenv("AEGISMESH_CONSOLE_ENABLED", "yesplease")
	if _, err = Load(writeTemp(t, "mesh.yaml", minimalValid)); err == nil {
		t.Fatal("invalid env accepted")
	}
}

func TestConsolePathAndOperatorLimits(t *testing.T) {
	cfg, err := Load(writeTemp(t, "mesh.yaml", minimalValid+"\nconsole:\n  state_dir: notes\n"+
		"  tls_cert_file: cert.pem\n  tls_key_file: key.pem\n"))
	if err != nil {
		t.Fatal(err)
	}

	base := filepath.Dir(cfg.SourcePath)
	if cfg.ConsoleStateDir() != filepath.Join(base, "notes") ||
		cfg.Console.TLSCertFile != filepath.Join(base, "cert.pem") ||
		cfg.Console.TLSKeyFile != filepath.Join(base, "key.pem") {
		t.Fatal("relative path resolution", cfg.Console)
	}

	cfg.Console.StateDir = filepath.Join(base, "absolute")
	if cfg.ConsoleStateDir() != cfg.Console.StateDir {
		t.Fatal("absolute state path changed")
	}

	cfg.Console.Operators = []Operator{
		{
			Name:        "alice",
			Role:        "admin",
			TokenSHA256: strings.Repeat("a", 64),
		},
		{
			Name:        "carol",
			Role:        "viewer",
			TokenSHA256: strings.Repeat("a", 64),
		},
	}

	if cfg.Validate() == nil {
		t.Fatal("duplicate digests accepted")
	}

	cfg.Console.Operators = make([]Operator, 33)
	if cfg.Validate() == nil {
		t.Fatal("operator count limit")
	}
}
