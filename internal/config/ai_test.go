package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAIDecoyScaffold(t *testing.T) {
	var previous string
	for i := 0; i < 2; i++ {
		dir := t.TempDir()
		if _, err := ScaffoldProfile(dir, ProfileAIDecoy, false); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(filepath.Join(dir, "mesh.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.LLM.Provider != "local" || len(cfg.Honeytokens) != 2 || !cfg.Correlation.IsEnabled() {
			t.Fatal("unsafe or incomplete profile")
		}
		if cfg.Honeytokens[0].Value == previous {
			t.Fatal("deployments reused token")
		}
		previous = cfg.Honeytokens[0].Value
		found := map[string]bool{}
		var bodies strings.Builder
		for _, s := range cfg.Sensors {
			if s.Fallback != nil && s.Fallback.Enabled {
				t.Fatal("AI decoy has provider fallback")
			}
			for _, r := range s.Rules {
				if len(r.Body) > 4096 || len(r.Headers) == 0 || r.Status < 200 || r.Status > 499 {
					t.Fatal("invalid response")
				}
				found[r.Name] = true
				bodies.WriteString(r.Body)
				if r.Headers["Content-Type"] == "application/json" && !json.Valid([]byte(r.Body)) {
					t.Fatal("invalid synthetic JSON response")
				}
			}
		}
		for _, token := range cfg.Honeytokens {
			if !strings.Contains(bodies.String(), token.Value) {
				t.Fatal("marker not planted in a response")
			}
		}
		for _, name := range []string{"ollama-root", "ollama-version", "ollama-tags", "ollama-ps", "ollama-generate", "ollama-chat", "ollama-show", "ollama-pull", "models", "chat", "completion", "embeddings", "liveliness", "readiness", "model-info", "key-info", "key-generate", "vllm-version", "vllm-metrics", "vllm-models"} {
			if !found[name] {
				t.Errorf("missing %s", name)
			}
		}
	}
}

func TestHoneytokensConfigStrictAndValidated(t *testing.T) {
	for _, tc := range []struct {
		name, section string
		ok            bool
	}{
		{"valid", "honeytokens:\n  - {id: plant, value: synthetic-test-token-value, kind: credential}\n", true},
		{"canary", "honeytokens:\n  - {id: agent, value: synthetic-test-token-value, kind: agent_canary}\n", true},
		{"short", "honeytokens:\n  - {id: plant, value: short, kind: credential}\n", false},
		{"id", "honeytokens:\n  - {id: bad/id, value: synthetic-test-token-value, kind: credential}\n", false},
		{"kind", "honeytokens:\n  - {id: plant, value: synthetic-test-token-value, kind: other}\n", false},
		{"unknown", "honeytokens:\n  - {id: plant, value: synthetic-test-token-value, kind: credential, command: nope}\n", false},
		{"duplicate", "honeytokens:\n  - {id: plant, value: synthetic-test-token-value, kind: credential}\n  - {id: other, value: synthetic-test-token-value, kind: agent_canary}\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "mesh.yaml")
			body := append(append([]byte{}, demoConfig...), []byte("\n"+tc.section)...)
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if (err == nil) != tc.ok {
				t.Fatalf("ok=%v err=%v", tc.ok, err)
			}
			if err != nil && strings.Contains(err.Error(), "synthetic-test-token-value") {
				t.Fatal("token leaked in error")
			}
		})
	}
	// Every new disabled rule is accepted by its owner's registry.
	d := Detection{Actions: DetectionActions{Info: "observe", Low: "tag", Medium: "isolate", High: "refuse"}, DisabledRules: []string{"LLM-001", "LLM-002", "LLM-003", "LLM-004", "HT-001", "AGT-001"}}
	if err := ValidateDetection(d); err != nil {
		t.Fatal(err)
	}
	c := Correlation{DisabledRules: []string{"COR-005", "COR-006", "COR-007", "COR-008"}, AutomationThreshold: 4, CredentialThreshold: 3}
	if err := ValidateCorrelation(&c); err != nil {
		t.Fatal(err)
	}
}

func TestAIThresholdConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Correlation
		ok   bool
	}{
		{"defaults", Correlation{}, true}, {"minimums", Correlation{AutomationThreshold: 4, CredentialThreshold: 3}, true},
		{"max", Correlation{PerSourceEvents: 512, AutomationThreshold: 512, CredentialThreshold: 512}, true},
		{"negative automation", Correlation{AutomationThreshold: -1}, false}, {"small automation", Correlation{AutomationThreshold: 3}, false},
		{"negative stuffing", Correlation{CredentialThreshold: -1}, false}, {"small stuffing", Correlation{CredentialThreshold: 2}, false},
		{"over ring", Correlation{PerSourceEvents: 8, CredentialThreshold: 9}, false}, {"over max", Correlation{AutomationThreshold: 513}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateCorrelation(&tc.cfg); (err == nil) != tc.ok {
				t.Fatalf("ok=%v err=%v", tc.ok, err)
			}
		})
	}
}
