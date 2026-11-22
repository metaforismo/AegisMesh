package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMCPEnvironmentValidation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*MCPEnvironment)
	}{
		{"depth missing", func(e *MCPEnvironment) { e.DepthThreshold = 0 }},
		{"depth small", func(e *MCPEnvironment) { e.DepthThreshold = 1 }},
		{"depth large", func(e *MCPEnvironment) { e.DepthThreshold = 33 }},
		{"files count", func(e *MCPEnvironment) { e.Files = make([]MCPEntry, 33) }},
		{"env count", func(e *MCPEnvironment) { e.Env = make([]MCPEntry, 33) }},
		{"query count", func(e *MCPEnvironment) {
			e.Queries = map[string]string{}
			for i := 0; i < 33; i++ {
				e.Queries[strings.Repeat("a", i+1)] = "x"
			}
		}},
		{"duplicate file", func(e *MCPEnvironment) { e.Files = append(e.Files, e.Files[0]) }},
		{"empty name", func(e *MCPEnvironment) { e.Files[0].Name = "" }},
		{"long name", func(e *MCPEnvironment) { e.Files[0].Name = strings.Repeat("a", 129) }},
		{"control name", func(e *MCPEnvironment) { e.Files[0].Name = "a\nb" }},
		{"format name", func(e *MCPEnvironment) { e.Files[0].Name = "a\u202eb" }},
		{"empty content", func(e *MCPEnvironment) { e.Files[0].Content = "" }},
		{"long content", func(e *MCPEnvironment) { e.Files[0].Content = strings.Repeat("a", 4097) }},
		{"bad utf8 content", func(e *MCPEnvironment) { e.Files[0].Content = "\xff" }},
		{"unknown token", func(e *MCPEnvironment) { e.Files[0].TokenID = "unknown" }},
		{"unplanted token", func(e *MCPEnvironment) { e.Files[1].Content = "nothing" }},
		{"env needs token", func(e *MCPEnvironment) { e.Env[0].TokenID = "" }},
		{"env shape", func(e *MCPEnvironment) { e.Env[0].Name = "bad-name" }},
		{"empty query", func(e *MCPEnvironment) { e.Queries = map[string]string{"": "x"} }},
		{"query result bound", func(e *MCPEnvironment) { e.Queries = map[string]string{"query": strings.Repeat("a", 4097)} }},
		{"query empty result", func(e *MCPEnvironment) { e.Queries = map[string]string{"query": ""} }},
		{"aggregate", func(e *MCPEnvironment) {
			e.Queries = map[string]string{"one": strings.Repeat("a", 4096), "two": strings.Repeat("a", 4096), "three": strings.Repeat("a", 4096), "four": strings.Repeat("a", 4096)}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := AIDecoyConfig()
			if err != nil {
				t.Fatal(err)
			}
			cfg.applyDefaults()
			tc.mutate(cfg.Sensors[2].Environment)
			if err := cfg.Validate(); err == nil {
				t.Fatal("accepted invalid environment")
			} else {
				for _, token := range cfg.Honeytokens {
					if strings.Contains(err.Error(), token.Value) {
						t.Fatal("credential leaked")
					}
				}
			}
		})
	}
	cfg, err := AIDecoyConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.Sensors[2].Tools = []MCPTool{{
		Name:        "read_file",
		Description: "collision",
		ResultJSON:  `{}`,
	}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("shadowed reserved tool")
	}
}

func TestMCPEnvironmentStrictDecoding(t *testing.T) {
	cfg, _ := AIDecoyConfig()
	raw, _ := json.Marshal(cfg)
	for _, field := range []string{"command", "files_bad", "env_bad", "queries_bad", "depth_threshold_bad"} {
		changed := strings.Replace(string(raw), `"environment":{`, `"environment":{"`+field+`":true,`, 1)
		var out Config
		if err := strictJSON([]byte(changed), &out); err == nil {
			t.Fatalf("accepted %s", field)
		}
	}
	for _, field := range []string{"name_bad", "content_bad", "token_id_bad"} {
		changed := strings.Replace(string(raw), `"files":[{`, `"files":[{"`+field+`":true,`, 1)
		var out Config
		if err := strictJSON([]byte(changed), &out); err == nil {
			t.Fatalf("accepted entry %s", field)
		}
	}
	var out Config
	if err := strictYAML([]byte("sensors:\n - environment:\n     depth_threshold: 4\n     files:\n      - {name: x, content: y, command: z}\n"), &out); err == nil {
		t.Fatal("accepted YAML entry field")
	}
}
