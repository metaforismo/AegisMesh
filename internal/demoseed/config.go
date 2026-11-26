package demoseed

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/metaforismo/aegismesh/internal/config"
)

// Config writes and loads the fixed synthetic demo configuration in workDir:
// one loopback HTTP, TCP, MCP and SSH sensor on OS-assigned ports, the AI
// decoy honeytokens and MCP environment, and the data directory workDir/data.
// The demo and the seeded performance harness share it.
func Config(workDir string) (*config.Config, error) {
	cfg := config.Config{
		APIVersion: config.APIVersionV1Alpha1,
		Runtime: config.Runtime{
			InstanceName: "synthetic-demo",
			DataDir:      filepath.Join(workDir, "data"),
		},
		Admin:   config.Admin{Listen: "127.0.0.1:0"},
		Logging: config.Logging{Level: "error", Format: "json"},
		LLM:     config.LLM{Provider: "local"},
		Sensors: []config.Sensor{
			{
				ID: "demo-http", Kind: config.SensorKindHTTP, Listen: "127.0.0.1:0",
				Persona: &config.HTTPPersona{ServerHeader: "AegisMesh-Demo"},
				Rules:   []config.HTTPRule{{Name: "root", PathRegex: "^/$", Methods: []string{"GET"}, Status: http.StatusOK, Body: "synthetic demo\n"}},
			},
			{
				ID: "demo-tcp", Kind: config.SensorKindTCP, Listen: "127.0.0.1:0", Banner: "AEGISMESH DEMO\n",
				Session:         &config.TCPSession{MaxLineBytes: 128, IdleTimeoutSeconds: 3, MaxSessionSeconds: 5},
				TCPResponseRule: []config.TCPRule{{Name: "ping", LineRegex: "^PING$", Response: "+OK PONG\n"}},
			},
			{
				ID: "demo-mcp", Kind: config.SensorKindMCP, Listen: "127.0.0.1:0", MCPPath: "/mcp",
				ServerName: "aegismesh-demo", ServerVer: "1.0.0",
				Tools: []config.MCPTool{{Name: "canary_demo", Description: "Synthetic canary for the local demo", ResultJSON: `{"ok":true}`}},
			},
			{ID: "demo-ssh", Kind: config.SensorKindSSH, Listen: "127.0.0.1:0"},
		},
	}
	ai, err := config.AIDecoyConfig()
	if err != nil {
		return nil, err
	}
	cfg.Honeytokens = ai.Honeytokens
	cfg.Sensors[2].Environment = ai.Sensors[2].Environment
	cfg.Sensors[0].Rules = append(cfg.Sensors[0].Rules, ai.Sensors[0].Rules[1:]...)
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("demo: encode internal config: %w", err)
	}
	path := filepath.Join(workDir, "mesh.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return nil, fmt.Errorf("demo: write internal config: %w", err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		return nil, fmt.Errorf("demo: validate internal config: %w", err)
	}
	return loaded, nil
}
