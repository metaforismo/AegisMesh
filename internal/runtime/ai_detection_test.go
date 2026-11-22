package runtime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/detect"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/honeytoken"
	"github.com/metaforismo/aegismesh/internal/recommend"
	"github.com/metaforismo/aegismesh/internal/redact"
	"github.com/metaforismo/aegismesh/internal/rulecatalog"
	"golang.org/x/crypto/ssh"
)

func TestAIHoneytokenLoopAcrossAllSensors(t *testing.T) {
	for _, isolated := range []bool{false, true} {
		t.Run(fmt.Sprintf("isolated=%v", isolated), func(t *testing.T) {
			cfg := testConfig(t)
			key := honeytoken.Token{ID: "test-key", Value: "sk-synthetic-honey-replay-marker", Kind: honeytoken.Credential}
			agent := honeytoken.Token{ID: "test-agent", Value: "synthetic-agent-echo-marker", Kind: honeytoken.AgentCanary}
			cfg.Honeytokens = []honeytoken.Token{key, agent}
			cfg.Detection.Actions = config.DetectionActions{Info: "observe", Low: "observe", Medium: "observe", High: "observe"}
			on := true
			cfg.Correlation.Enabled = &on
			cfg.Correlation.CredentialThreshold = 4
			for i := range cfg.Sensors {
				cfg.Sensors[i].ProcessIsolation = isolated
			}
			sys, err := Build(cfg, quietLogger())
			if err != nil {
				t.Fatal(err)
			}
			defer sys.Stop(context.Background())
			if err := sys.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			endpoints, err := sys.Endpoints()
			if err != nil {
				t.Fatal(err)
			}
			addresses := map[string]string{}
			for _, endpoint := range endpoints {
				addresses[endpoint.Kind] = endpoint.Addr
			}
			client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second}
			defer client.CloseIdleConnections()
			call := func(method, path, body string, headers map[string]string) {
				t.Helper()
				req, err := http.NewRequest(method, "http://"+addresses["http"]+path, strings.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				for k, v := range headers {
					req.Header.Set(k, v)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode == 403 {
					t.Fatal("observe-only finding refused")
				}
			}
			call("GET", "/api/tags", "", nil)
			call("POST", "/v1/completions", `{"prompt":"hi","max_tokens":1}`, nil)
			call("POST", "/api/pull", `{"name":"synthetic-model"}`, nil)
			call("GET", "/path/"+key.Value, "", nil)
			call("GET", "/?q="+key.Value, "", nil)
			call("GET", "/", "", map[string]string{"Authorization": "Bearer " + key.Value})
			call("GET", "/", "", map[string]string{"X-Synthetic-Marker": key.Value, "User-Agent": agent.Value})
			call("POST", "/", "prefix "+key.Value+" "+agent.Value, nil)
			call("POST", "/", strings.Repeat(".", 9000)+key.Value, nil) // past detection prefix
			for i := 0; i < 2; i++ {
				req, _ := http.NewRequest("GET", "http://"+addresses["http"]+"/", nil)
				req.SetBasicAuth("synthetic-user", fmt.Sprintf("synthetic-pass-%d", i))
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
			}
			conn, err := net.DialTimeout("tcp", addresses["tcp"], 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			r := bufio.NewReader(conn)
			if _, err := r.ReadString('\n'); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(conn, key.Value+" "+agent.Value+"\n"); err != nil {
				t.Fatal(err)
			}
			if _, err := r.ReadString('\n'); err != nil {
				t.Fatal(err)
			}
			conn.Close()
			mcp := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"canary_tool","arguments":{"text":"` + key.Value + ` ` + agent.Value + `"}}}`
			resp, err := client.Post("http://"+addresses["mcp"]+"/mcp", "application/json", strings.NewReader(mcp))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			resp, err = client.Post("http://"+addresses["mcp"]+"/mcp", "application/json", strings.NewReader(key.Value+" "+agent.Value))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			sshClient, err := ssh.Dial("tcp", addresses["ssh"], &ssh.ClientConfig{User: key.Value, Auth: []ssh.AuthMethod{ssh.Password(agent.Value)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			sshClient.Close()
			sys.Stop(context.Background())
			var envelopes []event.Envelope
			byKind := map[string]map[string]bool{}
			signals := map[string]bool{}
			unparsedMCP := false
			err = sys.store.Reader().ForEach(func(e event.Envelope) error {
				if err := e.VerifyIntegrity(); err != nil {
					return err
				}
				b, err := json.Marshal(e)
				if err != nil {
					return err
				}
				for _, value := range []string{key.Value, agent.Value, redact.AuthDigest("password", key.Value, agent.Value)} {
					if bytes.Contains(b, []byte(value)) {
						t.Error("raw marker or auth digest persisted")
					}
				}
				if len(e.AuthAttempts) != 0 {
					t.Error("digest survived storage")
				}
				var obs struct {
					RuleID    string `json:"rule_id"`
					Method    string `json:"method"`
					Detection *struct {
						Findings []detect.Finding `json:"findings"`
					} `json:"detection"`
				}
				// Use the production probe for rule/family decoding, and separately pin
				// token id presence in the native observation contract.
				var probe obsProbe
				if err := json.Unmarshal(e.Observation, &probe); err != nil {
					return err
				}
				if byKind[e.Sensor.Kind] == nil {
					byKind[e.Sensor.Kind] = map[string]bool{}
				}
				if probe.Detection != nil {
					for _, f := range probe.Detection.Findings {
						byKind[e.Sensor.Kind][f.RuleID] = true
					}
				}
				if err := json.Unmarshal(e.Observation, &obs); err != nil {
					return err
				}
				if e.Sensor.Kind == "mcp" && obs.Method == "unparsed" && obs.Detection != nil {
					unparsedMCP = true
				}
				if obs.Detection != nil {
					for _, f := range obs.Detection.Findings {
						if f.RuleID == detect.RuleHoneytoken && f.TokenID != key.ID {
							t.Error("credential token id missing")
						}
						if f.RuleID == detect.RuleAgentCanary && f.TokenID != agent.ID {
							t.Error("agent token id missing")
						}
					}
				}
				if obs.RuleID != "" {
					signals[obs.RuleID] = true
				}
				envelopes = append(envelopes, e)
				return nil
			}, func(_ string, err error) { t.Error(err) })
			if err != nil {
				t.Fatal(err)
			}
			if !unparsedMCP {
				t.Error("malformed MCP marker was not observed")
			}
			for _, kind := range []string{"http", "tcp", "mcp", "ssh"} {
				for _, id := range []string{"HT-001", "AGT-001"} {
					if !byKind[kind][id] {
						t.Errorf("%s missing %s", kind, id)
					}
				}
			}
			for _, id := range []string{"LLM-001", "LLM-002", "LLM-003", "LLM-004"} {
				if !byKind["http"][id] {
					t.Errorf("http missing %s", id)
				}
			}
			for _, id := range []string{"COR-006", "COR-007", "COR-008"} {
				if !signals[id] {
					t.Errorf("missing live correlation %s", id)
				}
			}
			if _, err := recommend.Generate(envelopes, recommend.Options{}); err != nil {
				t.Fatalf("new findings broke recommendation reader: %v", err)
			}
		})
	}
}

func TestAIDecoyProfileResponsesOnLoopback(t *testing.T) {
	dir := t.TempDir()
	if _, err := config.ScaffoldProfile(dir, config.ProfileAIDecoy, false); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(dir + "/mesh.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Admin.Listen = "127.0.0.1:0"
	off := false
	cfg.Correlation.Enabled = &off
	for i := range cfg.Sensors {
		cfg.Sensors[i].Listen = "127.0.0.1:0"
	}
	sys, err := Build(cfg, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer sys.Stop(context.Background())
	if err := sys.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	endpoints, err := sys.Endpoints()
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	for i, sensor := range cfg.Sensors {
		for _, rule := range sensor.Rules {
			t.Run(sensor.ID+"/"+rule.Name, func(t *testing.T) {
				path := strings.TrimSuffix(strings.TrimPrefix(rule.PathRegex, "^"), "$")
				req, err := http.NewRequest(rule.Methods[0], "http://"+endpoints[i].Addr+path, strings.NewReader(`{}`))
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				b, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != rule.Status || string(b) != rule.Body || resp.Header.Get("Content-Type") != rule.Headers["Content-Type"] {
					t.Fatalf("static response drift for %s", rule.Name)
				}
			})
		}
	}
}

func TestRulesAPIFrameworkMappings(t *testing.T) {
	_, base := consoleSystem(t, consoleConfig(t))
	response := callAPI(t, base, "GET", "/api/v1/rules", "synthetic-viewer", "", nil, "")
	if response.status != 200 {
		t.Fatal(response.status)
	}
	var payload struct {
		Rules []struct {
			ID         string                         `json:"id"`
			Frameworks []rulecatalog.FrameworkMapping `json:"frameworks"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(response.body, &payload); err != nil {
		t.Fatal(err)
	}
	want := rulecatalog.All()
	if len(payload.Rules) != len(want) {
		t.Fatal("API rule count")
	}
	for i, rule := range payload.Rules {
		if rule.ID != want[i].ID || !reflect.DeepEqual(rule.Frameworks, want[i].Frameworks) {
			t.Fatalf("API mapping drift for %s", rule.ID)
		}
	}
}

func TestMCPSecretReadThenCrossSensorReplay(t *testing.T) {
	for _, isolated := range []bool{false, true} {
		t.Run(fmt.Sprintf("isolated=%v", isolated), func(t *testing.T) {
			cfg := testConfig(t)
			token := honeytoken.Token{
				ID:    "workspace-key",
				Kind:  honeytoken.Credential,
				Value: "synthetic-workspace-replay-marker",
			}
			cfg.Honeytokens = []honeytoken.Token{token}
			on := true
			cfg.Correlation.Enabled = &on
			cfg.Detection.Actions = config.DetectionActions{
				Info:   "observe",
				Low:    "observe",
				Medium: "observe",
				High:   "observe",
			}
			for i := range cfg.Sensors {
				if cfg.Sensors[i].Kind == config.SensorKindMCP {
					cfg.Sensors[i].ProcessIsolation = isolated
					cfg.Sensors[i].Environment = &config.MCPEnvironment{
						DepthThreshold: 2,
						Files: []config.MCPEntry{{
							Name:    ".env",
							Content: token.Value,
							TokenID: token.ID,
						}},
					}
				}
			}
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
			sys, err := Build(cfg, quietLogger())
			if err != nil {
				t.Fatal(err)
			}
			defer sys.Stop(context.Background())
			if err := sys.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			endpoints, _ := sys.Endpoints()
			addresses := map[string]string{}
			for _, e := range endpoints {
				addresses[e.Kind] = e.Addr
			}
			transport := &http.Transport{Proxy: nil}
			defer transport.CloseIdleConnections()
			client := &http.Client{
				Transport: transport,
				Timeout:   3 * time.Second,
			}
			body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":".env"}}}`
			response, err := client.Post("http://"+addresses["mcp"]+"/mcp", "application/json", strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			content, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || !bytes.Contains(content, []byte(token.Value)) {
				t.Fatal("synthetic read failed", err)
			}
			request, _ := http.NewRequest("GET", "http://"+addresses["http"]+"/", nil)
			request.Header.Set("Authorization", "Bearer "+token.Value)
			response, err = client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			sys.Stop(context.Background())
			foundRead, foundReplay := false, false
			if err := sys.store.Reader().ForEach(func(e event.Envelope) error {
				if bytes.Contains(e.Observation, []byte(token.Value)) {
					return fmt.Errorf("marker leaked")
				}
				if bytes.Contains(e.Observation, []byte(`"rule_id":"MCP-001"`)) {
					foundRead = true
				}
				if bytes.Contains(e.Observation, []byte(`"rule_id":"COR-008"`)) {
					foundReplay = true
				}
				return e.VerifyIntegrity()
			}, func(_ string, err error) { t.Error(err) }); err != nil {
				t.Fatal(err)
			}
			if !foundRead || !foundReplay {
				t.Fatalf("read=%v correlation=%v", foundRead, foundReplay)
			}
		})
	}
}
