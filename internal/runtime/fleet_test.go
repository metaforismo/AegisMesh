package runtime

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
)

func TestFleetHubDownDoesNotBlockEvidenceOrSensors(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	cfg := testConfig(t)
	cfg.Sensors = cfg.Sensors[:1]
	cfg.Fleet.Agent.Enabled = true
	cfg.Fleet.Agent.HubURL = "http://" + address
	cfg.Fleet.Agent.EnrollmentTokenEnv = "AEGISMESH_SYNTHETIC_ENROLLMENT"
	t.Setenv(cfg.Fleet.Agent.EnrollmentTokenEnv, strings.Repeat("a", 64))
	system, err := Build(cfg, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := system.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer system.Stop(context.Background())
	response, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + system.ConsoleSensors()[0].Listen + "/")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if system.FleetStatus().Agent.LastError != "" && system.fleetCounts.interaction.Load() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	snapshot := system.fleetHeartbeat()
	if system.FleetStatus().Agent.LastError == "" || snapshot.Counters.Interaction != 1 ||
		!snapshot.StorageHealthy || snapshot.SensorsStarted != 1 {
		t.Fatalf("hub failure affected runtime: %+v", snapshot)
	}
	if err := system.store.Flush(); err != nil {
		t.Fatal(err)
	}
	count := 0
	err = system.store.Reader().ForEach(func(_ event.Envelope) error {
		count++
		return nil
	}, nil)
	if err != nil || count != 1 {
		t.Fatalf("evidence while offline: count=%d err=%v", count, err)
	}
	body, _ := json.Marshal(snapshot)
	if strings.Contains(string(body), "127.0.0.1") {
		t.Fatal("heartbeat leaked sensor address")
	}
}

func TestFleetConsoleEnrollmentIntegration(t *testing.T) {
	cfg := consoleConfig(t)
	cfg.Fleet.Hub.Enabled = true
	cfg.Fleet.Hub.Listen = "127.0.0.1:0"
	system, base := consoleSystem(t, cfg)
	minted := callAPI(t, base, "POST", "/api/v1/fleet/enrollment-tokens", "synthetic-admin", `{}`, nil, "")
	if minted.status != 201 {
		t.Fatalf("mint: %s", minted.body)
	}
	var token struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(minted.body, &token); err != nil {
		t.Fatal(err)
	}
	agentConfig := testConfig(t)
	agentConfig.Sensors = agentConfig.Sensors[:1]
	agentConfig.Fleet.Agent.Enabled = true
	agentConfig.Fleet.Agent.HubURL = "http://" + system.FleetStatus().Hub.Listen
	agentConfig.Fleet.Agent.EnrollmentTokenEnv = "AEGISMESH_SYNTHETIC_FLEET_TOKEN"
	t.Setenv(agentConfig.Fleet.Agent.EnrollmentTokenEnv, token.Token)
	reporter, err := Build(agentConfig, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer reporter.Stop(context.Background())
	if err := reporter.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && reporter.FleetStatus().Agent.LastHeartbeatAt == "" {
		time.Sleep(10 * time.Millisecond)
	}
	inventory := callAPI(t, base, "GET", "/api/v1/fleet/nodes?status=online", "synthetic-viewer", "", nil, "")
	var result struct {
		Nodes []protocol.Node `json:"nodes"`
	}
	if err := json.Unmarshal(inventory.body, &result); err != nil || len(result.Nodes) != 1 {
		t.Fatalf("inventory: %s, %v", inventory.body, err)
	}
	revoked := callAPI(t, base, "POST", "/api/v1/fleet/nodes/"+result.Nodes[0].ID+"/revoke",
		"synthetic-admin", "", nil, "")
	if revoked.status != 200 || reporter.fleetAgent.Step(context.Background()) == nil {
		t.Fatalf("revocation: %s", revoked.body)
	}
}

func TestFleetDryRunDoesNotConsumeEnrollmentToken(t *testing.T) {
	hubConfig := consoleConfig(t)
	hubConfig.Fleet.Hub.Enabled = true
	hubConfig.Fleet.Hub.Listen = "127.0.0.1:0"
	hubSystem, base := consoleSystem(t, hubConfig)
	minted := callAPI(t, base, "POST", "/api/v1/fleet/enrollment-tokens", "synthetic-admin", `{}`, nil, "")
	if minted.status != 201 {
		t.Fatalf("mint: %s", minted.body)
	}
	var token struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(minted.body, &token); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t)
	cfg.Sensors = cfg.Sensors[:1]
	cfg.Fleet.Agent.Enabled = true
	cfg.Fleet.Agent.HubURL = "http://" + hubSystem.FleetStatus().Hub.Listen
	cfg.Fleet.Agent.EnrollmentTokenEnv = "AEGISMESH_DRY_RUN_TOKEN"
	t.Setenv(cfg.Fleet.Agent.EnrollmentTokenEnv, token.Token)
	system, err := Build(cfg, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer system.Stop(context.Background())
	if err := system.StartDryRun(context.Background()); err != nil {
		t.Fatal(err)
	}
	tokens, err := hubSystem.fleetHub.Tokens()
	if err != nil || len(tokens) != 1 || system.FleetStatus().Agent.Enrolled {
		t.Fatal("dry-run consumed enrollment token")
	}
	// The very same preflighted agent can enroll when explicitly asked to send.
	if err := system.fleetAgent.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	tokens, err = hubSystem.fleetHub.Tokens()
	if err != nil || len(tokens) != 0 {
		t.Fatal("explicit live send did not enroll")
	}
}

func TestFleetHubWithoutSensors(t *testing.T) {
	cfg := consoleConfig(t)
	cfg.Sensors = nil
	cfg.Fleet.Hub.Enabled = true
	cfg.Fleet.Hub.Listen = "127.0.0.1:0"
	system, base := consoleSystem(t, cfg)
	if status := system.Status(); status.SensorsWanted != 0 || status.SensorsStarted != 0 || !status.StoreHealthy {
		t.Fatalf("hub-only runtime: %+v", status)
	}
	response := callAPI(t, base, "GET", "/api/v1/fleet", "synthetic-viewer", "", nil, "")
	if response.status != 200 {
		t.Fatalf("hub-only console: %s", response.body)
	}
	token, err := system.fleetHub.Mint(0, "hub-only test")
	if err != nil || len(token.Token) != 64 {
		t.Fatalf("hub-only enrollment readiness: %v", err)
	}
}
