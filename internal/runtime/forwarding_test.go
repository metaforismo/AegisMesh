package runtime

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/storage"
)

func TestRuntimeForwardedEvidenceEncryptionAndConsole(t *testing.T) {
	for _, mode := range []string{"plaintext", "encrypted-hub", "encrypted-agent", "hub-disabled", "agent-disabled"} {
		t.Run(mode, func(t *testing.T) {
			identity, err := age.GenerateX25519Identity()
			if err != nil {
				t.Fatal(err)
			}
			hubConfig := consoleConfig(t)
			hubConfig.Fleet.Hub.Enabled = true
			hubConfig.Fleet.Hub.Listen = "127.0.0.1:0"
			hubConfig.Fleet.Hub.AcceptEvidence.Enabled = mode != "hub-disabled"
			if mode == "encrypted-hub" {
				hubConfig.Storage.Encryption = &config.StorageEncryption{Enabled: true, Recipient: identity.Recipient().String()}
			}
			hubSystem, base := consoleSystem(t, hubConfig)
			agents := []*System{}
			for i := 0; i < 2; i++ {
				token, err := hubSystem.fleetHub.Mint(0, "synthetic")
				if err != nil {
					t.Fatal(err)
				}
				cfg := testConfig(t)
				cfg.Sensors = cfg.Sensors[:1]
				cfg.Fleet.Agent.Enabled = true
				cfg.Fleet.Agent.ForwardEvidence.Enabled = mode != "agent-disabled"
				cfg.Fleet.Agent.HubURL = "http://" + hubSystem.FleetStatus().Hub.Listen
				cfg.Fleet.Agent.EnrollmentTokenEnv = "AEGISMESH_FORWARD_TEST_TOKEN"
				t.Setenv(cfg.Fleet.Agent.EnrollmentTokenEnv, token.Token)
				if mode == "encrypted-agent" {
					cfg.Storage.Encryption = &config.StorageEncryption{Enabled: true, Recipient: identity.Recipient().String()}
				}
				system, err := Build(cfg, quietLogger())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { system.Stop(context.Background()) })
				// Start sensors without background fleet timing; execute real signed steps explicitly.
				if err := system.StartDryRun(context.Background()); err != nil {
					t.Fatal(err)
				}
				if err := system.fleetAgent.Step(context.Background()); err != nil {
					t.Fatal(err)
				}
				response, err := http.Get("http://" + system.ConsoleSensors()[0].Listen + "/synthetic?password=private-fixture")
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				deadline := time.Now().Add(3 * time.Second)
				for time.Now().Before(deadline) && (system.fleetCounts.interaction.Load() == 0 ||
					mode != "agent-disabled" && system.FleetStatus().Agent.Forwarding.QueuedEvents == 0) {
					time.Sleep(time.Millisecond)
				}
				if system.fleetCounts.interaction.Load() == 0 {
					t.Fatal("sensor event was not stored")
				}
				if err := system.fleetAgent.ForwardStep(context.Background()); err != nil && mode != "hub-disabled" {
					t.Fatal(err)
				}
				agents = append(agents, system)
			}
			if mode == "hub-disabled" {
				if agents[0].FleetStatus().Agent.Forwarding.LastError != "evidence_disabled" {
					t.Fatal("missing distinct disabled status")
				}
				// A refusal does not affect the independent first heartbeat.
				if agents[0].FleetStatus().Agent.LastHeartbeatAt == "" {
					t.Fatal("heartbeat lost")
				}
				return
			}
			if mode == "agent-disabled" {
				if hubSystem.index.Stats().Events != 0 {
					t.Fatal("disabled agent disclosed evidence")
				}
				return
			}
			overview := callAPI(t, base, "GET", "/api/v1/overview", "synthetic-viewer", "", nil, "")
			var aggregate struct {
				ByNode []evidenceindex.NodeCount `json:"by_node"`
			}
			if json.Unmarshal(overview.body, &aggregate) != nil || len(aggregate.ByNode) != 2 {
				t.Fatalf("overview: %s", overview.body)
			}
			for _, system := range agents {
				id := system.FleetStatus().Agent.NodeID
				page := callAPI(t, base, "GET", "/api/v1/events?node="+id, "synthetic-viewer", "", nil, "")
				var events evidenceindex.Page
				if json.Unmarshal(page.body, &events) != nil || len(events.Events) != 1 || events.Events[0].Node.ID != id {
					t.Fatalf("fleet page: %s", page.body)
				}
				detail := callAPI(t, base, "GET", "/api/v1/events/"+events.Events[0].ID+"?node="+id, "synthetic-viewer", "", nil, "")
				if !strings.Contains(string(detail.body), "hub_payload_hash_consistency") {
					t.Fatalf("integrity scope: %s", detail.body)
				}
				dir := filepath.Join(hubConfig.FleetStateDir(false), "evidence", id)
				opts := storage.ReaderOptions{}
				if mode == "encrypted-hub" {
					keyPath := filepath.Join(t.TempDir(), "read.agekey")
					if err := os.WriteFile(keyPath, []byte(identity.String()+"\n"), 0600); err != nil {
						t.Fatal(err)
					}
					opts.IdentityFiles = []string{keyPath}
					files, _ := os.ReadDir(dir)
					encrypted := false
					for _, file := range files {
						encrypted = encrypted || strings.HasSuffix(file.Name(), ".age")
					}
					if !encrypted {
						t.Fatalf("no encrypted forwarded segment: %v", files)
					}
				}
				reader, err := storage.NewReaderWithOptions(dir, opts)
				if err != nil {
					t.Fatal(err)
				}
				count := 0
				_, err = reader.ForEachVerified(func(e event.Envelope) error { count++; return e.VerifyIntegrity() }, nil)
				if err != nil || count != 1 {
					t.Fatalf("inspect-compatible verification: %d %v", count, err)
				}
			}
			local := callAPI(t, base, "GET", "/api/v1/events?node=local", "synthetic-viewer", "", nil, "")
			if !strings.Contains(string(local.body), `"total_matched":0`) {
				t.Fatal("local filter includes forwarded evidence")
			}
			// The changed SSE route emits authenticated origin and respects the node filter.
			id := agents[0].FleetStatus().Agent.NodeID
			request, _ := http.NewRequest("GET", base+"/api/v1/events/stream?node="+id, nil)
			request.Header.Set("Authorization", "Bearer synthetic-viewer")
			client := &http.Client{Timeout: 10 * time.Second}
			stream, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Body.Close()
			time.Sleep(5 * time.Second)
			response, err := http.Get("http://" + agents[0].ConsoleSensors()[0].Listen + "/sse")
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			deadline := time.Now().Add(time.Second)
			for time.Now().Before(deadline) && (agents[0].fleetCounts.interaction.Load() < 2 ||
				agents[0].FleetStatus().Agent.Forwarding.QueuedEvents == 0) {
				time.Sleep(time.Millisecond)
			}
			if err := agents[0].fleetAgent.ForwardStep(context.Background()); err != nil {
				t.Fatal(err)
			}

			scanner := bufio.NewScanner(stream.Body)
			got := false
			for scanner.Scan() {
				if strings.HasPrefix(scanner.Text(), "data:") {
					if !strings.Contains(scanner.Text(), id) {
						t.Fatal("SSE ignored node filter")
					}
					got = true
					break
				}
			}
			if !got {
				t.Fatal("SSE origin not emitted", scanner.Err())
			}
		})
	}
}
