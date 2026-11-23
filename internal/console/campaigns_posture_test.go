package console_test

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console"
	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/honeytoken"
	"github.com/metaforismo/aegismesh/internal/posture"
)

type step struct {
	kind, class, observation string
	at                       time.Duration
}

func addSteps(t *testing.T, index *evidenceindex.Index, base time.Time, steps []step) {
	t.Helper()
	for _, s := range steps {
		e, err := event.New(&event.Sequencer{}, "synthetic", event.SensorRef{ID: "ai-" + s.kind, Kind: s.kind}, s.class, json.RawMessage(s.observation), nil)
		if err != nil {
			t.Fatal(err)
		}
		e.Time = base.Add(s.at)
		index.Add(e)
	}
}

// probe emits the same model-listing then chat sequence from source; repeat
// adds extra model polls (collapsed into one step) at 400 ms spacing.
func probe(source string, offset time.Duration, repeat int) []step {
	http := func(method, path string, rules ...string) string {
		findings := []string{}
		for _, id := range rules {
			findings = append(findings, fmt.Sprintf(`{"rule_id":%q}`, id))
		}
		return fmt.Sprintf(`{"method":%q,"path":%q,"remote_host":%q,"user_agent":"OpenAI/Python 1.54.0","response":{"status":200},"detection":{"action":"observe","findings":[%s]}}`,
			method, path, source, strings.Join(findings, ","))
	}
	out := []step{{"http", "interaction", http("GET", "/api/tags"), offset}}
	for i := 0; i <= repeat; i++ {
		out = append(out, step{"http", "interaction", http("GET", "/v1/models", "LLM-001"), offset + time.Duration(len(out))*400*time.Millisecond})
	}
	out = append(out, step{"http", "interaction", http("POST", "/v1/chat/completions", "LLM-002"), offset + time.Duration(len(out))*400*time.Millisecond})
	return out
}

func agentSteps(source string, offset time.Duration) []step {
	mcp := func(method, tool string) string {
		if tool == "" {
			return fmt.Sprintf(`{"method":%q,"remote_host":%q}`, method, source)
		}
		return fmt.Sprintf(`{"method":%q,"tool_name":%q,"remote_host":%q}`, method, tool, source)
	}
	return []step{
		{"mcp", "interaction", mcp("initialize", ""), offset},
		{"mcp", "interaction", mcp("tools/list", ""), offset + time.Second},
		{"mcp", "canary_invocation", mcp("tools/call", "list_files"), offset + 3*time.Second},
		{"mcp", "canary_invocation", mcp("tools/call", "read_file"), offset + 4*time.Second},
		{"mcp", "canary_invocation", mcp("tools/call", "read_file"), offset + 6*time.Second},
	}
}

func TestCampaignsSessionsActorAndPostureOverHTTP(t *testing.T) {
	base := time.Now().UTC().Add(-20 * time.Minute).Truncate(time.Second)
	value := "synthetic-canary-value-0123456789"
	h := newConsoleHarness(t, func(opts *console.Options) {
		addSteps(t, opts.Index, base, probe("192.0.2.10", 0, 8))
		addSteps(t, opts.Index, base, probe("198.51.100.20", 2*time.Minute, 0))
		addSteps(t, opts.Index, base, agentSteps("203.0.113.9", 4*time.Minute))
		cfg := &config.Config{
			Sensors: []config.Sensor{
				{ID: "web", Kind: "http", Listen: "127.0.0.1:0", Rules: []config.HTTPRule{{Name: "root", PathRegex: "^/$", Status: 200, Body: "token " + value}}},
			},
			Honeytokens: []honeytoken.Token{{ID: "agent-diagnostic", Kind: honeytoken.AgentCanary, Value: value}},
			Console:     opts.Config,
		}
		facts := console.PostureFacts(cfg)
		opts.Posture = &facts
	})

	list := h.request(t, apiRequest{method: "GET", path: "/api/v1/campaigns", token: "synthetic-viewer"})
	requireStatus(t, list, 200)
	var campaigns struct {
		Items []struct {
			ID               string         `json:"id"`
			Label            string         `json:"label"`
			Basis            []string       `json:"basis"`
			Sources          []string       `json:"sources"`
			SessionIDs       []string       `json:"session_ids"`
			EventCount       int            `json:"event_count"`
			Stages           []string       `json:"stages"`
			AutomationCounts map[string]int `json:"automation_counts"`
		} `json:"items"`
		ScannedSessions int    `json:"scanned_sessions"`
		Truncated       bool   `json:"truncated"`
		GeneratedAt     string `json:"generated_at"`
	}
	if err := json.Unmarshal(list.body, &campaigns); err != nil {
		t.Fatal(err)
	}
	if len(campaigns.Items) != 1 || campaigns.ScannedSessions != 4 || campaigns.Truncated || campaigns.GeneratedAt == "" {
		t.Fatalf("%s", list.body)
	}
	c := campaigns.Items[0]
	if !regexp.MustCompile(`^cmp_[0-9a-f]{12}$`).MatchString(c.ID) || strings.Join(c.Sources, ",") != "192.0.2.10,198.51.100.20" ||
		strings.Join(c.Basis, ",") != "same_step_sequence,same_client_family" || c.EventCount != 14 ||
		c.Label != "GET /api/tags → GET /v1/models → POST /v1/chat/completions" ||
		c.AutomationCounts["likely_automated"] != 1 || c.AutomationCounts["inconclusive"] != 1 || strings.Join(c.Stages, ",") != "discovery,ai_service_abuse" {
		t.Fatalf("%s", list.body)
	}
	if testing.Verbose() {
		t.Logf("campaigns: %s", list.body)
	}

	detail := h.request(t, apiRequest{method: "GET", path: "/api/v1/campaigns/" + c.ID, token: "synthetic-viewer"})
	requireStatus(t, detail, 200)
	var d struct {
		Steps []struct {
			Index    int    `json:"index"`
			Shape    string `json:"shape"`
			Stage    string `json:"stage"`
			Sessions int    `json:"sessions"`
		} `json:"steps"`
		Sessions []struct {
			ID         string  `json:"id"`
			CampaignID *string `json:"campaign_id"`
		} `json:"sessions"`
		Caveats []string `json:"caveats"`
	}
	if err := json.Unmarshal(detail.body, &d); err != nil {
		t.Fatal(err)
	}
	if len(d.Steps) != 3 || d.Steps[2].Shape != "POST /v1/chat/completions" || d.Steps[2].Stage != "ai_service_abuse" || d.Steps[0].Sessions != 2 ||
		len(d.Sessions) != 2 || d.Sessions[0].CampaignID == nil || *d.Sessions[0].CampaignID != c.ID || len(d.Caveats) == 0 {
		t.Fatalf("%s", detail.body)
	}
	if testing.Verbose() {
		t.Logf("campaign detail: %s", detail.body)
	}
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/campaigns/cmp_000000000000", token: "synthetic-viewer"}), 404)
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/campaigns/cmp_ZZ", token: "synthetic-viewer"}), 400)
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/campaigns?limit=1", token: "synthetic-viewer"}), 400)
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/campaigns"}), 401)

	sessions := h.request(t, apiRequest{method: "GET", path: "/api/v1/sessions?window=1h", token: "synthetic-viewer"})
	requireStatus(t, sessions, 200)
	var listed struct {
		Sessions []struct {
			Source     string  `json:"source"`
			CampaignID *string `json:"campaign_id"`
			Actor      struct {
				Assessment string `json:"assessment"`
				Summary    string `json:"summary"`
				Signals    []struct {
					Code    string `json:"code"`
					Present bool   `json:"present"`
				} `json:"signals"`
			} `json:"actor"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(sessions.body, &listed); err != nil {
		t.Fatal(err)
	}
	assessments := map[string]string{}
	for _, s := range listed.Sessions {
		assessments[s.Source] = s.Actor.Assessment
		if len(s.Actor.Signals) != 10 || s.Actor.Summary == "" {
			t.Fatalf("%s", sessions.body)
		}
		if (s.CampaignID != nil) != (s.Source == "192.0.2.10" || s.Source == "198.51.100.20") {
			t.Fatalf("campaign_id membership: %s", sessions.body)
		}
	}
	if assessments["203.0.113.9"] != "possibly_ai_agent" || assessments["192.0.2.10"] != "likely_automated" || assessments["198.51.100.20"] != "inconclusive" {
		t.Fatal(assessments)
	}
	if !strings.Contains(string(sessions.body), `"campaign_id":null`) {
		t.Fatal("non-members must carry an explicit null campaign_id")
	}
	if testing.Verbose() {
		t.Logf("sessions: %s", sessions.body)
	}

	review := h.request(t, apiRequest{method: "GET", path: "/api/v1/posture", token: "synthetic-viewer"})
	requireStatus(t, review, 200)
	var report posture.Report
	if err := json.Unmarshal(review.body, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Checks) != 19 || report.Scope != "configuration_and_evidence" || report.Summary.Attention+report.Summary.OK+report.Summary.Info != 19 {
		t.Fatalf("%s", review.body)
	}
	if strings.Contains(string(review.body), value) || strings.Contains(string(review.body), "token_sha256") {
		t.Fatal("posture disclosed a secret")
	}
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/posture?x=1", token: "synthetic-viewer"}), 400)
	if testing.Verbose() {
		t.Logf("posture: %s", review.body)
	}
}

func TestCampaignsAndPostureNeverCrossTenants(t *testing.T) {
	base := time.Now().UTC().Add(-20 * time.Minute)
	var bravo *evidenceindex.Index
	h := newConsoleHarness(t, func(opts *console.Options) {
		opts.Config.Tenants = []string{"default", "bravo"}
		opts.Config.Operators = append(opts.Config.Operators, config.Operator{Name: "bravo-viewer", Role: "viewer", TokenSHA256: auth.Digest("bravo-viewer"), Tenants: []string{"bravo"}})
		var err error
		bravo, err = evidenceindex.New(1000, opts.Meter)
		if err != nil {
			t.Fatal(err)
		}
		opts.TenantIndexes = map[string]*evidenceindex.Index{"default": opts.Index, "bravo": bravo}
		// One source in each tenant follows the same steps; a second source exists only in default.
		addSteps(t, opts.Index, base, probe("192.0.2.10", 0, 0))
		addSteps(t, opts.Index, base, probe("192.0.2.11", time.Minute, 0))
		addSteps(t, bravo, base, probe("198.51.100.20", 2*time.Minute, 0))
		facts := posture.Facts{Sensors: []posture.Sensor{{ID: "default-only-sensor", Kind: "http", Listen: "127.0.0.1:1"}}}
		opts.Posture = &facts
	})
	own := h.request(t, apiRequest{method: "GET", path: "/api/v1/campaigns", token: "synthetic-viewer"})
	requireStatus(t, own, 200)
	foreign := h.request(t, apiRequest{method: "GET", path: "/api/v1/campaigns", token: "bravo-viewer"})
	requireStatus(t, foreign, 200)
	var a, b struct {
		Items []struct {
			ID      string   `json:"id"`
			Sources []string `json:"sources"`
		} `json:"items"`
	}
	if json.Unmarshal(own.body, &a) != nil || json.Unmarshal(foreign.body, &b) != nil {
		t.Fatal("decode")
	}
	if len(a.Items) != 1 || strings.Join(a.Items[0].Sources, ",") != "192.0.2.10,192.0.2.11" || len(b.Items) != 0 {
		t.Fatalf("default %s bravo %s", own.body, foreign.body)
	}
	if strings.Contains(string(foreign.body), "192.0.2.") {
		t.Fatal("bravo saw default sources")
	}
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/campaigns/" + a.Items[0].ID, token: "bravo-viewer"}), 404)
	// Adding bravo's own second source forms a bravo campaign that excludes default sessions.
	addSteps(t, bravo, base, probe("198.51.100.21", 3*time.Minute, 0))
	foreign = h.request(t, apiRequest{method: "GET", path: "/api/v1/campaigns", token: "bravo-viewer"})
	if json.Unmarshal(foreign.body, &b) != nil || len(b.Items) != 1 || strings.Join(b.Items[0].Sources, ",") != "198.51.100.20,198.51.100.21" || b.Items[0].ID == a.Items[0].ID {
		t.Fatalf("%s", foreign.body)
	}
	review := h.request(t, apiRequest{method: "GET", path: "/api/v1/posture", token: "bravo-viewer"})
	requireStatus(t, review, 200)
	if strings.Contains(string(review.body), "default-only-sensor") || !strings.Contains(string(review.body), `"scope":"evidence_only"`) {
		t.Fatalf("%s", review.body)
	}
}

func TestPostureFactsFromAIDecoyProfile(t *testing.T) {
	cfg, err := config.AIDecoyConfig()
	if err != nil {
		t.Fatal(err)
	}
	facts := console.PostureFacts(cfg)
	report := posture.Evaluate(&facts, posture.Unavailable("evidence not read in this test"), time.Unix(0, 0))
	status := map[string]string{}
	for _, c := range report.Checks {
		status[c.ID] = c.Status
	}
	for id, want := range map[string]string{"POS-007": "ok", "POS-008": "ok", "POS-011": "ok", "POS-014": "ok", "POS-016": "info"} {
		if status[id] != want {
			t.Fatalf("%s = %s, want %s", id, status[id], want)
		}
	}
	body, _ := json.Marshal(report)
	for _, token := range cfg.Honeytokens {
		if strings.Contains(string(body), token.Value) {
			t.Fatal("posture disclosed a honeytoken value")
		}
	}
}
