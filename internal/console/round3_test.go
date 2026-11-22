package console_test

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console"
	"github.com/metaforismo/aegismesh/internal/digest"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/honeytoken"
)

func TestSIEMDownloadScopesFormatsAndAudit(t *testing.T) {
	h := newConsoleHarness(t, nil)
	id := sessionID(t, h)
	created := h.request(t, apiRequest{
		method: "POST",
		path:   "/api/v1/investigations",
		token:  "synthetic-analyst",
		body:   fmt.Sprintf(`{"title":"Synthetic export scope","event_ids":[%q]}`, h.eventID),
	})
	requireStatus(t, created, 201)
	var item struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(created.body, &item) != nil {
		t.Fatal("case response")
	}
	for _, format := range []string{"cef", "syslog-rfc5424", "otlp-json", "ecs"} {
		for _, scope := range []string{"window=24h", "source=127.0.0.1", "session=" + id, "investigation=" + item.ID} {
			path := "/api/v1/export/events?format=" + format + "&" + scope
			response := h.request(t, apiRequest{
				method: "GET",
				path:   path,
				token:  "synthetic-analyst",
			})
			requireStatus(t, response, 200)
			if !strings.Contains(string(response.body), h.eventID) || response.header.Get("Cache-Control") != "no-store" || response.header.Get("X-AegisMesh-Scan-Limit") != "8192" || !strings.HasPrefix(response.header.Get("Content-Disposition"), `attachment; filename="aegismesh-events-`) {
				t.Fatal(response.header, string(response.body))
			}
			again := h.request(t, apiRequest{
				method: "GET",
				path:   path,
				token:  "synthetic-analyst",
			})
			requireStatus(t, again, 200)
			if string(response.body) != string(again.body) {
				t.Fatal("download drift")
			}
		}
	}
	audit := h.request(t, apiRequest{
		method: "GET",
		path:   "/api/v1/audit?limit=200",
		token:  "synthetic-admin",
	})
	requireStatus(t, audit, 200)
	if strings.Count(string(audit.body), `"action":"export.events"`) != 32 {
		t.Fatal("missing audited downloads", string(audit.body))
	}
	h.server.CloseAuditForTest()
	failed := h.request(t, apiRequest{
		method: "GET",
		path:   "/api/v1/export/events?window=24h&format=cef",
		token:  "synthetic-analyst",
	})
	requireStatus(t, failed, 503)
	if failed.header.Get("Content-Disposition") != "" || strings.Contains(string(failed.body), "CEF:0") {
		t.Fatal("disclosure before audit")
	}
}

func TestRound3StrictQueries(t *testing.T) {
	h := newConsoleHarness(t, nil)
	for _, path := range []string{
		"/api/v1/digest?window=1h", "/api/v1/digest?window=24h&window=7d", "/api/v1/digest?format=md",
		"/api/v1/decoys?window=bad", "/api/v1/decoys?window=24h&window=7d", "/api/v1/decoys?include_values=true",
		"/api/v1/honeytokens?window=bad", "/api/v1/honeytokens?value=synthetic", "/api/v1/honeytokens?window=24h&window=7d",
		"/api/v1/export/events?format=cef", "/api/v1/export/events?format=cef&window=24h&source=127.0.0.1",
		"/api/v1/export/events?format=cef&source=", "/api/v1/export/events?format=cef&session=bad",
		"/api/v1/export/events?format=cef&source=" + strings.Repeat("x", 256),
		"/api/v1/export/events?format=cef&format=ecs&window=24h", "/api/v1/export/events?format=cef&window=bad",
		"/api/v1/export/events?format=" + url.QueryEscape("cef\r\nInjected: yes") + "&window=24h",
	} {
		t.Run(path, func(t *testing.T) {
			requireStatus(t, h.request(t, apiRequest{
				method: "GET",
				path:   path,
				token:  "synthetic-admin",
			}), 400)
		})
	}
}

func TestRound3TenantIsolation(t *testing.T) {
	h, _ := tenantHarness(t, nil)
	id := sessionID(t, h)
	for _, path := range []string{"/api/v1/digest?window=7d", "/api/v1/decoys", "/api/v1/honeytokens", "/api/v1/export/events?format=ecs&window=24h"} {
		response := h.request(t, apiRequest{
			method: "GET",
			path:   path,
			token:  "bravo-analyst",
		})
		requireStatus(t, response, 200)
		if strings.Contains(string(response.body), h.eventID) || strings.Contains(string(response.body), "127.0.0.1") {
			t.Fatal("foreign evidence leaked", path, string(response.body))
		}
		if strings.Contains(path, "digest") {
			var report digest.Report
			if json.Unmarshal(response.body, &report) != nil || report.Totals.Events != 0 || report.Bounds.Index.Events != 0 {
				t.Fatal(string(response.body))
			}
		}
	}
	for _, format := range []string{"cef", "syslog-rfc5424", "ecs", "otlp-json"} {
		requireStatus(t, h.request(t, apiRequest{
			method: "GET",
			path:   "/api/v1/export/events?format=" + format + "&session=" + id,
			token:  "bravo-analyst",
		}), 404)
	}
}

func TestConfiguredDecoysAndHoneytokenIDsOnly(t *testing.T) {
	const value = "synthetic-planted-marker-value"
	var index *evidenceindex.Index
	h := newConsoleHarness(t, func(opts *console.Options) {
		cfg := &config.Config{
			Honeytokens: []honeytoken.Token{{
				ID:    "plant",
				Kind:  honeytoken.Credential,
				Value: value,
			}, {
				ID:    "second",
				Kind:  honeytoken.Credential,
				Value: "synthetic-second-planted-value",
			}},
			Sensors: []config.Sensor{{
				ID:     "workspace",
				Kind:   "mcp",
				Listen: "127.0.0.1:8002",
				Environment: &config.MCPEnvironment{
					DepthThreshold: 3,
					Files: []config.MCPEntry{{
						Name:    ".env",
						Content: value,
						TokenID: "plant",
					}},
				},
			}},
		}
		opts.Decoys, opts.Honeytokens = console.DecoyCatalog(cfg)
		index = opts.Index
		e, err := event.New(&event.Sequencer{}, "synthetic", event.SensorRef{
			ID:   "workspace",
			Kind: "mcp",
		}, "canary_invocation", json.RawMessage(`{"method":"tools/call","remote_host":"192.0.2.4","detection":{"findings":[{"rule_id":"HT-001","token_id":"plant"},{"rule_id":"HT-001","token_id":"second"}]}}`), nil)
		if err != nil {
			t.Fatal(err)
		}
		e.Time = time.Now().Add(-time.Minute)
		index.Add(e)
		index.AddForwarded(e, strings.Repeat("a", 32))
	})
	response := h.request(t, apiRequest{
		method: "GET",
		path:   "/api/v1/decoys",
		token:  "synthetic-viewer",
	})
	requireStatus(t, response, 200)
	var decoys struct {
		Decoys []console.Decoy `json:"decoys"`
	}
	if json.Unmarshal(response.body, &decoys) != nil || len(decoys.Decoys) != 1 {
		t.Fatal(string(response.body))
	}
	d := decoys.Decoys[0]
	if d.ID != "workspace" || d.Tools != 5 || d.FakeFiles != 1 || d.Events != 1 || d.LastActivity == "" || strings.Join(d.HoneytokenIDs, ",") != "plant" {
		t.Fatal(d)
	}
	response = h.request(t, apiRequest{
		method: "GET",
		path:   "/api/v1/honeytokens",
		token:  "synthetic-viewer",
	})
	requireStatus(t, response, 200)
	var markers struct {
		Tokens []console.Honeytoken `json:"honeytokens"`
	}
	if json.Unmarshal(response.body, &markers) != nil || len(markers.Tokens) != 2 {
		t.Fatal(string(response.body))
	}
	for _, m := range markers.Tokens {
		if m.Hits != 1 || m.LastHit == "" || strings.Join(m.Sources, ",") != "192.0.2.4" {
			t.Fatal(m)
		}
	}
	if strings.Contains(string(response.body), value) || strings.Contains(string(response.body), `"value"`) || strings.Contains(string(response.body), `"content"`) {
		t.Fatal("values disclosed")
	}
}

func TestEventSessionOverviewAndFullSourceHistogram(t *testing.T) {
	h := newConsoleHarness(t, func(opts *console.Options) {
		for i := 0; i < 8; i++ {
			body := json.RawMessage(`{"remote_host":"192.0.2.9","method":"GET","path":"/","detection":{"findings":[{"rule_id":"PI-001"}]}}`)
			e, _ := event.New(&event.Sequencer{}, "synthetic", event.SensorRef{
				ID:   "web",
				Kind: "http",
			}, "interaction", body, nil)
			e.Time = time.Now().Add(-time.Minute + time.Duration(i)*time.Second)
			opts.Index.Add(e)
		}
	})
	response := h.request(t, apiRequest{
		method: "GET",
		path:   "/api/v1/events/" + h.eventID,
		token:  "synthetic-viewer",
	})
	requireStatus(t, response, 200)
	var detail struct {
		SessionID string `json:"session_id"`
	}
	if json.Unmarshal(response.body, &detail) != nil || detail.SessionID != sessionID(t, h) {
		t.Fatal(string(response.body))
	}
	response = h.request(t, apiRequest{
		method: "GET",
		path:   "/api/v1/overview",
		token:  "synthetic-viewer",
	})
	requireStatus(t, response, 200)
	var overview evidenceindex.Overview
	if json.Unmarshal(response.body, &overview) != nil || overview.Index.Events != 9 || len(overview.TopRules) == 0 || overview.TopRules[0].Title == "" || overview.TopRules[0].Severity != "high" {
		t.Fatal(string(response.body))
	}
	response = h.request(t, apiRequest{
		method: "GET",
		path:   "/api/v1/sources/192.0.2.9?limit=1",
		token:  "synthetic-viewer",
	})
	requireStatus(t, response, 200)
	var source struct {
		Events    []evidenceindex.Summary   `json:"events"`
		Histogram []evidenceindex.GapBucket `json:"inter_arrival"`
	}
	if json.Unmarshal(response.body, &source) != nil || len(source.Events) != 1 {
		t.Fatal(string(response.body))
	}
	total := 0
	for _, b := range source.Histogram {
		total += b.Count
	}
	if total != 7 {
		t.Fatal("histogram limited to page", string(response.body))
	}
	audit := h.request(t, apiRequest{
		method: "GET",
		path:   "/api/v1/audit?action=event.read",
		token:  "synthetic-admin",
	})
	requireStatus(t, audit, 200)
	if !strings.Contains(string(audit.body), "local:"+h.eventID) {
		t.Fatal("event detail unaudited")
	}
}
