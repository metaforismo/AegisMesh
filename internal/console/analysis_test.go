package console_test

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/console"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/evidenceview"
)

func sessionID(t *testing.T, h *consoleHarness) string {
	t.Helper()
	response := h.request(t, apiRequest{method: "GET", path: "/api/v1/sessions", token: "synthetic-admin"})
	requireStatus(t, response, 200)
	var list struct {
		Sessions []evidenceview.Session `json:"sessions"`
	}
	if err := json.Unmarshal(response.body, &list); err != nil || len(list.Sessions) == 0 {
		t.Fatal("missing session", err)
	}
	return list.Sessions[0].ID
}

func TestAnalysisRoutesAndAttachments(t *testing.T) {
	h := newConsoleHarness(t, nil)
	id := sessionID(t, h)
	detail := h.request(t, apiRequest{method: "GET", path: "/api/v1/sessions/" + id, token: "synthetic-viewer"})
	requireStatus(t, detail, 200)
	var parsed struct {
		evidenceview.Detail
		Bounds evidenceindex.Snapshot `json:"bounds"`
	}
	if json.Unmarshal(detail.body, &parsed) != nil || parsed.ID != id || parsed.EventCount != 1 || len(parsed.Timeline) != 1 || parsed.Bounds.Scanned != 1 || parsed.Automation.Assessment != "inconclusive" {
		t.Fatal(string(detail.body))
	}
	coverage := h.request(t, apiRequest{method: "GET", path: "/api/v1/coverage?window=24h", token: "synthetic-viewer"})
	requireStatus(t, coverage, 200)
	if !strings.Contains(string(coverage.body), `"mitre-atlas"`) || !strings.Contains(string(coverage.body), `"observed_event_count":0`) {
		t.Fatal(string(coverage.body))
	}
	created := h.request(t, apiRequest{method: "POST", path: "/api/v1/investigations", token: "synthetic-analyst", body: fmt.Sprintf(`{"title":"Report fixture","event_ids":[%q]}`, h.eventID)})
	requireStatus(t, created, 201)
	var investigation struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(created.body, &investigation) != nil {
		t.Fatal("invalid investigation")
	}
	note := h.request(t, apiRequest{method: "POST", path: "/api/v1/investigations/" + investigation.ID + "/notes", token: "synthetic-analyst", body: `{"text":"` + "```\\n# FORGED <script>" + `"}`})
	requireStatus(t, note, 201)
	paths := []string{
		"/api/v1/export/indicators?session=" + id + "&format=stix",
		"/api/v1/export/indicators?source=127.0.0.1&format=csv",
		"/api/v1/export/indicators?investigation=" + investigation.ID + "&format=txt",
		"/api/v1/export/indicators?window=24h&format=txt",
		"/api/v1/sessions/" + id + "/report",
		"/api/v1/investigations/" + investigation.ID + "/report",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			response := h.request(t, apiRequest{method: "GET", path: path, token: "synthetic-analyst"})
			requireStatus(t, response, 200)
			if !strings.HasPrefix(response.header.Get("Content-Disposition"), "attachment;") || response.header.Get("X-AegisMesh-Scan-Limit") != "8192" || len(response.body) == 0 {
				t.Fatal(response.header)
			}
			if strings.Contains(path, "/report") {
				if !strings.HasPrefix(response.header.Get("Content-Type"), "text/markdown") || strings.Contains(string(response.body), "\n# FORGED") || strings.Contains(string(response.body), "<script>") {
					t.Fatal("report injection")
				}
			}
			again := h.request(t, apiRequest{method: "GET", path: path, token: "synthetic-analyst"})
			requireStatus(t, again, 200)
			if string(response.body) != string(again.body) {
				t.Fatal("non-deterministic download")
			}
		})
	}
	audit := h.request(t, apiRequest{method: "GET", path: "/api/v1/audit", token: "synthetic-admin"})
	requireStatus(t, audit, 200)
	for _, action := range []string{"export.indicators", "session.report", "investigation.report"} {
		if !strings.Contains(string(audit.body), action) {
			t.Errorf("missing audit %s", action)
		}
	}
}

func TestAnalysisStrictQueries(t *testing.T) {
	h := newConsoleHarness(t, nil)
	id := sessionID(t, h)
	for _, path := range []string{
		"/api/v1/sessions?limit=201", "/api/v1/sessions?window=bad", "/api/v1/sessions?cursor=bad", "/api/v1/sessions?source=a&source=b", "/api/v1/sessions?source=" + strings.Repeat("x", 256),
		"/api/v1/sessions/" + id + "?limit=1", "/api/v1/sessions/bad", "/api/v1/coverage?window=bad", "/api/v1/coverage?limit=1",
		"/api/v1/export/indicators?window=24h&format=json", "/api/v1/export/indicators?format=txt", "/api/v1/export/indicators?source=x&window=24h&format=csv", "/api/v1/export/indicators?source=&format=txt", "/api/v1/export/indicators?session=bad&format=txt", "/api/v1/export/indicators?window=24h&window=1h&format=txt",
		"/api/v1/sessions/" + id + "/report?anything=1",
	} {
		t.Run(path, func(t *testing.T) {
			requireStatus(t, h.request(t, apiRequest{method: "GET", path: path, token: "synthetic-admin"}), 400)
		})
	}
}

func TestSessionPaginationFilterBindingAndStaleness(t *testing.T) {
	var index *evidenceindex.Index
	h := newConsoleHarness(t, func(opts *console.Options) {
		index = opts.Index
		for i := 0; i < 3; i++ {
			e, err := event.New(&event.Sequencer{}, "synthetic", event.SensorRef{ID: "web", Kind: "http"}, "interaction", json.RawMessage(fmt.Sprintf(`{"remote_host":"192.0.2.%d","method":"GET","path":"/"}`, i+1)), nil)
			if err != nil {
				t.Fatal(err)
			}
			e.Time = time.Now().Add(-time.Duration(i+1) * time.Minute)
			index.Add(e)
		}
	})
	response := h.request(t, apiRequest{method: "GET", path: "/api/v1/sessions?limit=1", token: "synthetic-viewer"})
	requireStatus(t, response, 200)
	var list struct {
		Sessions []evidenceview.Session `json:"sessions"`
		Cursor   string                 `json:"next_cursor"`
	}
	if json.Unmarshal(response.body, &list) != nil || len(list.Sessions) != 1 || list.Cursor == "" {
		t.Fatal(string(response.body))
	}
	cursor := url.QueryEscape(list.Cursor)
	next := h.request(t, apiRequest{method: "GET", path: "/api/v1/sessions?limit=2&cursor=" + cursor, token: "synthetic-viewer"})
	requireStatus(t, next, 200)
	for _, suffix := range []string{"&source=other", "&window=1h", "x"} {
		requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/sessions?cursor=" + cursor + suffix, token: "synthetic-viewer"}), 400)
	}
	e, _ := event.New(&event.Sequencer{}, "synthetic", event.SensorRef{ID: "web", Kind: "http"}, "interaction", json.RawMessage(`{"remote_host":"192.0.2.99"}`), nil)
	index.Add(e)
	requireStatus(t, h.request(t, apiRequest{method: "GET", path: "/api/v1/sessions?cursor=" + cursor, token: "synthetic-viewer"}), 400)
}

func TestAnalysisTenantIsolation(t *testing.T) {
	h, _ := tenantHarness(t, nil)
	id := sessionID(t, h)
	for _, path := range []string{"/api/v1/sessions/" + id, "/api/v1/sessions/" + id + "/report", "/api/v1/export/indicators?session=" + id + "&format=txt"} {
		requireStatus(t, h.request(t, apiRequest{method: "GET", path: path, token: "bravo-admin"}), 404)
	}
	for _, path := range []string{"/api/v1/sessions", "/api/v1/coverage", "/api/v1/export/indicators?source=127.0.0.1&format=txt"} {
		response := h.request(t, apiRequest{method: "GET", path: path, token: "bravo-admin"})
		requireStatus(t, response, 200)
		if strings.Contains(string(response.body), h.eventID) || strings.Contains(string(response.body), "127.0.0.1") {
			t.Fatal("tenant leaked", string(response.body))
		}
	}
}

func TestDownloadAuditFailureReturnsNoAttachment(t *testing.T) {
	for _, kind := range []string{"indicators", "report"} {
		t.Run(kind, func(t *testing.T) {
			h := newConsoleHarness(t, nil)
			id := sessionID(t, h)
			path := "/api/v1/export/indicators?window=24h&format=txt"
			if kind == "report" {
				path = "/api/v1/sessions/" + id + "/report"
			}
			h.server.CloseAuditForTest()
			response := h.request(t, apiRequest{method: "GET", path: path, token: "synthetic-analyst"})
			requireStatus(t, response, 503)
			if response.header.Get("Content-Disposition") != "" || strings.Contains(string(response.body), "127.0.0.1") {
				t.Fatal("released sensitive bytes", string(response.body))
			}
		})
	}
}
