package console

import (
	"net/http"
	"strconv"
	"time"

	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/evidenceview"
	"github.com/metaforismo/aegismesh/internal/indicatorexport"
)

func (s *Server) exportIndicators(w http.ResponseWriter, r *http.Request, credentials caller) {
	values, ok := query(w, r, "session", "source", "investigation", "window", "format")
	if !ok {
		return
	}
	format := values.Get("format")
	if format != "stix" && format != "csv" && format != "txt" {
		invalid(w)
		return
	}
	if !validExportScope(values) {
		invalid(w)
		return
	}

	snapshot, events, ok := s.exportScope(w, r)
	if !ok {
		return
	}
	body, result, err := indicatorexport.Render(events, format, s.instanceID+":"+s.tenantID)
	if err != nil {
		fail(w, 503, "unavailable", "indicator download exceeds limits; narrow scope")
		return
	}
	target := values.Get("session")
	if target == "" {
		target = values.Get("investigation")
	}
	if s.record(r, credentials.session.Principal, "export.indicators", target, "ok") != nil {
		fail(w, 503, "unavailable", "audit trail is unavailable")
		return
	}
	setBoundsHeaders(w, snapshot)
	w.Header().Set("X-AegisMesh-Skipped-Non-IP-Sources", strconv.Itoa(result.SkippedSource))
	w.Header().Set("X-AegisMesh-Skipped-Non-IP-Events", strconv.Itoa(result.SkippedEvents))
	contentType := map[string]string{"stix": "application/stix+json", "csv": "text/csv; charset=utf-8", "txt": "text/plain; charset=utf-8"}[format]
	ext := format
	if format == "stix" {
		ext = "json"
	}
	attachment(w, body, contentType, "aegismesh-indicators."+ext)
}

func investigationEvents(events []evidenceindex.Summary, ids []string) []evidenceindex.Summary {
	selected := map[string]bool{}
	for _, id := range ids {
		selected[id] = true
	}
	out := []evidenceindex.Summary{}
	for _, e := range events {
		if e.Node == nil && selected[e.ID] {
			out = append(out, e)
		}
	}
	return out
}

func setBoundsHeaders(w http.ResponseWriter, snapshot evidenceindex.Snapshot) {
	w.Header().Set("X-AegisMesh-Index-History", snapshot.Index.History)
	w.Header().Set("X-AegisMesh-Index-Events", strconv.Itoa(snapshot.Index.Events))
	w.Header().Set("X-AegisMesh-Scanned-Events", strconv.Itoa(snapshot.Scanned))
	w.Header().Set("X-AegisMesh-Scan-Limit", strconv.Itoa(snapshot.Limit))
	w.Header().Set("X-AegisMesh-Scan-Truncated", strconv.FormatBool(snapshot.Truncated))
}

func attachment(w http.ResponseWriter, body []byte, contentType, name string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(200)
	_, _ = w.Write(body)
}

func (s *Server) exportScope(w http.ResponseWriter, r *http.Request) (evidenceindex.Snapshot, []evidenceindex.Summary, bool) {
	values := r.URL.Query()
	analysis := s.analysis()
	snapshot := analysis.snapshot
	events := []evidenceindex.Summary{}
	switch {
	case values.Get("session") != "":
		if !evidenceindex.ValidID(values.Get("session")) {
			invalid(w)
			return evidenceindex.Snapshot{}, nil, false
		}
		found := false
		for _, session := range analysis.Sessions() {
			if session.ID == values.Get("session") {
				events, found = session.Events, true
				break
			}
		}
		if !found {
			fail(w, 404, "not_found", "session is no longer indexed")
			return evidenceindex.Snapshot{}, nil, false
		}
	case values.Get("investigation") != "":
		investigation, err := s.cases.Get(values.Get("investigation"))
		if err != nil {
			s.caseError(w, err)
			return evidenceindex.Snapshot{}, nil, false
		}
		events = investigationEvents(snapshot.Events, investigation.EventIDs)
	case values.Get("source") != "":
		for _, e := range snapshot.Events {
			if e.Source == values.Get("source") {
				events = append(events, e)
			}
		}
	default:
		duration, _, err := evidenceindex.Window(values.Get("window"))
		if err != nil {
			invalid(w)
			return evidenceindex.Snapshot{}, nil, false
		}
		now := time.Now().UTC()
		for _, e := range snapshot.Events {
			if !evidenceview.Time(e).Before(now.Add(-duration)) && !evidenceview.Time(e).After(now) {
				events = append(events, e)
			}
		}
	}

	return snapshot, events, true
}
