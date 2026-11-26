package console

import (
	"net/http"
	"time"
)

func (s *Server) overview(w http.ResponseWriter, r *http.Request, _ caller) {
	values, ok := query(w, r, "window")
	if !ok {
		return
	}

	now := time.Now().UTC()
	overview, err := s.index.Overview(values.Get("window"), now)
	if err != nil {
		invalid(w)
		return
	}

	if s.fleetHub != nil && s.fleetHub.EvidenceEnabled() {
		byNode := s.index.ByNode(overview.Window, now)
		overview.ByNode = &byNode
	}
	for _, investigation := range s.cases.List("") {
		if investigation.Status != "closed" {
			overview.OpenInvestigations++
		}
	}

	send(w, 200, overview)
}

func (s *Server) recommendations(w http.ResponseWriter, r *http.Request, _ caller) {
	values, ok := query(w, r, "limit")
	if !ok {
		return
	}

	count, err := limit(values, 20, 1000)
	if err != nil {
		invalid(w)
		return
	}

	report, err := s.recommendationReport(count)
	if err != nil {
		fail(w, 503, "unavailable", "indexed evidence cannot produce a verified recommendation report")
		return
	}

	send(w, 200, report)
}
