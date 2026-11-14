package console

import (
	"net/http"
	"time"

	"github.com/metaforismo/aegismesh/internal/recommend"
)

func (s *Server) overview(w http.ResponseWriter, r *http.Request, _ caller) {
	values, ok := query(w, r, "window")
	if !ok {
		return
	}

	overview, err := s.index.Overview(values.Get("window"), time.Now().UTC())
	if err != nil {
		invalid(w)
		return
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

	report, err := recommend.Generate(s.index.Envelopes(recommend.MaxEvidence), recommend.Options{Limit: count})
	if err != nil {
		fail(w, 503, "unavailable", "indexed evidence cannot produce a verified recommendation report")
		return
	}

	send(w, 200, report)
}
