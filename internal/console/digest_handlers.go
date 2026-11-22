package console

import (
	"net/http"
	"time"

	"github.com/metaforismo/aegismesh/internal/digest"
	"github.com/metaforismo/aegismesh/internal/evidenceview"
	"github.com/metaforismo/aegismesh/internal/recommend"
)

func (s *Server) digest(w http.ResponseWriter, r *http.Request, _ caller) {
	values, ok := query(w, r, "window")
	if !ok {
		return
	}
	window := values.Get("window")
	if window == "" {
		window = "24h"
	}
	duration, err := digest.Window(window)
	if err != nil {
		invalid(w)
		return
	}
	now := time.Now().UTC()
	snapshot := s.index.Analysis()
	ids := []string{}
	excluded := 0
	for _, e := range snapshot.Events {
		timestamp := evidenceview.Time(e)
		if timestamp.Before(now.Add(-duration)) || !timestamp.Before(now) {
			continue
		}
		if e.Node != nil || len(ids) >= recommend.MaxEvidence {
			excluded++
			continue
		}
		ids = append(ids, e.ID)
	}
	envelopes, missing, err := s.index.LocalEvidence(ids)
	if err != nil {
		fail(w, 503, "unavailable", "digest recommendation inputs exceed limits")
		return
	}
	proposals, err := recommend.Generate(envelopes, recommend.Options{Limit: 20})
	if err != nil {
		fail(w, 503, "unavailable", "digest cannot produce verified recommendations")
		return
	}
	open := 0
	for _, item := range s.cases.List("") {
		if item.Status != "closed" {
			open++
		}
	}
	report, err := digest.Build(digest.Input{
		Tenant:                 s.tenantID,
		Window:                 window,
		AsOf:                   now,
		Bounds:                 snapshot,
		OpenInvestigations:     &open,
		Recommendations:        len(proposals.Recommendations),
		RecommendationExcluded: excluded,
		RecommendationMissing:  missing,
	})
	if err != nil {
		invalid(w)
		return
	}
	boundedJSON(w, report)
}
