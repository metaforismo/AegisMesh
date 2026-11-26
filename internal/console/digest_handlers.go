package console

import (
	"errors"
	"net/http"
	"time"

	"github.com/metaforismo/aegismesh/internal/console/settings"
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
	analysis := s.analysis()
	snapshot := analysis.snapshot
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
	proposals, missing, err := s.digestRecommendations(snapshot, ids)
	if errors.Is(err, errDigestInputs) {
		fail(w, 503, "unavailable", "digest recommendation inputs exceed limits")
		return
	}
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
		Organization:           s.live.value(settings.OrganizationName),
		Window:                 window,
		AsOf:                   now,
		Bounds:                 snapshot,
		OpenInvestigations:     &open,
		Recommendations:        proposals,
		RecommendationExcluded: excluded,
		RecommendationMissing:  missing,
		Sessions:               analysis.Sessions(),
	})
	if err != nil {
		invalid(w)
		return
	}
	boundedJSON(w, report)
}
