package console

import (
	"net/http"

	"github.com/metaforismo/aegismesh/internal/evidencereport"
	"github.com/metaforismo/aegismesh/internal/evidenceview"
	"github.com/metaforismo/aegismesh/internal/recommend"
)

func (s *Server) sessionReport(w http.ResponseWriter, r *http.Request, credentials caller) {
	if _, ok := query(w, r); !ok {
		return
	}
	session, snapshot, ok := s.findAttackerSession(w, r.PathValue("id"))
	if !ok {
		return
	}
	s.writeReport(w, r, credentials, evidencereport.Input{
		Tenant: s.tenantID, Scope: "Session " + session.ID,
		Bounds: snapshot, Events: session.Events,
	}, "session.report", session.ID)
}

func (s *Server) investigationReport(w http.ResponseWriter, r *http.Request, credentials caller) {
	if _, ok := query(w, r); !ok {
		return
	}
	investigation, err := s.cases.Get(r.PathValue("id"))
	if err != nil {
		s.caseError(w, err)
		return
	}
	snapshot := s.index.SharedAnalysis()
	s.writeReport(w, r, credentials, evidencereport.Input{
		Tenant: s.tenantID, Scope: "Investigation " + investigation.ID,
		Bounds: snapshot, Events: investigationEvents(snapshot.Events, investigation.EventIDs),
		Investigation: &investigation,
	}, "investigation.report", investigation.ID)
}

func (s *Server) writeReport(w http.ResponseWriter, r *http.Request, credentials caller, input evidencereport.Input, action, id string) {
	ids := []string{}
	for _, e := range evidenceview.Chronological(input.Events) {
		if e.Node != nil || len(ids) >= recommend.MaxEvidence {
			input.RecommendationExcluded++
			continue
		}
		ids = append(ids, e.ID)
	}
	envelopes, missing, err := s.index.LocalEvidence(ids)
	if err != nil {
		fail(w, 503, "unavailable", "recommendation input exceeds limits")
		return
	}
	input.RecommendationMissing = missing
	input.Recommendations, err = recommend.Generate(envelopes, recommend.Options{Limit: 20})
	if err != nil {
		fail(w, 503, "unavailable", "indexed evidence cannot produce verified recommendations")
		return
	}
	body, err := evidencereport.Render(input)
	if err != nil {
		fail(w, 503, "unavailable", "report exceeds 2 MiB; narrow scope")
		return
	}
	if s.record(r, credentials.session.Principal, action, id, "ok") != nil {
		fail(w, 503, "unavailable", "audit trail is unavailable")
		return
	}
	setBoundsHeaders(w, input.Bounds)
	attachment(w, body, "text/markdown; charset=utf-8", "aegismesh-observation-report.md")
}
