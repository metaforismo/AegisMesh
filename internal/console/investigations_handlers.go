package console

import (
	"errors"
	"net/http"

	"github.com/metaforismo/aegismesh/internal/console/investigations"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

type investigationDetail struct {
	investigations.Investigation
	Notes  []investigations.Note   `json:"notes"`
	Events []evidenceindex.Summary `json:"events"`
}

func (s *Server) caseEvents(investigation investigations.Investigation) investigationDetail {
	ids := make(map[string]bool, len(investigation.EventIDs))
	for _, id := range investigation.EventIDs {
		ids[id] = true
	}

	summaries := []evidenceindex.Summary{}
	for _, summary := range s.index.Summaries() {
		if ids[summary.ID] {
			summaries = append(summaries, summary)
		}
	}

	return investigationDetail{
		Investigation: investigation,
		Notes:         append([]investigations.Note{}, investigation.Notes...),
		Events:        summaries,
	}
}

func (s *Server) listCases(w http.ResponseWriter, r *http.Request, _ caller) {
	values, ok := query(w, r, "status")
	if !ok {
		return
	}

	status := values.Get("status")
	if status != "" && status != "open" && status != "monitoring" && status != "closed" {
		invalid(w)
		return
	}

	send(w, 200, map[string]any{"investigations": s.cases.List(status)})
}

func (s *Server) getCase(w http.ResponseWriter, r *http.Request, _ caller) {
	investigation, err := s.cases.Get(r.PathValue("id"))
	if err != nil {
		s.caseError(w, err)
		return
	}

	send(w, 200, s.caseEvents(investigation))
}

func (s *Server) caseError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, investigations.ErrInvalid):
		fail(w, 400, "invalid_argument", "invalid investigation fields")
	case errors.Is(err, investigations.ErrNotFound):
		fail(w, 404, "not_found", "investigation not found")
	case errors.Is(err, investigations.ErrLimit):
		fail(w, 409, "conflict", "investigation quota reached")
	default:
		fail(w, 503, "unavailable", "investigation state could not be persisted")
	}
}

func (s *Server) caseResult(
	w http.ResponseWriter,
	r *http.Request,
	credentials caller,
	investigation investigations.Investigation,
	err error,
	action string,
	status int,
) {
	if err != nil {
		if s.record(r, credentials.session.Principal, action, "", "error") != nil {
			fail(w, 503, "unavailable", "audit trail is unavailable")
			return
		}
		s.caseError(w, err)
		return
	}

	if s.record(r, credentials.session.Principal, action, investigation.ID, "ok") != nil {
		fail(w, 503, "unavailable", "state saved but audit append failed; inspect state before retrying")
		return
	}

	send(w, status, s.caseEvents(investigation))
}

func (s *Server) createCase(w http.ResponseWriter, r *http.Request, credentials caller) {
	var body investigations.Create
	if !strictBody(w, r, &body) {
		return
	}

	investigation, err := s.cases.Create(body, credentials.session.Principal.Name)
	s.caseResult(w, r, credentials, investigation, err, "investigation.create", 201)
}

func (s *Server) patchCase(w http.ResponseWriter, r *http.Request, credentials caller) {
	var body investigations.Patch
	if !strictBody(w, r, &body) {
		return
	}

	investigation, err := s.cases.Patch(r.PathValue("id"), body)
	s.caseResult(w, r, credentials, investigation, err, "investigation.update", 200)
}

func (s *Server) noteCase(w http.ResponseWriter, r *http.Request, credentials caller) {
	var body struct {
		Text string `json:"text"`
	}

	if !strictBody(w, r, &body) {
		return
	}

	investigation, err := s.cases.AddNote(r.PathValue("id"), body.Text, credentials.session.Principal.Name)
	s.caseResult(w, r, credentials, investigation, err, "investigation.note", 201)
}

func (s *Server) attachCase(w http.ResponseWriter, r *http.Request, credentials caller) {
	attach := r.Method == "PUT"
	action := "investigation.detach"
	if attach {
		action = "investigation.attach"
	}

	investigation, err := s.cases.Attach(r.PathValue("id"), r.PathValue("event_id"), attach)
	s.caseResult(w, r, credentials, investigation, err, action, 200)
}
