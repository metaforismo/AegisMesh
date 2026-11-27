package console

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"sort"

	"github.com/metaforismo/aegismesh/internal/console/accounts"
	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/console/investigations"
	"github.com/metaforismo/aegismesh/internal/console/notifications"
	"github.com/metaforismo/aegismesh/internal/console/permission"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

// caseSummary is computed from the attached events still retained in the
// index; it is never persisted.
type caseSummary struct {
	Sources     int      `json:"sources"`
	Sensors     []string `json:"sensors"`
	FirstSeen   *string  `json:"first_seen"`
	LastSeen    *string  `json:"last_seen"`
	MaxSeverity string   `json:"max_severity"`
	RuleIDs     []string `json:"rule_ids"`
	// IndexedEvents counts attached references still retained; MissingEvents
	// counts references evicted from the bounded index.
	IndexedEvents int `json:"indexed_events"`
	MissingEvents int `json:"missing_events"`
}

type investigationDetail struct {
	investigations.Investigation
	Notes    []investigations.Note     `json:"notes"`
	Events   []evidenceindex.Summary   `json:"events"`
	Activity []investigations.Activity `json:"activity"`
	Summary  caseSummary               `json:"summary"`
}

type investigationItem struct {
	investigations.Investigation
	EventCount  int    `json:"event_count"`
	MaxSeverity string `json:"max_severity"`
}

func summarizeCase(events []evidenceindex.Summary, missing int) caseSummary {
	out := caseSummary{Sensors: []string{}, RuleIDs: []string{}, IndexedEvents: len(events), MissingEvents: missing}
	sources, sensors, rules := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, e := range events {
		if e.Source != "" {
			sources[e.Source] = true
		}
		sensors[e.Sensor.ID] = true
		for _, id := range e.RuleIDs {
			rules[id] = true
		}
		if evidenceindex.Rank(e.Severity) > evidenceindex.Rank(out.MaxSeverity) {
			out.MaxSeverity = e.Severity
		}
	}
	out.Sources = len(sources)
	for id := range sensors {
		out.Sensors = append(out.Sensors, id)
	}
	for id := range rules {
		out.RuleIDs = append(out.RuleIDs, id)
	}
	sort.Strings(out.Sensors)
	sort.Strings(out.RuleIDs)
	if len(events) > 0 {
		// Events are newest first.
		first, last := events[len(events)-1].Time, events[0].Time
		out.FirstSeen, out.LastSeen = &first, &last
	}
	return out
}

func (s *Server) caseEvents(investigation investigations.Investigation) investigationDetail {
	summaries, missing := s.index.LocalSummaries(investigation.EventIDs)
	activity := investigation.Activity
	if activity == nil {
		activity = []investigations.Activity{}
	}
	return investigationDetail{
		Investigation: investigation,
		Notes:         append([]investigations.Note{}, investigation.Notes...),
		Events:        summaries,
		Activity:      append([]investigations.Activity{}, activity...),
		Summary:       summarizeCase(summaries, missing),
	}
}

func (s *Server) listCases(w http.ResponseWriter, r *http.Request, credentials caller) {
	values, ok := query(w, r, "status", "assignee")
	if !ok {
		return
	}

	status := values.Get("status")
	if status != "" && status != "open" && status != "monitoring" && status != "closed" {
		invalid(w)
		return
	}
	var assignee *string
	switch value := values.Get("assignee"); {
	case !values.Has("assignee"):
	case value == "me":
		assignee = &credentials.session.Principal.ID
	case value == "none":
		empty := ""
		assignee = &empty
	case accounts.ValidPrincipalID(value):
		assignee = &value
	default:
		invalid(w)
		return
	}

	items := []investigationItem{}
	for _, investigation := range s.cases.Filter(status, assignee) {
		summaries, _ := s.index.LocalSummaries(investigation.EventIDs)
		item := investigationItem{Investigation: investigation, EventCount: len(investigation.EventIDs)}
		for _, e := range summaries {
			if evidenceindex.Rank(e.Severity) > evidenceindex.Rank(item.MaxSeverity) {
				item.MaxSeverity = e.Severity
			}
		}
		items = append(items, item)
	}
	send(w, 200, map[string]any{"investigations": items})
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
	s.caseResultDetail(w, r, credentials, investigation, err, action, "", status)
}

func (s *Server) caseResultDetail(
	w http.ResponseWriter, r *http.Request, credentials caller, investigation investigations.Investigation,
	err error, action, detail string, status int,
) {
	if err != nil {
		if s.recordDetail(r, credentials.session.Principal, action, "", "error", detail) != nil {
			fail(w, 503, "unavailable", "audit trail is unavailable")
			return
		}
		s.caseError(w, err)
		return
	}

	if s.recordDetail(r, credentials.session.Principal, action, investigation.ID, "ok", detail) != nil {
		fail(w, 503, "unavailable", "state saved but audit append failed; inspect state before retrying")
		return
	}

	send(w, status, s.caseEvents(investigation))
}

func actorOf(credentials caller) investigations.Actor {
	principal := credentials.session.Principal
	return investigations.Actor{ID: principal.ID, Name: principal.Name}
}

func (s *Server) createCase(w http.ResponseWriter, r *http.Request, credentials caller) {
	var body investigations.Create
	if !strictBody(w, r, &body) {
		return
	}

	investigation, err := s.cases.CreateBy(body, actorOf(credentials), nil)
	s.caseResult(w, r, credentials, investigation, err, "investigation.create", 201)
}

// principalInfo is the assignment projection of one principal of any source.
type principalInfo struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`
	role    string   `json:"-"`
	Tenants []string `json:"-"`
	active  bool
}

// principals lists config operators, managed accounts and OIDC identities.
func (s *Server) principals() []principalInfo {
	out := []principalInfo{}
	for _, operator := range s.auth.Operators() {
		out = append(out, principalInfo{ID: operator.ID, Name: operator.Name, Kind: "person", role: operator.Role,
			Tenants: operator.Tenants, active: s.cfg.TokenEnabled()})
	}
	for _, account := range s.accounts.List() {
		out = append(out, principalInfo{ID: account.ID, Name: account.Name, Kind: account.Kind, role: account.Role,
			Tenants: account.Tenants, active: account.Status == accounts.StatusActive})
	}
	for _, identity := range s.accounts.Identities() {
		out = append(out, principalInfo{ID: identity.ID, Name: identity.Name, Kind: "person", role: identity.Role,
			Tenants: identity.Tenants, active: true})
	}
	return out
}

// assignable returns the active principals of this tenant whose role grants
// investigations.read, sorted by name.
func (s *Server) assignable() []principalInfo {
	out := []principalInfo{}
	for _, info := range s.principals() {
		if info.active && slices.Contains(info.Tenants, s.tenantID) &&
			s.grants(auth.Principal{Role: info.role}).has(permission.InvestigationsRead) {
			out = append(out, info)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (s *Server) assignees(w http.ResponseWriter, r *http.Request, _ caller) {
	if _, ok := query(w, r); !ok {
		return
	}
	send(w, 200, map[string]any{"assignees": s.assignable()})
}

func (s *Server) patchCase(w http.ResponseWriter, r *http.Request, credentials caller) {
	var body struct {
		Title    *string         `json:"title"`
		Status   *string         `json:"status"`
		Priority *string         `json:"priority"`
		Assignee json.RawMessage `json:"assignee"`
	}
	if !strictBody(w, r, &body) {
		return
	}
	patch := investigations.Patch{Title: body.Title, Status: body.Status, Priority: body.Priority}
	if body.Assignee != nil {
		var id *string
		if json.Unmarshal(body.Assignee, &id) != nil {
			invalid(w)
			return
		}
		patch.Assign = &investigations.Actor{}
		if id != nil {
			found := false
			for _, info := range s.assignable() {
				if info.ID == *id {
					patch.Assign, found = &investigations.Actor{ID: info.ID, Name: info.Name}, true
				}
			}
			if !found {
				if s.record(r, credentials.session.Principal, "investigation.assign", r.PathValue("id"), "denied") != nil {
					fail(w, 503, "unavailable", "audit trail is unavailable")
					return
				}
				fail(w, 400, "invalid_argument",
					"assignee must be an active principal of this tenant whose role grants investigations.read")
				return
			}
		}
	}

	investigation, previous, err := s.cases.PatchBy(r.PathValue("id"), patch, actorOf(credentials))
	if patch.Assign == nil {
		s.caseResult(w, r, credentials, investigation, err, "investigation.update", 200)
		return
	}
	// A patch that also changes other fields is audited as both actions.
	if patch.Title != nil || patch.Status != nil || patch.Priority != nil {
		outcome, target := "ok", investigation.ID
		if err != nil {
			outcome, target = "error", ""
		}
		if s.record(r, credentials.session.Principal, "investigation.update", target, outcome) != nil {
			fail(w, 503, "unavailable", "audit trail is unavailable")
			return
		}
	}
	assigned, detail := patch.Assign.ID, "assignee=none"
	if assigned != "" {
		detail = "assignee=" + assigned
	}
	// The new assignee (never the actor assigning to themselves) gets an
	// assignment notification in this tenant only.
	if err == nil && assigned != "" && assigned != previous && assigned != credentials.session.Principal.ID {
		s.notify([]string{s.tenantID}, notifications.Assignment(assigned, investigation.ID, s.now().UTC()))
	}
	s.caseResultDetail(w, r, credentials, investigation, err, "investigation.assign", detail, 200)
}

func (s *Server) noteCase(w http.ResponseWriter, r *http.Request, credentials caller) {
	var body struct {
		Text string `json:"text"`
	}

	if !strictBody(w, r, &body) {
		return
	}

	investigation, err := s.cases.NoteBy(r.PathValue("id"), body.Text, actorOf(credentials))
	s.caseResult(w, r, credentials, investigation, err, "investigation.note", 201)
}

func (s *Server) attachCase(w http.ResponseWriter, r *http.Request, credentials caller) {
	attach := r.Method == "PUT"
	action := "investigation.detach"
	if attach {
		action = "investigation.attach"
	}

	investigation, err := s.cases.AttachBy(r.PathValue("id"), r.PathValue("event_id"), attach, actorOf(credentials))
	s.caseResult(w, r, credentials, investigation, err, action, 200)
}
