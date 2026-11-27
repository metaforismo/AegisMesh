package console

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/metaforismo/aegismesh/internal/console/investigations"
	"github.com/metaforismo/aegismesh/internal/console/notifications"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/evidenceview"
)

// caseFromBody is the optional body of POST /campaigns|sessions/{id}/investigation.
type caseFromBody struct {
	Title     *string `json:"title"`
	Priority  string  `json:"priority"`
	MaxEvents *int    `json:"max_events"`
}

func (b caseFromBody) limit() (int, bool) {
	if b.MaxEvents == nil {
		return investigations.MaxEvents, true
	}
	return *b.MaxEvents, *b.MaxEvents >= 1 && *b.MaxEvents <= investigations.MaxEvents
}

func localEvent(e evidenceindex.Summary) bool { return e.Node == nil }

// safeList renders at most max values that pass a grammar check, joined by commas.
func safeList(values []string, max int, safe func(string) string) string {
	out := []string{}
	for _, value := range values {
		if value = safe(value); value != "" && len(out) < max {
			out = append(out, value)
		}
	}
	if len(out) == 0 {
		return "none"
	}
	if len(values) > len(out) {
		return strings.Join(out, ", ") + ", …"
	}
	return strings.Join(out, ", ")
}

func severityText(value string) string {
	if value == "" {
		return "none"
	}
	return value
}

func eventIDs(events []evidenceindex.Summary) []string {
	ids := make([]string, 0, len(events))
	for _, e := range events {
		ids = append(ids, e.ID)
	}
	return ids
}

// createFromOrigin persists the seeded investigation and audits it as
// investigation.create with the origin in the detail. Two identical requests
// create two investigations; the console disables the button while one is in
// flight.
func (s *Server) createFromOrigin(w http.ResponseWriter, r *http.Request, credentials caller,
	body caseFromBody, title string, events []evidenceindex.Summary, seed investigations.Seed) {
	if body.Title != nil {
		title = *body.Title
	}
	input := investigations.Create{Title: title, Priority: body.Priority, EventIDs: eventIDs(events)}
	investigation, err := s.cases.CreateBy(input, actorOf(credentials), &seed)
	detail := fmt.Sprintf("origin=%s:%s events=%d", seed.Origin.Kind, seed.Origin.ID, len(events))
	s.caseResultDetail(w, r, credentials, investigation, err, "investigation.create", detail, 201)
}

func (s *Server) campaignCase(w http.ResponseWriter, r *http.Request, credentials caller) {
	var body caseFromBody
	if !strictBody(w, r, &body) {
		return
	}
	max, valid := body.limit()
	id := r.PathValue("id")
	if !valid || !campaignIDPattern.MatchString(id) {
		invalid(w)
		return
	}
	set, _ := s.campaignSet()
	for _, campaign := range set.Campaigns {
		if campaign.ID != id {
			continue
		}
		events := campaign.EventSample(max, localEvent)
		forwarded := campaign.EventCount - len(campaign.EventSample(campaign.EventCount, localEvent))
		note := fmt.Sprintf("Opened from campaign %s. Basis: %s. %d sessions from %d sources (%s), %d events in the retained sample; "+
			"%d attached, newest per session first, limit %d.",
			campaign.ID, strings.Join(campaign.Basis, ", "), campaign.SessionCount, campaign.SourceCount,
			safeList(campaign.Sources, 5, notifications.SafeSource), campaign.EventCount, len(events), max)
		if forwarded > 0 {
			note += fmt.Sprintf(" %d forwarded events are not attachable to an investigation and were left out.", forwarded)
		}
		note += fmt.Sprintf(" Rules: %s. Highest severity: %s.\n\nCaveats:\n- %s",
			safeList(campaign.RuleIDs, 20, notifications.SafeRule), severityText(campaign.MaxSeverity),
			strings.Join(evidenceview.CampaignCaveats, "\n- "))
		title := fmt.Sprintf("Campaign %s: %d sources, %d sessions", campaign.ID, campaign.SourceCount, campaign.SessionCount)
		s.createFromOrigin(w, r, credentials, body, title, events, investigations.Seed{
			Origin:       investigations.Origin{Kind: investigations.OriginCampaign, ID: campaign.ID},
			Note:         note,
			AttachDetail: fmt.Sprintf("attached %d events from campaign %s", len(events), campaign.ID),
		})
		return
	}
	fail(w, 404, "not_found", "campaign is not present in the retained analysis sample")
}

func (s *Server) sessionCase(w http.ResponseWriter, r *http.Request, credentials caller) {
	var body caseFromBody
	if !strictBody(w, r, &body) {
		return
	}
	max, valid := body.limit()
	if !valid {
		invalid(w)
		return
	}
	session, _, ok := s.findAttackerSession(w, r.PathValue("id"))
	if !ok {
		return
	}
	events := session.EventSample(max, localEvent)
	source := notifications.SafeSource(session.Source)
	note := fmt.Sprintf("Opened from session %s (source %s). %d events between %s and %s on sensors %s; %d attached, newest first, limit %d.",
		session.ID, severityText(source), session.EventCount, session.FirstSeen, session.LastSeen,
		safeList(session.Sensors, 10, notifications.SafeSensor), len(events), max)
	if forwarded := session.EventCount - len(session.EventSample(session.EventCount, localEvent)); forwarded > 0 {
		note += fmt.Sprintf(" %d forwarded events are not attachable to an investigation and were left out.", forwarded)
	}
	note += fmt.Sprintf(" Rules: %s. Highest severity: %s. Automation assessment: %s; actor assessment: %s. "+
		"Both are observations from timing and rule predicates, not attribution.\n\nCaveat: a session groups consecutive "+
		"retained events from one source key with gaps of at most 30 minutes; NAT, proxies and shared egress can merge or split real clients.",
		safeList(session.RuleIDs, 20, notifications.SafeRule), severityText(session.MaxSeverity),
		session.Automation.Assessment, session.Actor.Assessment)
	title := fmt.Sprintf("Session %s: %d events", session.ID[:12], session.EventCount)
	if source != "" {
		title = fmt.Sprintf("Session from %s: %d events", source, session.EventCount)
	}
	s.createFromOrigin(w, r, credentials, body, title, events, investigations.Seed{
		Origin:       investigations.Origin{Kind: investigations.OriginSession, ID: session.ID},
		Note:         note,
		AttachDetail: fmt.Sprintf("attached %d events from session %s", len(events), session.ID),
	})
}
