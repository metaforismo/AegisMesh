package console

import (
	"net/http"
)

type routeSpec struct {
	pattern string
	role    string
	group   string
	handle  func(http.ResponseWriter, *http.Request, caller)
}

func (s *Server) routeTable() []routeSpec {
	return []routeSpec{
		{
			pattern: "GET /api/v1/meta",
			role:    "",
			group:   "meta",
			handle:  s.meta,
		},
		{
			pattern: "POST /api/v1/session",
			role:    "",
			group:   "session",
			handle:  s.login,
		},
		{
			pattern: "GET /api/v1/session",
			role:    "viewer",
			group:   "session",
			handle:  s.session,
		},
		{
			pattern: "DELETE /api/v1/session",
			role:    "viewer",
			group:   "session",
			handle:  s.logout,
		},
		{
			pattern: "GET /api/v1/overview",
			role:    "viewer",
			group:   "overview",
			handle:  s.overview,
		},
		{
			pattern: "GET /api/v1/events",
			role:    "viewer",
			group:   "events",
			handle:  s.events,
		},
		{
			pattern: "GET /api/v1/events/stream",
			role:    "viewer",
			group:   "stream",
			handle:  s.stream,
		},
		{
			pattern: "GET /api/v1/events/{id}",
			role:    "viewer",
			group:   "event",
			handle:  s.eventDetail,
		},
		{
			pattern: "GET /api/v1/sources",
			role:    "viewer",
			group:   "sources",
			handle:  s.sources,
		},
		{
			pattern: "GET /api/v1/sources/{source}",
			role:    "viewer",
			group:   "source",
			handle:  s.source,
		},
		{
			pattern: "GET /api/v1/sensors",
			role:    "viewer",
			group:   "sensors",
			handle:  s.sensors,
		},
		{
			pattern: "GET /api/v1/rules",
			role:    "viewer",
			group:   "rules",
			handle:  s.ruleList,
		},
		{
			pattern: "GET /api/v1/recommendations",
			role:    "viewer",
			group:   "recommendations",
			handle:  s.recommendations,
		},
		{
			pattern: "GET /api/v1/node",
			role:    "viewer",
			group:   "node",
			handle:  s.node,
		},
		{
			pattern: "GET /api/v1/investigations",
			role:    "viewer",
			group:   "investigations",
			handle:  s.listCases,
		},
		{
			pattern: "POST /api/v1/investigations",
			role:    "analyst",
			group:   "investigations",
			handle:  s.createCase,
		},
		{
			pattern: "GET /api/v1/investigations/{id}",
			role:    "viewer",
			group:   "investigations",
			handle:  s.getCase,
		},
		{
			pattern: "PATCH /api/v1/investigations/{id}",
			role:    "analyst",
			group:   "investigations",
			handle:  s.patchCase,
		},
		{
			pattern: "POST /api/v1/investigations/{id}/notes",
			role:    "analyst",
			group:   "investigations",
			handle:  s.noteCase,
		},
		{
			pattern: "PUT /api/v1/investigations/{id}/events/{event_id}",
			role:    "analyst",
			group:   "investigations",
			handle:  s.attachCase,
		},
		{
			pattern: "DELETE /api/v1/investigations/{id}/events/{event_id}",
			role:    "analyst",
			group:   "investigations",
			handle:  s.attachCase,
		},
		{
			pattern: "GET /api/v1/audit",
			role:    "admin",
			group:   "audit",
			handle:  s.readAudit,
		},
		{
			pattern: "GET /api/v1/audit/verify",
			role:    "admin",
			group:   "audit",
			handle:  s.verifyAudit,
		},
	}
}

func (s *Server) routes() {
	for _, route := range s.routeTable() {
		s.route(route.pattern, route.role, route.group, route.handle)
	}

	s.mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		s.requests.Inc("unknown")
		fail(w, 404, "not_found", "API route not found")
	})
	s.mux.HandleFunc("/", s.static)
}
