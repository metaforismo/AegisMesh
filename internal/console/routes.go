package console

import (
	"net/http"
)

type routeSpec struct {
	pattern string
	role    string
	group   string
	handle  func(*Server, http.ResponseWriter, *http.Request, caller)
}

func (s *Server) routeTable() []routeSpec {
	return append(s.fleetRoutes(), []routeSpec{
		{pattern: "GET /api/v1/auth/oidc/login", group: "oidc", handle: (*Server).oidcLogin},
		{pattern: "GET /api/v1/auth/oidc/callback", group: "oidc", handle: (*Server).oidcCallback},
		{pattern: "POST /api/v1/session/tenant", role: "viewer", group: "session", handle: (*Server).switchTenant},
		{
			pattern: "GET /api/v1/meta",
			role:    "",
			group:   "meta",
			handle:  (*Server).meta,
		},
		{
			pattern: "POST /api/v1/session",
			role:    "",
			group:   "session",
			handle:  (*Server).login,
		},
		{
			pattern: "GET /api/v1/session",
			role:    "viewer",
			group:   "session",
			handle:  (*Server).session,
		},
		{
			pattern: "DELETE /api/v1/session",
			role:    "viewer",
			group:   "session",
			handle:  (*Server).logout,
		},
		{
			pattern: "GET /api/v1/overview",
			role:    "viewer",
			group:   "overview",
			handle:  (*Server).overview,
		},
		{
			pattern: "GET /api/v1/events",
			role:    "viewer",
			group:   "events",
			handle:  (*Server).events,
		},
		{
			pattern: "GET /api/v1/events/stream",
			role:    "viewer",
			group:   "stream",
			handle:  (*Server).stream,
		},
		{
			pattern: "GET /api/v1/events/{id}",
			role:    "viewer",
			group:   "event",
			handle:  (*Server).eventDetail,
		},
		{
			pattern: "GET /api/v1/sources",
			role:    "viewer",
			group:   "sources",
			handle:  (*Server).sources,
		},
		{
			pattern: "GET /api/v1/sources/{source}",
			role:    "viewer",
			group:   "source",
			handle:  (*Server).source,
		},
		{
			pattern: "GET /api/v1/sensors",
			role:    "viewer",
			group:   "sensors",
			handle:  (*Server).sensors,
		},
		{
			pattern: "GET /api/v1/rules",
			role:    "viewer",
			group:   "rules",
			handle:  (*Server).ruleList,
		},
		{
			pattern: "GET /api/v1/recommendations",
			role:    "viewer",
			group:   "recommendations",
			handle:  (*Server).recommendations,
		},
		{
			pattern: "GET /api/v1/node",
			role:    "viewer",
			group:   "node",
			handle:  (*Server).node,
		},
		{
			pattern: "GET /api/v1/investigations",
			role:    "viewer",
			group:   "investigations",
			handle:  (*Server).listCases,
		},
		{
			pattern: "POST /api/v1/investigations",
			role:    "analyst",
			group:   "investigations",
			handle:  (*Server).createCase,
		},
		{
			pattern: "GET /api/v1/investigations/{id}",
			role:    "viewer",
			group:   "investigations",
			handle:  (*Server).getCase,
		},
		{
			pattern: "PATCH /api/v1/investigations/{id}",
			role:    "analyst",
			group:   "investigations",
			handle:  (*Server).patchCase,
		},
		{
			pattern: "POST /api/v1/investigations/{id}/notes",
			role:    "analyst",
			group:   "investigations",
			handle:  (*Server).noteCase,
		},
		{
			pattern: "PUT /api/v1/investigations/{id}/events/{event_id}",
			role:    "analyst",
			group:   "investigations",
			handle:  (*Server).attachCase,
		},
		{
			pattern: "DELETE /api/v1/investigations/{id}/events/{event_id}",
			role:    "analyst",
			group:   "investigations",
			handle:  (*Server).attachCase,
		},
		{
			pattern: "GET /api/v1/audit",
			role:    "admin",
			group:   "audit",
			handle:  (*Server).readAudit,
		},
		{
			pattern: "GET /api/v1/audit/verify",
			role:    "admin",
			group:   "audit",
			handle:  (*Server).verifyAudit,
		},
	}...)
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
