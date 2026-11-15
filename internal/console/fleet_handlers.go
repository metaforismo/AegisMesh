package console

import (
	"net/http"

	"github.com/metaforismo/aegismesh/internal/console/audit"
	"github.com/metaforismo/aegismesh/internal/fleet/hub"
	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
)

func (s *Server) fleetRoutes() []routeSpec {
	return []routeSpec{
		{
			pattern: "GET /api/v1/fleet",
			role:    "viewer",
			group:   "fleet",
			handle:  (*Server).fleet,
		},
		{
			pattern: "GET /api/v1/fleet/nodes",
			role:    "viewer",
			group:   "fleet-nodes",
			handle:  (*Server).fleetNodes,
		},
		{
			pattern: "GET /api/v1/fleet/nodes/{id}",
			role:    "viewer",
			group:   "fleet-nodes",
			handle:  (*Server).fleetNode,
		},
		{
			pattern: "POST /api/v1/fleet/nodes/{id}/revoke",
			role:    "admin",
			group:   "fleet-nodes",
			handle:  (*Server).fleetRevoke,
		},
		{
			pattern: "GET /api/v1/fleet/enrollment-tokens",
			role:    "admin",
			group:   "fleet-tokens",
			handle:  (*Server).fleetTokens,
		},
		{
			pattern: "POST /api/v1/fleet/enrollment-tokens",
			role:    "admin",
			group:   "fleet-tokens",
			handle:  (*Server).fleetMint,
		},
		{
			pattern: "DELETE /api/v1/fleet/enrollment-tokens/{id}",
			role:    "admin",
			group:   "fleet-tokens",
			handle:  (*Server).fleetDeleteToken,
		},
	}
}

// RecordFleet adds fixed machine-authored metadata to the console's existing audit chain.
func (s *Server) RecordFleet(action, target, outcome string) error {
	return s.RecordFleetTenant(s.cfg.LocalTenant, action, target, outcome)
}

// RecordFleetTenant appends machine observations only to their owning audit chain.
func (s *Server) RecordFleetTenant(name, action, target, outcome string) error {
	view := s.views[name]
	if view == nil {
		return audit.ErrAudit
	}
	return view.audit.Append(audit.Record{
		Actor:   "fleet",
		Role:    "agent",
		Action:  action,
		Target:  target,
		Outcome: outcome,
	})
}

func (s *Server) fleet(w http.ResponseWriter, r *http.Request, _ caller) {
	if _, ok := query(w, r); !ok {
		return
	}
	status := protocol.Status{}
	if s.fleetStatus != nil {
		status = s.fleetStatus()
	}
	send(w, 200, status)
}

func (s *Server) fleetAvailable(w http.ResponseWriter) bool {
	if s.fleetHub == nil {
		fail(w, 503, "unavailable", "fleet hub is disabled; enable fleet.hub.enabled for inventory")
		return false
	}
	return true
}

func fleetError(w http.ResponseWriter, err error) {
	status := 503
	code := hub.Code(err)
	switch code {
	case "not_found":
		status = 404
	case "invalid_argument":
		status = 400
	default:
		code = "unavailable"
	}
	fail(w, status, code, "fleet operation failed; inspect hub state and quotas")
}

func (s *Server) fleetMutation(w http.ResponseWriter, r *http.Request, credentials caller, action, target string) bool {
	if s.record(r, credentials.session.Principal, action, target, "ok") != nil {
		fail(w, 503, "unavailable", "fleet state may already be saved; audit failed, inspect before retrying")
		return false
	}
	return true
}
