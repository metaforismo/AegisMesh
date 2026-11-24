package console

import (
	"slices"
	"time"

	"github.com/metaforismo/aegismesh/internal/console/permission"
)

// SetStreamHeartbeatForTest shortens the SSE heartbeat and credential re-check
// interval; the returned function restores it.
func SetStreamHeartbeatForTest(interval time.Duration) func() {
	previous := streamHeartbeat
	streamHeartbeat = interval
	return func() { streamHeartbeat = previous }
}

// RouteForTest exposes registration metadata only to the external HTTP tests.
type RouteForTest struct {
	Pattern string
	// Role is the least built-in role whose permissions pass the gate ("" for public routes).
	Role string
	// Permission is the declared catalogue id, "authenticated" or "" (public).
	Permission string
}

// RoutesForTest returns the actual registered API routes for coverage checks.
func (s *Server) RoutesForTest() []RouteForTest {
	routes := make([]RouteForTest, 0, len(s.routeTable()))
	for _, route := range s.routeTable() {
		role := ""
		switch {
		case route.perm == permPublic:
		case route.perm == permAuthenticated || viewerHolds(route.perm):
			role = "viewer"
		case slices.Contains(permission.Builtin(permission.Analyst), route.perm):
			role = "analyst"
		default:
			role = "admin"
		}
		routes = append(routes, RouteForTest{Pattern: route.pattern, Role: role, Permission: route.perm})
	}
	return routes
}

// CloseAuditForTest makes sensitive-download fail-closed checks use a real
// unavailable audit writer without adding a production injection seam.
func (s *Server) CloseAuditForTest() {
	for _, view := range s.views {
		_ = view.audit.Close()
	}
}
