package console

// RouteForTest exposes registration metadata only to the external HTTP tests.
type RouteForTest struct {
	Pattern string
	Role    string
}

// RoutesForTest returns the actual registered API routes for coverage checks.
func (s *Server) RoutesForTest() []RouteForTest {
	routes := make([]RouteForTest, 0, len(s.routeTable()))
	for _, route := range s.routeTable() {
		routes = append(routes, RouteForTest{
			Pattern: route.pattern,
			Role:    route.role,
		})
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
