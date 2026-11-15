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
