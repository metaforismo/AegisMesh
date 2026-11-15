package console

import "net/http"

func (s *Server) fleetNodes(w http.ResponseWriter, r *http.Request, _ caller) {
	values, ok := query(w, r, "status")
	if !ok || !s.fleetAvailable(w) {
		return
	}
	nodes, err := s.fleetHub.Nodes(values.Get("status"))
	if err != nil {
		fleetError(w, err)
		return
	}
	send(w, 200, map[string]any{"nodes": nodes})
}

func (s *Server) fleetNode(w http.ResponseWriter, r *http.Request, _ caller) {
	if _, ok := query(w, r); !ok || !s.fleetAvailable(w) {
		return
	}
	node, err := s.fleetHub.Node(r.PathValue("id"))
	if err != nil {
		fleetError(w, err)
		return
	}
	send(w, 200, node)
}

func (s *Server) fleetRevoke(w http.ResponseWriter, r *http.Request, credentials caller) {
	if _, ok := query(w, r); !ok || !s.fleetAvailable(w) {
		return
	}
	node, err := s.fleetHub.Revoke(r.PathValue("id"))
	if err != nil {
		fleetError(w, err)
		return
	}
	if s.fleetMutation(w, r, credentials, "fleet.node.revoke", node.ID) {
		send(w, 200, node)
	}
}
