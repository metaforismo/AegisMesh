package console

import (
	"net/http"
	"time"
)

// fleetToken is the operator-facing view of an outstanding enrollment token.
// It never carries the secret or its digest.
type fleetToken struct {
	Tenant    string `json:"tenant"`
	ID        string `json:"id"`
	ExpiresAt string `json:"expires_at"`
	Note      string `json:"note"`
}

func (s *Server) fleetTokens(w http.ResponseWriter, r *http.Request, _ caller) {
	if _, ok := query(w, r); !ok || !s.fleetAvailable(w) {
		return
	}
	tokens, err := s.fleetHub.Tokens()
	if err != nil {
		fleetError(w, err)
		return
	}
	listed := make([]fleetToken, 0, len(tokens))
	for _, token := range tokens {
		listed = append(listed, fleetToken{
			ID:        token.ID,
			Tenant:    s.tenantID,
			ExpiresAt: time.Unix(token.ExpiresAt, 0).UTC().Format(time.RFC3339),
			Note:      token.Note,
		})
	}
	send(w, 200, map[string]any{"tokens": listed})
}

func (s *Server) fleetMint(w http.ResponseWriter, r *http.Request, credentials caller) {
	if _, ok := query(w, r); !ok || !s.fleetAvailable(w) {
		return
	}
	var input struct {
		TTLSeconds int    `json:"ttl_seconds"`
		Note       string `json:"note"`
	}
	if !strictBody(w, r, &input) {
		return
	}
	token, err := s.fleetHub.Mint(input.TTLSeconds, input.Note)
	if err != nil {
		fleetError(w, err)
		return
	}
	if s.fleetMutation(w, r, credentials, "fleet.token.create", token.ID) {
		send(w, 201, token)
	}
}

func (s *Server) fleetDeleteToken(w http.ResponseWriter, r *http.Request, credentials caller) {
	if _, ok := query(w, r); !ok || !s.fleetAvailable(w) {
		return
	}
	id := r.PathValue("id")
	if err := s.fleetHub.DeleteToken(id); err != nil {
		fleetError(w, err)
		return
	}
	if s.fleetMutation(w, r, credentials, "fleet.token.delete", id) {
		w.WriteHeader(204)
	}
}
