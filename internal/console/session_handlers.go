package console

import (
	"net/http"

	"github.com/metaforismo/aegismesh/internal/console/auth"
)

func (s *Server) login(w http.ResponseWriter, r *http.Request, _ caller) {
	if !s.auth.AllowLogin(remote(r)) {
		s.failures.Inc()
		if s.record(r, auth.Principal{}, "session.login_failed", "", "denied") != nil {
			fail(w, 503, "unavailable", "audit trail is unavailable")
			return
		}
		w.Header().Set("Retry-After", "60")
		fail(w, 429, "rate_limited", "login attempt limit reached")
		return
	}

	var body struct {
		Token string `json:"token"`
	}

	if !s.validOrigin(r) {
		_ = s.record(r, auth.Principal{}, "session.login_failed", "", "denied")
		fail(w, 403, "forbidden", "Origin does not match console authority")
		return
	}

	if !strictBody(w, r, &body) {
		_ = s.record(r, auth.Principal{}, "session.login_failed", "", "denied")
		return
	}

	principal, ok := s.auth.Authenticate(body.Token)
	if !ok {
		s.failures.Inc()
		if s.record(r, auth.Principal{}, "session.login_failed", "", "denied") != nil {
			fail(w, 503, "unavailable", "audit trail is unavailable")
			return
		}
		fail(w, 401, "unauthenticated", "invalid operator token")
		return
	}

	id, session, err := s.auth.Login(principal)
	if err != nil {
		fail(w, 503, "unavailable", "session entropy unavailable")
		return
	}

	if err = s.record(r, principal, "session.login", "", "ok"); err != nil {
		s.auth.Logout(id)
		fail(w, 503, "unavailable", "audit trail is unavailable")
		return
	}

	// Successful reauthentication rotates and invalidates a preexisting session.
	if old, err := r.Cookie(CookieName); err == nil {
		s.auth.Logout(old.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.TLSCertFile != "",
		SameSite: http.SameSiteStrictMode,
		MaxAge:   s.cfg.SessionTTLSeconds,
		Expires:  session.ExpiresAt,
	})
	send(w, 200, session)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, credentials caller) {
	if s.record(r, credentials.session.Principal, "session.logout", "", "ok") != nil {
		fail(w, 503, "unavailable", "audit trail is unavailable")
		return
	}

	s.auth.Logout(credentials.id)
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.TLSCertFile != "",
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	w.WriteHeader(204)
}

func (s *Server) session(w http.ResponseWriter, _ *http.Request, credentials caller) {
	send(w, 200, credentials.session)
}
