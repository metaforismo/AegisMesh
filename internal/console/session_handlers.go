package console

import (
	"net/http"

	"github.com/metaforismo/aegismesh/internal/console/auth"
)

func (s *Server) login(w http.ResponseWriter, r *http.Request, _ caller) {
	if !s.cfg.TokenEnabled() {
		fail(w, 403, "forbidden", "token login is disabled")
		return
	}
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

	principal, expiry, ok := s.auth.AuthenticateUntil(body.Token)
	if !ok {
		s.failures.Inc()
		if s.record(r, auth.Principal{}, "session.login_failed", "", "denied") != nil {
			fail(w, 503, "unavailable", "audit trail is unavailable")
			return
		}
		fail(w, 401, "unauthenticated", "invalid operator token")
		return
	}

	id, session, err := s.auth.LoginWith(principal, expiry, s.loginMeta(r))
	if err != nil {
		fail(w, 503, "unavailable", "session entropy unavailable")
		return
	}

	if err = s.record(r, principal, "session.login", "", "ok"); err != nil {
		s.auth.Logout(id)
		fail(w, 503, "unavailable", "audit trail is unavailable")
		return
	}

	s.setSession(w, r, id, session)
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

// loginMeta carries the peer host and a User-Agent that auth reduces to a fixed family.
func (s *Server) loginMeta(r *http.Request) auth.Meta {
	return auth.Meta{Remote: remote(r), UserAgent: r.Header.Get("User-Agent")}
}

func (s *Server) session(w http.ResponseWriter, _ *http.Request, credentials caller) {
	send(w, 200, credentials.session)
}
