package console

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/console/oidc"
)

const preloginCookie = "aegismesh_oidc"

func (s *Server) oidcError(w http.ResponseWriter, r *http.Request, principal auth.Principal, code string) {
	if s.record(r, principal, "session.oidc_denied", "", "denied") != nil {
		code = "unavailable"
	}
	http.Redirect(w, r, "/#/login?error="+code, http.StatusFound)
}

func (s *Server) oidcLogin(w http.ResponseWriter, r *http.Request, _ caller) {
	if _, ok := query(w, r); !ok {
		return
	}
	if s.oidc == nil {
		s.oidcError(w, r, auth.Principal{}, "unavailable")
		return
	}
	if !s.auth.AllowLogin(remote(r)) {
		s.oidcError(w, r, auth.Principal{}, "rate_limited")
		return
	}
	// The configured callback origin, rather than any forwarding header, binds this browser flow.
	redirect, _ := url.Parse(s.cfg.OIDC.RedirectURI)
	if !s.validOrigin(r) || !equalAuthority(r.Host, redirect.Host) {
		s.oidcError(w, r, auth.Principal{}, "invalid_request")
		return
	}
	location, browser, err := s.oidc.Begin()
	if err != nil {
		s.oidcError(w, r, auth.Principal{}, "unavailable")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: preloginCookie, Value: browser, Path: "/api/v1/auth/oidc", HttpOnly: true,
		Secure: s.cfg.TLSCertFile != "", SameSite: http.SameSiteLaxMode,
		MaxAge: int(oidc.PendingTTL / time.Second),
	})
	http.Redirect(w, r, location, http.StatusFound)
}

func equalAuthority(a, b string) bool { return a == b }

func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request, _ caller) {
	http.SetCookie(w, &http.Cookie{
		Name: preloginCookie, Path: "/api/v1/auth/oidc", HttpOnly: true,
		Secure: s.cfg.TLSCertFile != "", SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
	if s.oidc == nil {
		s.oidcError(w, r, auth.Principal{}, "unavailable")
		return
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		s.oidcError(w, r, auth.Principal{}, "invalid_request")
		return
	}
	for key, value := range values {
		if len(value) != 1 || key != "state" && key != "code" && key != "error" &&
			key != "error_description" && key != "iss" && key != "session_state" {
			s.oidcError(w, r, auth.Principal{}, "invalid_request")
			return
		}
	}
	browser := ""
	if cookie, err := r.Cookie(preloginCookie); err == nil {
		browser = cookie.Value
	}
	code := values.Get("code")
	if values.Get("error") != "" {
		code = ""
	}
	principal, expiry, err := s.oidc.Finish(r.Context(), values.Get("state"), browser, code)
	if err != nil {
		errorCode := "invalid_identity"
		if errors.Is(err, oidc.ErrState) {
			errorCode = "invalid_state"
		}
		if errors.Is(err, oidc.ErrDenied) {
			errorCode = "access_denied"
		}
		s.oidcError(w, r, principal, errorCode)
		return
	}
	id, session, err := s.auth.LoginUntil(principal, expiry)
	if err != nil {
		s.oidcError(w, r, principal, "unavailable")
		return
	}
	if s.record(r, principal, "session.oidc_login", "", "ok") != nil {
		s.auth.Logout(id)
		s.oidcError(w, r, principal, "unavailable")
		return
	}
	s.setSession(w, r, id, session)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) setSession(w http.ResponseWriter, r *http.Request, id string, session auth.Session) {
	if previous, err := r.Cookie(CookieName); err == nil {
		s.auth.Logout(previous.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: id, Path: "/", HttpOnly: true, Secure: s.cfg.TLSCertFile != "",
		SameSite: http.SameSiteStrictMode, Expires: session.ExpiresAt,
	})
}
