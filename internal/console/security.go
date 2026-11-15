package console

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/metaforismo/aegismesh/internal/console/audit"
	"github.com/metaforismo/aegismesh/internal/console/auth"
)

func (s *Server) validHost(host string) bool {
	if len(host) > 255 || strings.ContainsAny(host, "\r\n/@\\") {
		return false
	}

	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		return false
	}

	configured, _, _ := net.SplitHostPort(s.cfg.Listen)
	_, actualPort, _ := net.SplitHostPort(s.Addr())
	if port != actualPort {
		return false
	}

	if strings.EqualFold(hostname, configured) && hostname != "" {
		return true
	}

	ip := net.ParseIP(hostname)
	return strings.EqualFold(hostname, "localhost") || ip != nil && ip.IsLoopback()
}

func (s *Server) validOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}

	parsedOrigin, err := url.Parse(origin)
	scheme := "http"
	if s.cfg.TLSCertFile != "" {
		scheme = "https"
	}

	return err == nil &&
		parsedOrigin.Scheme == scheme &&
		strings.EqualFold(parsedOrigin.Host, r.Host) &&
		parsedOrigin.User == nil &&
		parsedOrigin.RawQuery == "" &&
		parsedOrigin.Fragment == "" &&
		parsedOrigin.Path == ""
}

// ServeHTTP checks authority and request bounds before dispatching any API or asset request.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", CSP)
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Cache-Control", "no-store")
	}

	if !s.validHost(r.Host) {
		s.requests.Inc("rejected")
		fail(w, 421, "invalid_argument", "Host does not match console authority")
		return
	}

	if len(r.URL.RequestURI()) > 8192 {
		s.requests.Inc("rejected")
		fail(w, 400, "invalid_argument", "request URI exceeds limit")
		return
	}

	select {
	case <-s.done:
		fail(w, 503, "unavailable", "console is shutting down")
		return
	default:
	}

	// ServeMux redirects cleaned paths; reject traversal before that normalization.
	for _, segment := range strings.Split(r.URL.Path, "/") {
		if segment == "." || segment == ".." {
			fail(w, 404, "not_found", "route not found")
			return
		}
	}
	s.mux.ServeHTTP(w, r)
}

func remote(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}

	return host
}

func (s *Server) record(r *http.Request, principal auth.Principal, action, target, outcome string) error {
	return s.audit.Append(audit.Record{
		Actor:   principal.Name,
		Role:    principal.Role,
		Action:  action,
		Target:  target,
		Outcome: outcome,
		Remote:  remote(r),
	})
}

type caller struct {
	session auth.Session
	id      string
	cookie  bool
}

func (s *Server) caller(r *http.Request) (caller, bool) {
	if header := r.Header.Get("Authorization"); header != "" {
		if !strings.HasPrefix(header, "Bearer ") {
			return caller{}, false
		}
		principal, ok := s.auth.Authenticate(strings.TrimPrefix(header, "Bearer "))
		return caller{session: auth.Session{Principal: principal}}, ok
	}

	credentials, err := r.Cookie(CookieName)
	if err != nil {
		return caller{}, false
	}

	session, ok := s.auth.Session(credentials.Value)
	return caller{
		session: session,
		id:      credentials.Value,
		cookie:  true,
	}, ok
}

func (s *Server) route(pattern, role, group string, handler func(http.ResponseWriter, *http.Request, caller)) {
	s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		s.requests.Inc(group)
		switch group {
		case "meta", "session", "event", "sensors", "rules", "node":
			if _, ok := query(w, r); !ok {
				return
			}
		}
		credentials := caller{}
		if role != "" {
			var ok bool
			credentials, ok = s.caller(r)
			if !ok {
				s.failures.Inc()
				fail(w, 401, "unauthenticated", "valid operator authentication is required")
				return
			}
			if !auth.Granted(credentials.session.Principal.Role, role) {
				if s.record(r, credentials.session.Principal, "authz.denied", "", "denied") != nil {
					fail(w, 503, "unavailable", "audit trail is unavailable")
					return
				}
				fail(w, 403, "forbidden", "operator role does not grant this action")
				return
			}
			if r.Method != "GET" &&
				r.Method != "HEAD" &&
				credentials.cookie &&
				(!auth.CSRF(r.Header.Get("X-AegisMesh-CSRF"), credentials.session.CSRFToken) ||
					!s.validOrigin(r)) {
				if s.record(r, credentials.session.Principal, "authz.denied", "", "denied") != nil {
					fail(w, 503, "unavailable", "audit trail is unavailable")
					return
				}
				fail(w, 403, "forbidden", "CSRF token or Origin is invalid")
				return
			}
		}
		acceptsBody := r.Method == "POST" &&
			(group == "session" ||
				group == "investigations" || group == "fleet-tokens") ||
			r.Method == "PATCH" &&
				group == "investigations"
		if !acceptsBody && (r.ContentLength != 0 || len(r.TransferEncoding) > 0) {
			fail(w, 400, "invalid_argument", "this endpoint does not accept a request body")
			return
		}
		if group != "stream" {
			select {
			case s.slots <- struct{}{}:
				defer func() {
					<-s.slots
				}()
			default:
				fail(w, 503, "unavailable", "console request capacity reached")
				return
			}
		}
		if (role == "analyst" || role == "admin") && !s.audit.Ready() {
			fail(w, 503, "unavailable", "audit trail requires inspection and restart")
			return
		}
		handler(w, r, credentials)
	})
}
