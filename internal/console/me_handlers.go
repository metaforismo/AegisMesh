package console

import (
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/metaforismo/aegismesh/internal/console/accounts"
	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/console/permission"
)

type capabilities struct {
	// ManageOwnKeys is true for managed accounts while token authentication is enabled.
	ManageOwnKeys bool `json:"manage_own_keys"`
	// Administer is true when the role grants any administration read
	// (accounts.read, settings.read, system.read or audit.export) and the
	// principal is a member of the local tenant.
	Administer bool `json:"administer"`
}

type meResponse struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Kind         string       `json:"kind"`
	Source       string       `json:"source"`
	Role         string       `json:"role"`
	RoleName     string       `json:"role_name"`
	Permissions  []string     `json:"permissions"`
	Tenants      []string     `json:"tenants"`
	Tenant       string       `json:"tenant"`
	AuthMethod   string       `json:"auth_method"`
	CreatedAt    *time.Time   `json:"created_at"`
	LastSeenAt   *time.Time   `json:"last_seen_at"`
	Capabilities capabilities `json:"capabilities"`
}

type keyRequest struct {
	Label         string `json:"label"`
	ExpiresInDays int    `json:"expires_in_days"`
}

type keyCreated struct {
	Key   accounts.KeyView `json:"key"`
	Token string           `json:"token"`
}

type preferencesPatch struct {
	Timezone      *string `json:"timezone"`
	DefaultWindow *string `json:"default_window"`
	Density       *string `json:"density"`
	Theme         *string `json:"theme"`
	ReduceMotion  *string `json:"reduce_motion"`
}

func (s *Server) capabilities(principal auth.Principal) capabilities {
	granted := s.grants(principal)
	administer := false
	for _, perm := range []string{permission.AccountsRead, permission.SettingsRead, permission.SystemRead, permission.AuditExport} {
		administer = administer || granted.has(perm)
	}
	return capabilities{
		ManageOwnKeys: principal.Source == auth.SourceManaged && s.cfg.TokenEnabled() && granted.has(permission.KeysSelf),
		Administer:    administer && slices.Contains(principal.Tenants, s.cfg.LocalTenant),
	}
}

// configAdmins counts config-file administrators that can still sign in and
// administer; they are the break-glass path for the last-admin guard.
func (s *Server) configAdmins() int {
	if !s.cfg.TokenEnabled() {
		return 0
	}
	count := 0
	for _, operator := range s.auth.Operators() {
		if operator.Role == "admin" && slices.Contains(operator.Tenants, s.cfg.LocalTenant) {
			count++
		}
	}
	return count
}

func timePointer(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	value = value.UTC()
	return &value
}

func (s *Server) me(w http.ResponseWriter, _ *http.Request, credentials caller) {
	principal := credentials.session.Principal
	granted := s.grants(principal)
	response := meResponse{
		ID: principal.ID, Name: principal.Name, Kind: principal.Kind, Source: principal.Source,
		Role: principal.Role, RoleName: granted.name, Permissions: granted.perms, Tenants: slices.Clone(principal.Tenants), Tenant: credentials.session.Tenant,
		AuthMethod: principal.AuthMethod, Capabilities: s.capabilities(principal),
	}
	if response.Tenant == "" {
		response.Tenant = principal.Tenant
	}
	if response.Kind == "" {
		response.Kind = "person"
	}
	switch principal.Source {
	case auth.SourceManaged:
		if account, err := s.accounts.Get(principal.ID); err == nil {
			response.CreatedAt = timePointer(account.CreatedAt)
			response.LastSeenAt = account.LastSeenAt
		}
	case auth.SourceOIDC:
		for _, identity := range s.accounts.Identities() {
			if identity.ID == principal.ID {
				response.CreatedAt = timePointer(identity.FirstSeenAt)
				response.LastSeenAt = timePointer(identity.LastSeenAt)
			}
		}
	default:
		if seen, ok := s.auth.LastSeen(principal.ID); ok {
			response.LastSeenAt = timePointer(seen)
		}
	}
	send(w, 200, response)
}

func (s *Server) getPreferences(w http.ResponseWriter, _ *http.Request, credentials caller) {
	send(w, 200, s.accounts.Preferences(credentials.session.Principal.ID))
}

func (s *Server) putPreferences(w http.ResponseWriter, r *http.Request, credentials caller) {
	var body preferencesPatch
	if !strictBody(w, r, &body) {
		return
	}
	principal := credentials.session.Principal
	next := s.accounts.Preferences(principal.ID)
	for _, field := range []struct {
		value  *string
		target *string
	}{
		{body.Timezone, &next.Timezone}, {body.DefaultWindow, &next.DefaultWindow},
		{body.Density, &next.Density}, {body.Theme, &next.Theme}, {body.ReduceMotion, &next.ReduceMotion},
	} {
		if field.value != nil {
			*field.target = *field.value
		}
	}
	if !next.Valid() {
		fail(w, 400, "invalid_argument", "unknown preference value")
		return
	}
	err := s.accounts.SetPreferences(principal.ID, next)
	if !s.audited(w, r, principal, "preferences.update", principal.ID, err, "", false) {
		return
	}
	send(w, 200, next)
}

// audited records the outcome of a store mutation and writes the error
// response when either the mutation or the audit append failed.
func (s *Server) audited(
	w http.ResponseWriter, r *http.Request, principal auth.Principal,
	action, target string, err error, detail string, local bool,
) bool {
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	record := s.recordDetail
	if local {
		record = s.recordLocal
	}
	if record(r, principal, action, target, outcome, detail) != nil {
		if err == nil {
			fail(w, 503, "unavailable", "state saved but audit append failed; inspect state before retrying")
		} else {
			fail(w, 503, "unavailable", "audit trail is unavailable")
		}
		return false
	}
	if err != nil {
		accountError(w, err)
		return false
	}
	return true
}

func accountError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, accounts.ErrInvalid):
		fail(w, 400, "invalid_argument", "invalid account, key or preference fields")
	case errors.Is(err, accounts.ErrNotFound):
		fail(w, 404, "not_found", "account or key not found")
	case errors.Is(err, accounts.ErrLastAdmin):
		fail(w, 409, "last_admin", "the change would leave no active administrator")
	case errors.Is(err, accounts.ErrNameTaken):
		fail(w, 409, "conflict", "the name is already used by another account or operator")
	case errors.Is(err, accounts.ErrDisabled):
		fail(w, 409, "conflict", "the account is disabled")
	case errors.Is(err, accounts.ErrLimit):
		fail(w, 409, "conflict", "account or key quota reached")
	case errors.Is(err, accounts.ErrModified):
		fail(w, 503, "unavailable", "account state changed outside this process; restart the console")
	default:
		fail(w, 503, "unavailable", "account state could not be persisted")
	}
}

func (s *Server) mySessions(w http.ResponseWriter, _ *http.Request, credentials caller) {
	send(w, 200, map[string]any{"items": s.auth.Sessions(credentials.session.Principal.ID, credentials.id)})
}

func (s *Server) revokeMySession(w http.ResponseWriter, r *http.Request, credentials caller) {
	principal := credentials.session.Principal
	handle := r.PathValue("handle")
	if !validHandle(handle) {
		fail(w, 404, "not_found", "session not found")
		return
	}
	_, ok := s.auth.Revoke(handle, principal.ID)
	var err error
	if !ok {
		err = accounts.ErrNotFound
	}
	if !s.audited(w, r, principal, "session.revoke", handle, err, "scope=self", false) {
		return
	}
	if credentials.cookie && handle == s.auth.Handle(credentials.id) {
		s.clearCookie(w)
	}
	w.WriteHeader(204)
}

var handlePattern = regexp.MustCompile(`^ses_[0-9a-f]{16}$`)

func validHandle(handle string) bool { return handlePattern.MatchString(handle) }

func (s *Server) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: "", Path: "/", HttpOnly: true, Secure: s.cfg.TLSCertFile != "",
		SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
}

func (s *Server) ownKeys(w http.ResponseWriter, r *http.Request, credentials caller) (accounts.Account, bool) {
	principal := credentials.session.Principal
	if !s.capabilities(principal).ManageOwnKeys {
		if s.record(r, principal, "authz.denied", "", "denied") != nil {
			fail(w, 503, "unavailable", "audit trail is unavailable")
			return accounts.Account{}, false
		}
		fail(w, 403, "forbidden", "only managed accounts manage their own API keys")
		return accounts.Account{}, false
	}
	account, err := s.accounts.Get(principal.ID)
	if err != nil {
		accountError(w, err)
		return accounts.Account{}, false
	}
	return account, true
}

func keyViews(account accounts.Account, now time.Time) []accounts.KeyView {
	views := make([]accounts.KeyView, 0, len(account.Keys))
	for i := len(account.Keys) - 1; i >= 0; i-- {
		views = append(views, account.Keys[i].View(now))
	}
	return views
}

func (s *Server) myKeys(w http.ResponseWriter, r *http.Request, credentials caller) {
	account, ok := s.ownKeys(w, r, credentials)
	if !ok {
		return
	}
	send(w, 200, map[string]any{"items": keyViews(account, s.now())})
}

func (s *Server) createMyKey(w http.ResponseWriter, r *http.Request, credentials caller) {
	var body keyRequest
	if !strictBody(w, r, &body) {
		return
	}
	account, ok := s.ownKeys(w, r, credentials)
	if !ok {
		return
	}
	s.mintKey(w, r, credentials.session.Principal, account.ID, body, false)
}

func (s *Server) mintKey(w http.ResponseWriter, r *http.Request, principal auth.Principal, accountID string, body keyRequest, local bool) {
	view, token, err := s.accounts.CreateKey(accountID, body.Label, body.ExpiresInDays, principal.ID)
	days := body.ExpiresInDays
	if days == 0 {
		_, days = s.accounts.KeyLimits()
	}
	// The detail names the account and lifetime only; the token and its digest never reach the audit trail.
	if !s.audited(w, r, principal, "key.create", view.ID, err,
		"account="+accountID+" days="+strconv.Itoa(days), local) {
		return
	}
	send(w, 201, keyCreated{Key: view, Token: token})
}

func (s *Server) revokeMyKey(w http.ResponseWriter, r *http.Request, credentials caller) {
	account, ok := s.ownKeys(w, r, credentials)
	if !ok {
		return
	}
	s.revokeKey(w, r, credentials.session.Principal, account.ID, r.PathValue("key_id"), false)
}

func (s *Server) revokeKey(w http.ResponseWriter, r *http.Request, principal auth.Principal, accountID, keyID string, local bool) {
	if !accounts.ValidKeyID(keyID) {
		fail(w, 404, "not_found", "account or key not found")
		return
	}
	_, changed, err := s.accounts.RevokeKey(accountID, keyID, principal.ID, s.configAdmins())
	if err == nil {
		// Sessions created by signing in with this key end with it.
		s.auth.RevokeKey(keyID)
	}
	detail := "account=" + accountID
	if err == nil && !changed {
		detail += " already_revoked"
	}
	if !s.audited(w, r, principal, "key.revoke", keyID, err, detail, local) {
		return
	}
	w.WriteHeader(204)
}
