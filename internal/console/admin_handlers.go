package console

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/metaforismo/aegismesh/internal/console/accounts"
	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/console/notifications"
	"github.com/metaforismo/aegismesh/internal/console/permission"
)

// accountView is the administration projection shared by all three sources.
type accountView struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	Kind           string     `json:"kind"`
	Source         string     `json:"source"`
	Role           string     `json:"role"`
	RoleName       string     `json:"role_name"`
	Tenants        []string   `json:"tenants"`
	Status         string     `json:"status"`
	CreatedAt      *time.Time `json:"created_at"`
	CreatedBy      string     `json:"created_by"`
	UpdatedAt      *time.Time `json:"updated_at"`
	LastSeenAt     *time.Time `json:"last_seen_at"`
	ActiveKeys     int        `json:"active_keys"`
	ActiveSessions int        `json:"active_sessions"`
	// Editable is true only for managed accounts; config and OIDC identities are read-only here.
	Editable bool `json:"editable"`
}

type accountDetail struct {
	accountView
	Keys     []accounts.KeyView `json:"keys"`
	Sessions []auth.SessionInfo `json:"sessions"`
}

func (s *Server) managedView(account accounts.Account, now time.Time) accountView {
	return accountView{
		ID: account.ID, Name: account.Name, Kind: account.Kind, Source: auth.SourceManaged, Role: account.Role,
		RoleName: s.grants(auth.Principal{Role: account.Role}).name,
		Tenants:  slices.Clone(account.Tenants), Status: account.Status, CreatedAt: timePointer(account.CreatedAt),
		CreatedBy: account.CreatedBy, UpdatedAt: timePointer(account.UpdatedAt), LastSeenAt: account.LastSeenAt,
		ActiveKeys: account.ActiveKeys(now), ActiveSessions: s.auth.CountSessions(account.ID), Editable: true,
	}
}

func (s *Server) configViews() []accountView {
	status := accounts.StatusActive
	if !s.cfg.TokenEnabled() {
		// token_login: false means config operators cannot sign in.
		status = accounts.StatusDisabled
	}
	views := []accountView{}
	for _, operator := range s.auth.Operators() {
		view := accountView{
			ID: operator.ID, Name: operator.Name, Kind: "person", Source: auth.SourceConfig, Role: operator.Role, RoleName: operator.Role,
			Tenants: slices.Clone(operator.Tenants), Status: status, CreatedBy: "config",
			ActiveSessions: s.auth.CountSessions(operator.ID),
		}
		if seen, ok := s.auth.LastSeen(operator.ID); ok {
			view.LastSeenAt = timePointer(seen)
		}
		views = append(views, view)
	}
	return views
}

func (s *Server) identityViews() []accountView {
	views := []accountView{}
	for _, identity := range s.accounts.Identities() {
		views = append(views, accountView{
			ID: identity.ID, Name: identity.Name, Kind: "person", Source: auth.SourceOIDC, Role: identity.Role, RoleName: identity.Role,
			Tenants: identity.Tenants, Status: accounts.StatusActive, CreatedAt: timePointer(identity.FirstSeenAt),
			CreatedBy: "oidc", LastSeenAt: timePointer(identity.LastSeenAt),
			ActiveSessions: s.auth.CountSessions(identity.ID),
		})
	}
	return views
}

func (s *Server) listAccounts(w http.ResponseWriter, _ *http.Request, _ caller) {
	now := s.now()
	maxDays, defaultDays := s.accounts.KeyLimits()
	items := s.configViews()
	for _, account := range s.accounts.List() {
		items = append(items, s.managedView(account, now))
	}
	items = append(items, s.identityViews()...)
	send(w, 200, map[string]any{
		"items": items,
		"limits": map[string]int{
			"max_accounts": accounts.MaxAccounts, "max_keys_per_account": accounts.MaxKeysPerAccount,
			"max_key_days": maxDays, "default_key_days": defaultDays,
		},
	})
}

func (s *Server) createAccount(w http.ResponseWriter, r *http.Request, credentials caller) {
	var body accounts.Create
	if !strictBody(w, r, &body) {
		return
	}
	principal := credentials.session.Principal
	if s.roleExceeds(s.grants(principal), body.Role) {
		s.denyEscalation(w, r, principal, "account.create", "")
		return
	}
	account, err := s.accounts.Create(body, principal.ID)
	if !s.audited(w, r, principal, "account.create", account.ID, err,
		"kind="+safeWord(body.Kind)+" role="+safeRole(body.Role), true) {
		return
	}
	send(w, 201, s.managedView(account, s.now()))
}

// safeRole keeps only role-id-shaped request values in audit details.
func safeRole(value string) string {
	if permission.IsBuiltin(value) || accounts.ValidRoleID(value) {
		return value
	}
	return "invalid"
}

// safeWord keeps only enum-shaped request words in audit details.
func safeWord(value string) string {
	if len(value) == 0 || len(value) > 16 || strings.Trim(value, "abcdefghijklmnopqrstuvwxyz") != "" {
		return "invalid"
	}
	return value
}

// lookupAccount resolves any principal id to its administration view; ok is
// false after a 404 response. managed reports whether the console may change it.
func (s *Server) lookupAccount(w http.ResponseWriter, id string) (accountDetail, bool, bool) {
	now := s.now()
	if accounts.ValidAccountID(id) {
		account, err := s.accounts.Get(id)
		if err == nil {
			return accountDetail{
				accountView: s.managedView(account, now), Keys: keyViews(account, now),
				Sessions: s.auth.Sessions(id, ""),
			}, true, true
		}
	} else {
		for _, view := range append(s.configViews(), s.identityViews()...) {
			if view.ID == id {
				return accountDetail{accountView: view, Keys: []accounts.KeyView{}, Sessions: s.auth.Sessions(id, "")},
					false, true
			}
		}
	}
	fail(w, 404, "not_found", "account not found")
	return accountDetail{}, false, false
}

func (s *Server) getAccount(w http.ResponseWriter, r *http.Request, _ caller) {
	if detail, _, ok := s.lookupAccount(w, r.PathValue("id")); ok {
		send(w, 200, detail)
	}
}

func notManaged(w http.ResponseWriter) {
	fail(w, 409, "not_managed", "config-file operators and OIDC identities cannot be changed in the console")
}

func (s *Server) patchAccount(w http.ResponseWriter, r *http.Request, credentials caller) {
	var body accounts.Patch
	if !strictBody(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	detail, managed, ok := s.lookupAccount(w, id)
	if !ok {
		return
	}
	principal := credentials.session.Principal
	if !managed {
		if s.recordLocal(r, principal, "account.update", id, "denied", "not_managed") != nil {
			fail(w, 503, "unavailable", "audit trail is unavailable")
			return
		}
		notManaged(w)
		return
	}
	// Neither the account's current role nor a requested one may exceed the caller's.
	caller := s.grants(principal)
	if s.roleExceeds(caller, detail.Role) || body.Role != nil && s.roleExceeds(caller, *body.Role) {
		s.denyEscalation(w, r, principal, "account.update", id)
		return
	}
	account, change, err := s.accounts.Update(id, body, principal.ID, s.configAdmins())
	if err == nil && change.Revoke {
		// Role, membership or status changes cut off sessions minted under the old grant;
		// disabled accounts' keys already fail authentication.
		s.auth.RevokePrincipal(id)
	}
	if !s.audited(w, r, principal, "account.update", id, err, "fields="+strings.Join(change.Fields, ","), true) {
		return
	}
	if slices.Contains(change.Fields, "role") || slices.Contains(change.Fields, "tenants") {
		s.notify(account.Tenants, notifications.Account(id, notifications.ReasonRoleChanged, id != principal.ID, s.now()))
	}
	send(w, 200, s.managedView(account, s.now()))
}

func (s *Server) createAccountKey(w http.ResponseWriter, r *http.Request, credentials caller) {
	var body keyRequest
	if !strictBody(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	detail, managed, ok := s.lookupAccount(w, id)
	if !ok {
		return
	}
	if !managed {
		if s.recordLocal(r, credentials.session.Principal, "key.create", "", "denied", "not_managed") != nil {
			fail(w, 503, "unavailable", "audit trail is unavailable")
			return
		}
		notManaged(w)
		return
	}
	// A key authenticates as its account: minting one for a more privileged
	// account would hand the caller that account's permissions.
	if s.roleExceeds(s.grants(credentials.session.Principal), detail.Role) {
		s.denyEscalation(w, r, credentials.session.Principal, "key.create", id)
		return
	}
	s.mintKey(w, r, credentials.session.Principal, id, body, true)
}

func (s *Server) revokeAccountKey(w http.ResponseWriter, r *http.Request, credentials caller) {
	id := r.PathValue("id")
	detail, managed, ok := s.lookupAccount(w, id)
	if !ok {
		return
	}
	if !managed {
		notManaged(w)
		return
	}
	if s.roleExceeds(s.grants(credentials.session.Principal), detail.Role) {
		s.denyEscalation(w, r, credentials.session.Principal, "key.revoke", id)
		return
	}
	s.revokeKey(w, r, credentials.session.Principal, id, r.PathValue("key_id"), true)
}

func (s *Server) adminSessions(w http.ResponseWriter, _ *http.Request, credentials caller) {
	send(w, 200, map[string]any{"items": s.auth.Sessions("", credentials.id)})
}

func (s *Server) revokeAdminSession(w http.ResponseWriter, r *http.Request, credentials caller) {
	handle := r.PathValue("handle")
	if !validHandle(handle) {
		fail(w, 404, "not_found", "session not found")
		return
	}
	// Ending a more privileged principal's session is refused like any other
	// action on access the caller does not hold.
	if target, live := s.auth.SessionPrincipal(handle); live &&
		exceeds(s.grants(credentials.session.Principal), s.grants(target).perms) {
		s.denyEscalation(w, r, credentials.session.Principal, "session.revoke", handle)
		return
	}
	target, _ := s.auth.SessionPrincipal(handle)
	info, ok := s.auth.Revoke(handle, "")
	var err error
	if !ok {
		err = accounts.ErrNotFound
	}
	if !s.audited(w, r, credentials.session.Principal, "session.revoke", handle, err,
		"account="+info.AccountID, true) {
		return
	}
	// Only a session ended by someone else notifies its principal.
	if target.ID != "" && target.ID != credentials.session.Principal.ID {
		s.notify(target.Tenants, notifications.Account(target.ID, notifications.ReasonSessionRevoked, true, s.now()))
	}
	if credentials.cookie && handle == s.auth.Handle(credentials.id) {
		s.clearCookie(w)
	}
	w.WriteHeader(204)
}
