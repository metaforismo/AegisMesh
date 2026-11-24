package console

import (
	"net/http"
	"slices"
	"strconv"

	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/console/permission"
)

// access is a principal's resolved role: its id, display name and sorted
// permission set. An unknown role resolves to no permissions.
type access struct {
	role  string
	name  string
	perms []string
}

func (a access) has(perm string) bool { return slices.Contains(a.perms, perm) }

var viewerPermissions = permission.Builtin(permission.Viewer)

// viewerHolds reports whether the built-in viewer role grants perm.
func viewerHolds(perm string) bool { return slices.Contains(viewerPermissions, perm) }

// grants resolves the principal's role to permissions at request time. Built-in
// roles are fixed sets; custom roles are read from the account store, so an edit
// or a removed permission applies at the principal's next request.
func (s *Server) grants(principal auth.Principal) access {
	if permission.IsBuiltin(principal.Role) {
		return access{role: principal.Role, name: principal.Role, perms: permission.Builtin(principal.Role)}
	}
	if s.accounts != nil {
		if role, ok := s.accounts.Role(principal.Role); ok {
			return access{role: role.ID, name: role.Name, perms: slices.Clone(role.Permissions)}
		}
	}
	return access{role: principal.Role, name: principal.Role, perms: []string{}}
}

// exceeds reports whether perms holds any permission the caller lacks. Every
// administration path that grants, changes or removes access applies it, so a
// role holding accounts.manage, roles.manage or sessions.manage can never be
// used to reach a permission it does not already hold, nor act on a principal
// that holds more than the caller.
//
// Ids outside the catalogue are left to validation (400), not reported here.
func exceeds(caller access, perms []string) bool {
	for _, perm := range perms {
		if permission.Valid(perm) && !caller.has(perm) {
			return true
		}
	}
	return false
}

// roleExceeds resolves a role id and reports whether it holds more than the caller.
func (s *Server) roleExceeds(caller access, role string) bool {
	return exceeds(caller, s.grants(auth.Principal{Role: role}).perms)
}

// denyEscalation audits and answers a refused privilege escalation.
func (s *Server) denyEscalation(w http.ResponseWriter, r *http.Request, principal auth.Principal, action, target string) {
	if s.recordLocal(r, principal, action, target, "denied", "exceeds_own_permissions") != nil {
		fail(w, 503, "unavailable", "audit trail is unavailable")
		return
	}
	fail(w, 403, "exceeds_own_permissions",
		"the change would grant or affect permissions the caller's own role does not hold")
}

// quoteDetail renders an operator-supplied value for an audit detail: cut to
// limit bytes at a rune boundary, then Go-quoted so control characters and
// separators cannot forge other detail fields.
func quoteDetail(value string, limit int) string {
	return strconv.Quote(truncate(value, limit))
}
