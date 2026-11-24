package console

import (
	"slices"

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
