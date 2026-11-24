package console

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/metaforismo/aegismesh/internal/console/accounts"
	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/console/permission"
)

// roleAssigned counts principals holding a role, by source.
type roleAssigned struct {
	Managed int `json:"managed"`
	Config  int `json:"config"`
	OIDC    int `json:"oidc"`
}

// roleView is the API projection of a built-in or custom role.
type roleView struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Builtin     bool         `json:"builtin"`
	Permissions []string     `json:"permissions"`
	Assigned    roleAssigned `json:"assigned"`
	CreatedAt   *time.Time   `json:"created_at"`
	CreatedBy   string       `json:"created_by"`
	UpdatedAt   *time.Time   `json:"updated_at"`
}

var builtinDescriptions = map[string]string{
	permission.Viewer:  "Read evidence, analysis, investigations and fleet status.",
	permission.Analyst: "Viewer plus exports, reports and investigation writes.",
	permission.Admin:   "Every permission, including accounts, roles, settings, audit and fleet administration.",
}

func (s *Server) assigned(id string) roleAssigned {
	count := roleAssigned{}
	for _, account := range s.accounts.List() {
		if account.Role == id {
			count.Managed++
		}
	}
	for _, operator := range s.auth.Operators() {
		if operator.Role == id {
			count.Config++
		}
	}
	for _, identity := range s.accounts.Identities() {
		if identity.Role == id {
			count.OIDC++
		}
	}
	return count
}

func (s *Server) builtinRoleView(id string) roleView {
	return roleView{
		ID: id, Name: id, Description: builtinDescriptions[id], Builtin: true,
		Permissions: permission.Builtin(id), Assigned: s.assigned(id), CreatedBy: "builtin",
	}
}

func (s *Server) customRoleView(role accounts.Role) roleView {
	return roleView{
		ID: role.ID, Name: role.Name, Description: role.Description, Permissions: slices.Clone(role.Permissions),
		Assigned: s.assigned(role.ID), CreatedAt: timePointer(role.CreatedAt), CreatedBy: role.CreatedBy,
		UpdatedAt: timePointer(role.UpdatedAt),
	}
}

func (s *Server) permissionCatalogue(w http.ResponseWriter, _ *http.Request, _ caller) {
	send(w, 200, map[string]any{"version": permission.Version, "items": permission.Catalogue()})
}

func (s *Server) listRoles(w http.ResponseWriter, _ *http.Request, _ caller) {
	items := []roleView{}
	for _, id := range []string{permission.Viewer, permission.Analyst, permission.Admin} {
		items = append(items, s.builtinRoleView(id))
	}
	for _, role := range s.accounts.Roles() {
		items = append(items, s.customRoleView(role))
	}
	send(w, 200, map[string]any{"items": items, "limits": map[string]int{
		"max_roles": accounts.MaxRoles, "max_name_runes": accounts.MaxRoleNameRunes,
		"max_description_runes": accounts.MaxRoleDescriptionRunes,
	}})
}

func (s *Server) getRole(w http.ResponseWriter, r *http.Request, _ caller) {
	id := r.PathValue("id")
	if permission.IsBuiltin(id) {
		send(w, 200, s.builtinRoleView(id))
		return
	}
	role, ok := s.accounts.Role(id)
	if !ok {
		fail(w, 404, "not_found", "role not found")
		return
	}
	send(w, 200, s.customRoleView(role))
}

func (s *Server) createRole(w http.ResponseWriter, r *http.Request, credentials caller) {
	var body accounts.RoleInput
	if !strictBody(w, r, &body) {
		return
	}
	principal := credentials.session.Principal
	if exceeds(s.grants(principal), body.Permissions) {
		s.denyEscalation(w, r, principal, "role.create", "")
		return
	}
	role, err := s.accounts.CreateRole(body, principal.ID)
	if !s.roleAudited(w, r, principal, "role.create", role.ID, err, roleDetail(role.Name, role.Permissions)) {
		return
	}
	send(w, 201, s.customRoleView(role))
}

func (s *Server) patchRole(w http.ResponseWriter, r *http.Request, credentials caller) {
	var body accounts.RolePatch
	if !strictBody(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	if !permission.IsBuiltin(id) && !accounts.ValidRoleID(id) {
		fail(w, 404, "not_found", "role not found")
		return
	}
	principal := credentials.session.Principal
	// A caller may neither widen a role beyond its own permissions nor edit a
	// role that already holds more than it does.
	caller := s.grants(principal)
	if !permission.IsBuiltin(id) && (s.roleExceeds(caller, id) || body.Permissions != nil && exceeds(caller, *body.Permissions)) {
		s.denyEscalation(w, r, principal, "role.update", id)
		return
	}
	role, change, err := s.accounts.UpdateRole(id, body, principal.ID, s.configAdmins())
	// Permissions resolve per request, so principals holding the role use the
	// new set at their next request and streams re-check on the next event.
	detail := "fields=" + strings.Join(change.Fields, ",")
	if len(change.Removed) > 0 {
		detail += " removed=" + strings.Join(change.Removed, ",")
	}
	if err == nil && slices.Contains(change.Fields, "permissions") {
		detail += " permissions=" + strings.Join(role.Permissions, ",")
	}
	if !s.roleAudited(w, r, principal, "role.update", id, err, detail) {
		return
	}
	send(w, 200, s.customRoleView(role))
}

func (s *Server) deleteRole(w http.ResponseWriter, r *http.Request, credentials caller) {
	id := r.PathValue("id")
	if !permission.IsBuiltin(id) && !accounts.ValidRoleID(id) {
		fail(w, 404, "not_found", "role not found")
		return
	}
	principal := credentials.session.Principal
	if !permission.IsBuiltin(id) && s.roleExceeds(s.grants(principal), id) {
		s.denyEscalation(w, r, principal, "role.delete", id)
		return
	}
	role, err := s.accounts.DeleteRole(id, principal.ID)
	if !s.roleAudited(w, r, principal, "role.delete", id, err, roleDetail(role.Name, nil)) {
		return
	}
	w.WriteHeader(204)
}

// roleDetail renders a bounded audit detail; role names are validated printable text.
func roleDetail(name string, perms []string) string {
	detail := "name=" + quoteDetail(name, 48)
	if perms != nil {
		detail += " permissions=" + strings.Join(perms, ",")
	}
	return detail
}

// roleAudited records a role mutation on the local chain and maps role errors.
func (s *Server) roleAudited(w http.ResponseWriter, r *http.Request, principal auth.Principal, action, target string, err error, detail string) bool {
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	if s.recordLocal(r, principal, action, target, outcome, detail) != nil {
		if err == nil {
			fail(w, 503, "unavailable", "state saved but audit append failed; inspect state before retrying")
		} else {
			fail(w, 503, "unavailable", "audit trail is unavailable")
		}
		return false
	}
	switch {
	case err == nil:
		return true
	case errors.Is(err, accounts.ErrBuiltin):
		fail(w, 409, "builtin", "built-in roles cannot be changed or deleted")
	case errors.Is(err, accounts.ErrInUse):
		fail(w, 409, "in_use", "the role is still assigned; reassign its accounts first")
	case errors.Is(err, accounts.ErrInvalid):
		fail(w, 400, "invalid_argument", "invalid role name, description or permission set "+
			"(roles.manage and settings.manage need accounts.manage; *.manage needs the matching read)")
	case errors.Is(err, accounts.ErrNameTaken):
		fail(w, 409, "conflict", "the role name is already used")
	case errors.Is(err, accounts.ErrLimit):
		fail(w, 409, "conflict", "role quota reached")
	case errors.Is(err, accounts.ErrNotFound):
		fail(w, 404, "not_found", "role not found")
	default:
		accountError(w, err)
	}
	return false
}
