package accounts

import (
	"slices"
	"sort"
	"strings"

	"github.com/metaforismo/aegismesh/internal/console/permission"
)

// RoleInput carries the fields of a new custom role.
type RoleInput struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

// RolePatch carries optional role changes; an empty patch is invalid.
type RolePatch struct {
	Name        *string   `json:"name"`
	Description *string   `json:"description"`
	Permissions *[]string `json:"permissions"`
}

// RoleChange reports which fields an update changed and the permissions removed.
type RoleChange struct {
	Fields  []string
	Removed []string
}

// validRoleRef accepts a built-in role or a custom role id grammar.
func validRoleRef(id string) bool { return permission.IsBuiltin(id) || ValidRoleID(id) }

// Roles returns copies of the custom roles, oldest first.
func (s *Store) Roles() []Role {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Role, 0, len(s.data.Roles))
	for _, role := range s.data.Roles {
		out = append(out, cloneRole(role))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

// Role returns one custom role.
func (s *Store) Role(id string) (Role, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, role := range s.data.Roles {
		if role.ID == id {
			return cloneRole(role), true
		}
	}
	return Role{}, false
}

// Assigned counts managed accounts holding role id.
func (s *Store) Assigned(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, account := range s.data.Accounts {
		if account.Role == id {
			count++
		}
	}
	return count
}

func roleNameTaken(data snapshot, name, except string) bool {
	folded := strings.ToLower(name)
	if permission.IsBuiltin(folded) {
		return true
	}
	for _, role := range data.Roles {
		if role.ID != except && strings.ToLower(role.Name) == folded {
			return true
		}
	}
	return false
}

// CreateRole validates and persists a custom role. Permissions are normalized
// (sorted, deduplicated) before the combination rules are checked.
func (s *Store) CreateRole(input RoleInput, actor string) (Role, error) {
	if input.Permissions == nil {
		input.Permissions = []string{}
	}
	perms := permission.Normalize(input.Permissions)
	if !ValidRoleName(input.Name) || !ValidRoleDescription(input.Description) || !ValidPermissions(perms) ||
		!validActor(actor) {
		return Role{}, ErrInvalid
	}
	suffix, err := randomHex(6)
	if err != nil {
		return Role{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.data.Roles) >= MaxRoles {
		return Role{}, ErrLimit
	}
	if roleNameTaken(s.data, input.Name, "") {
		return Role{}, ErrNameTaken
	}
	if s.data.roleName("role_"+suffix) != "" {
		return Role{}, ErrLimit
	}
	now := s.clock()
	role := Role{
		ID: "role_" + suffix, Name: input.Name, Description: input.Description, Permissions: perms,
		CreatedAt: now, CreatedBy: actor, UpdatedAt: now,
	}
	next := s.data.clone()
	next.Roles = append(next.Roles, role)
	if err := s.save(next); err != nil {
		return Role{}, err
	}
	return cloneRole(role), nil
}

// UpdateRole applies a validated patch to a custom role. configAdmins feeds
// the last-administrator guard (NoGuard disables it).
func (s *Store) UpdateRole(id string, patch RolePatch, actor string, configAdmins int) (Role, RoleChange, error) {
	if permission.IsBuiltin(id) {
		return Role{}, RoleChange{}, ErrBuiltin
	}
	if patch.Name == nil && patch.Description == nil && patch.Permissions == nil {
		return Role{}, RoleChange{}, ErrInvalid
	}
	var perms []string
	if patch.Permissions != nil {
		perms = permission.Normalize(*patch.Permissions)
		if perms == nil {
			perms = []string{}
		}
	}
	if patch.Name != nil && !ValidRoleName(*patch.Name) ||
		patch.Description != nil && !ValidRoleDescription(*patch.Description) ||
		patch.Permissions != nil && !ValidPermissions(perms) || !validActor(actor) {
		return Role{}, RoleChange{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	index := -1
	for i, role := range s.data.Roles {
		if role.ID == id {
			index = i
		}
	}
	if index < 0 {
		return Role{}, RoleChange{}, ErrNotFound
	}
	next := s.data.clone()
	role := &next.Roles[index]
	change := RoleChange{Fields: []string{}, Removed: []string{}}
	if patch.Name != nil && *patch.Name != role.Name {
		if roleNameTaken(next, *patch.Name, id) {
			return Role{}, RoleChange{}, ErrNameTaken
		}
		role.Name = *patch.Name
		change.Fields = append(change.Fields, "name")
	}
	if patch.Description != nil && *patch.Description != role.Description {
		role.Description = *patch.Description
		change.Fields = append(change.Fields, "description")
	}
	if patch.Permissions != nil && !slices.Equal(perms, role.Permissions) {
		for _, old := range role.Permissions {
			if !slices.Contains(perms, old) {
				change.Removed = append(change.Removed, old)
			}
		}
		role.Permissions = perms
		change.Fields = append(change.Fields, "permissions")
	}
	if len(change.Fields) == 0 {
		return cloneRole(s.data.Roles[index]), change, nil
	}
	if err := s.guard(s.data, next, configAdmins); err != nil {
		return Role{}, RoleChange{}, err
	}
	role.UpdatedAt = s.clock()
	result := cloneRole(*role)
	if err := s.save(next); err != nil {
		return Role{}, RoleChange{}, err
	}
	return result, change, nil
}

// DeleteRole removes an unassigned custom role.
func (s *Store) DeleteRole(id, actor string) (Role, error) {
	if permission.IsBuiltin(id) {
		return Role{}, ErrBuiltin
	}
	if !validActor(actor) {
		return Role{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.data.clone()
	for i, role := range next.Roles {
		if role.ID != id {
			continue
		}
		for _, account := range next.Accounts {
			if account.Role == id {
				return Role{}, ErrInUse
			}
		}
		next.Roles = slices.Delete(next.Roles, i, i+1)
		if err := s.save(next); err != nil {
			return Role{}, err
		}
		return cloneRole(role), nil
	}
	return Role{}, ErrNotFound
}
