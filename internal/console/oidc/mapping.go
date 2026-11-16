package oidc

import (
	"encoding/json"
	"slices"
	"sort"
	"strings"

	"github.com/metaforismo/aegismesh/internal/console/auth"
)

func claimValues(raw json.RawMessage) ([]string, error) {
	var one string
	var values []string
	if json.Unmarshal(raw, &one) == nil && one != "" {
		values = []string{one}
	} else if json.Unmarshal(raw, &values) != nil {
		return nil, ErrDenied
	}
	if len(values) == 0 || len(values) > 64 {
		return nil, ErrDenied
	}
	for _, value := range values {
		if len(value) == 0 || len(value) > 128 {
			return nil, ErrDenied
		}
	}
	return values, nil
}

func (m *Manager) mapPrincipal(principal *auth.Principal, claims map[string]json.RawMessage) error {
	principal.Name = sanitize(principal.Subject)
	name := principal.Subject
	if raw, exists := claims[m.cfg.NameClaim]; exists {
		if json.Unmarshal(raw, &name) != nil || len(name) > 256 {
			return ErrDenied
		}
		if name == "" {
			name = principal.Subject
		}
	}
	principal.Name = sanitize(name)
	groups, err := claimValues(claims[m.cfg.RoleClaim])
	if err != nil {
		return ErrDenied
	}
	for _, group := range groups {
		role := m.cfg.RoleMapping[group]
		if auth.Granted(role, "viewer") && (principal.Role == "" || auth.Granted(role, principal.Role)) {
			principal.Role = role
		}
	}
	memberships, err := claimValues(claims[m.cfg.TenantClaim])
	if err != nil {
		return ErrDenied
	}
	for _, value := range memberships {
		name := value
		if len(m.cfg.TenantMapping) > 0 {
			name = m.cfg.TenantMapping[value]
		}
		// Claims only look up an existing, startup-validated partition. They never form paths.
		if slices.Contains(m.tenants, name) && !slices.Contains(principal.Tenants, name) {
			principal.Tenants = append(principal.Tenants, name)
		}
	}
	if principal.Role == "" || len(principal.Tenants) == 0 {
		return ErrDenied
	}
	sort.Strings(principal.Tenants)
	principal.Tenant = principal.Tenants[0]
	return nil
}

func sanitize(value string) string {
	var result strings.Builder
	for _, r := range value {
		if result.Len() >= 64 {
			break
		}
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("@._-+ ", r) {
			result.WriteRune(r)
		} else {
			result.WriteByte('_')
		}
	}
	return result.String()
}
