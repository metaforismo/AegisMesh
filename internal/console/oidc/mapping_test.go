package oidc

import (
	"encoding/json"
	"testing"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console/auth"
)

func TestConfiguredClaimsAndTenantMapping(t *testing.T) {
	for _, test := range []struct {
		name    string
		claims  string
		denied  bool
		display string
	}{
		{"mapped string claims", `{"roles":"responders","orgs":"organization-b","preferred":"Display"}`, false, "Display"},
		{"sub fallback", `{"roles":"responders","orgs":"organization-b"}`, false, "subject"},
		{"missing tenant", `{"roles":"responders","orgs":"unmapped"}`, true, ""},
		{"claim cannot select path", `{"roles":"responders","orgs":"../../escape"}`, true, ""},
		{"missing role", `{"roles":"unknown","orgs":"organization-b"}`, true, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := &Manager{cfg: config.OIDC{
				RoleClaim: "roles", RoleMapping: map[string]string{"responders": "analyst"}, NameClaim: "preferred",
				TenantClaim: "orgs", TenantMapping: map[string]string{"organization-b": "bravo"},
			}, tenants: []string{"default", "bravo"}}
			var claims map[string]json.RawMessage
			if err := json.Unmarshal([]byte(test.claims), &claims); err != nil {
				t.Fatal(err)
			}
			principal := auth.Principal{Subject: "subject"}
			err := manager.mapPrincipal(&principal, claims)
			if test.denied {
				if err == nil {
					t.Fatal("unmapped membership was admitted")
				}
				return
			}
			if err != nil || principal.Role != "analyst" || principal.Name != test.display || principal.Tenant != "bravo" {
				t.Fatalf("claim mapping: %+v %v", principal, err)
			}
		})
	}
}
