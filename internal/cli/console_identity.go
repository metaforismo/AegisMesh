package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console/tenant"
	"github.com/metaforismo/aegismesh/internal/egress"
)

type operatorMembership struct {
	Name    string   `json:"name"`
	Role    string   `json:"role"`
	Tenants []string `json:"tenants"`
}

type consoleIdentity struct {
	Token       bool                 `json:"token_login"`
	Tenants     []string             `json:"tenants"`
	LocalTenant string               `json:"local_tenant"`
	OIDC        config.OIDC          `json:"oidc"`
	Egress      string               `json:"oidc_egress"`
	Operators   []operatorMembership `json:"operators"`
}

func identityReport(cfg *config.Config) consoleIdentity {
	report := consoleIdentity{
		Token: cfg.Console.TokenEnabled(), Tenants: cfg.Console.Tenants,
		LocalTenant: cfg.Console.LocalTenant, OIDC: cfg.Console.OIDC,
		Egress: "disabled", Operators: []operatorMembership{},
	}
	for _, op := range cfg.Console.Operators {
		report.Operators = append(report.Operators, operatorMembership{
			Name: op.Name, Role: op.Role, Tenants: tenant.Membership(op.Tenants),
		})
	}
	if cfg.Console.OIDC.Enabled {
		report.Egress = "hostname; resolved sockets classified at dial time"
		u, err := egress.ValidateURL(cfg.Console.OIDC.EgressPolicy(), cfg.Console.OIDC.Issuer)
		if err != nil {
			report.Egress = "denied"
		} else if ip := net.ParseIP(u.Hostname()); ip != nil {
			report.Egress = "public HTTPS"
			if ip.IsLoopback() {
				report.Egress = "loopback"
			} else if ip.IsPrivate() {
				report.Egress = "private; explicit opt-in"
			}
		}
	}
	return report
}

func printIdentity(w io.Writer, cfg *config.Config) {
	encoded, _ := json.Marshal(identityReport(cfg))
	fmt.Fprintf(w, "  console identity (static; no discovery): %s\n", encoded)
}
