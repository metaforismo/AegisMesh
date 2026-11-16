package config

import (
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/metaforismo/aegismesh/internal/console/tenant"
	"github.com/metaforismo/aegismesh/internal/egress"
)

// OIDC configures experimental SSO; credentials are references only.
type OIDC struct {
	// Enabled opts into issuer discovery only when the console starts.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// DisplayName is the bounded label presented by the sign-in UI.
	DisplayName string `yaml:"display_name" json:"display_name"`
	// Issuer is the exact expected issuer, classified by the shared egress policy.
	Issuer string `yaml:"issuer" json:"issuer"`
	// ClientID is the registered relying-party identifier.
	ClientID string `yaml:"client_id" json:"client_id"`
	// ClientSecretFile references a private config-relative file for confidential clients.
	ClientSecretFile string `yaml:"client_secret_file" json:"client_secret_file"`
	// ClientSecretEnv names the secret environment variable for confidential clients.
	ClientSecretEnv string `yaml:"client_secret_env" json:"client_secret_env"`
	// RedirectURI is the exact registered console callback URL.
	RedirectURI string `yaml:"redirect_uri" json:"redirect_uri"`
	// RoleClaim names a string or array claim interpreted through RoleMapping.
	RoleClaim string `yaml:"role_claim" json:"role_claim"`
	// RoleMapping maps exact claim values to viewer, analyst or admin; highest wins.
	RoleMapping map[string]string `yaml:"role_mapping" json:"role_mapping"`
	// NameClaim names the display name claim, falling back to sub.
	NameClaim string `yaml:"name_claim" json:"name_claim"`
	// TenantClaim names the string or array membership claim; no match denies login.
	TenantClaim string `yaml:"tenant_claim" json:"tenant_claim"`
	// TenantMapping optionally translates claim values to declared tenant names.
	TenantMapping map[string]string `yaml:"tenant_mapping" json:"tenant_mapping"`
	// AllowPrivateEgress explicitly permits private issuer addresses, never metadata/link-local.
	AllowPrivateEgress bool `yaml:"allow_private_egress" json:"allow_private_egress"`
}

func (c *OIDC) defaults() {
	if c.DisplayName == "" {
		c.DisplayName = "Single sign-on"
	}
	if c.RoleClaim == "" {
		c.RoleClaim = "groups"
	}
	if c.NameClaim == "" {
		c.NameClaim = "email"
	}
	if c.TenantClaim == "" {
		c.TenantClaim = "tenants"
	}
}

// EgressPolicy returns the issuer-specific destination classification policy.
func (c OIDC) EgressPolicy() egress.Policy {
	return egress.Policy{AllowLoopback: true, AllowPrivate: c.AllowPrivateEgress}
}

func boundedText(value string, limit int) bool {
	if value == "" || len(value) > limit {
		return false
	}
	for _, r := range value {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}

func (c Console) validateIdentity() error {
	fail := func(message string) error { return errors.New(message) }
	names := tenant.Names(c.Tenants)
	if len(names) > tenant.MaxTenants {
		return fail("tenants exceeds 32")
	}
	seen := map[string]bool{}
	for _, name := range names {
		if _, err := tenant.Parse(name); err != nil || seen[name] {
			return fail("tenants must be unique canonical slugs")
		}
		seen[name] = true
	}
	if !slices.Contains(names, tenant.Local(c.LocalTenant)) {
		return fail("local_tenant must be declared")
	}
	if !c.TokenEnabled() && !c.OIDC.Enabled {
		return fail("token_login=false requires OIDC")
	}
	o := c.OIDC
	o.defaults()
	if !boundedText(o.DisplayName, 64) || (o.Enabled || o.ClientID != "") && !boundedText(o.ClientID, 256) {
		return fail("invalid OIDC display_name or client_id")
	}
	if o.Enabled || o.Issuer != "" {
		if len(o.Issuer) > 512 {
			return fail("OIDC issuer exceeds 512 bytes")
		}
		issuer, err := egress.ValidateURL(o.EgressPolicy(), o.Issuer)
		if err != nil || issuer.ForceQuery || strings.TrimSpace(o.Issuer) != o.Issuer {
			return fail("OIDC issuer must be an allowed HTTPS URL (HTTP only on loopback)")
		}
	}
	if o.Enabled || o.RedirectURI != "" {
		redirect, err := egress.ValidateURL(egress.Policy{AllowLoopback: true, AllowPrivate: true}, o.RedirectURI)
		if err != nil || len(o.RedirectURI) > 1024 || redirect.Path != "/api/v1/auth/oidc/callback" ||
			redirect.RawPath != "" || redirect.ForceQuery {
			return fail("OIDC redirect_uri must be the exact console callback URL")
		}
		if (c.TLSCertFile != "") != (redirect.Scheme == "https") {
			return fail("OIDC redirect_uri scheme must match console TLS")
		}
	}
	if o.ClientSecretEnv != "" && !envNameRe.MatchString(o.ClientSecretEnv) {
		return fail("invalid OIDC client_secret_env")
	}
	if o.ClientSecretEnv != "" && o.ClientSecretFile != "" {
		return fail("OIDC secret references are mutually exclusive")
	}
	if len(o.ClientSecretFile) > 4096 {
		return fail("OIDC secret file reference exceeds 4096 bytes")
	}
	path := filepath.Clean(o.ClientSecretFile)
	if o.ClientSecretFile != "" && (filepath.IsAbs(path) || path == ".." || strings.HasPrefix(path, "../")) {
		return fail("OIDC secret file must remain in config directory")
	}
	for _, claim := range []string{o.RoleClaim, o.NameClaim, o.TenantClaim} {
		if !boundedText(claim, 64) {
			return fail("OIDC claim names require 1..64 printable bytes")
		}
	}
	if o.Enabled && len(o.RoleMapping) == 0 || len(o.RoleMapping) > 128 || len(o.TenantMapping) > 128 {
		return fail("OIDC role_mapping requires 1..128 entries; tenant_mapping at most 128")
	}
	for value, role := range o.RoleMapping {
		if !boundedText(value, 128) || (role != "viewer" && role != "analyst" && role != "admin") {
			return fail("invalid OIDC role_mapping")
		}
	}
	for value, name := range o.TenantMapping {
		if !boundedText(value, 128) || !seen[name] {
			return fail("invalid OIDC tenant_mapping")
		}
	}
	return nil
}

// ResolveOIDCSecret materializes a bounded reference only at console construction.
func (c *Config) ResolveOIDCSecret() (string, error) {
	o := c.Console.OIDC
	if !o.Enabled {
		return "", nil
	}
	value := ""
	if o.ClientSecretEnv != "" {
		value = os.Getenv(o.ClientSecretEnv)
	} else if o.ClientSecretFile != "" {
		root, err := os.OpenRoot(filepath.Dir(absClean(c.SourcePath)))
		if err != nil {
			return "", errors.New("OIDC: cannot open credential directory")
		}
		defer root.Close()
		info, err := root.Lstat(o.ClientSecretFile)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return "", errors.New("OIDC: credential reference must be regular mode 0600")
		}
		file, err := root.Open(o.ClientSecretFile)
		if err != nil {
			return "", errors.New("OIDC: cannot open credential reference")
		}
		defer file.Close()
		body, err := io.ReadAll(io.LimitReader(file, 4097))
		if err != nil || len(body) > 4096 {
			return "", errors.New("OIDC: cannot read credential reference")
		}
		value = string(body)
	} else {
		return "", nil
	}
	value = strings.TrimSpace(value)
	if !boundedText(value, 4096) {
		return "", errors.New("OIDC: credential is empty or exceeds bounds")
	}
	return value, nil
}

// OIDCOrigin reports destination authority without credentials or paths.
func (c OIDC) OIDCOrigin() string {
	u, err := url.Parse(c.Issuer)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
