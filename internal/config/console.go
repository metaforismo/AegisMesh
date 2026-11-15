package config

import (
	"encoding/hex"
	"fmt"
	"github.com/metaforismo/aegismesh/internal/console/tenant"
	"net"
	"path/filepath"
	"slices"
)

// Console is a separate, authenticated read-mostly operator listener.
type Console struct {
	// TokenLogin permits token sessions and bearer authentication; nil means true.
	TokenLogin *bool `yaml:"token_login" json:"token_login"`
	// OIDC opts into SSO via a fixed issuer and explicit authorization mappings.
	OIDC OIDC `yaml:"oidc" json:"oidc"`
	// Tenants declares the process partitions; omitted means only default.
	Tenants []string `yaml:"tenants" json:"tenants"`
	// LocalTenant owns local evidence, runtime status, sensors and rules.
	LocalTenant string `yaml:"local_tenant" json:"local_tenant"`
	// Enabled enables the dedicated console listener.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Listen is the validated console bind authority.
	Listen string `yaml:"listen" json:"listen"`
	// StateDir selects trusted operator state storage, separate from evidence.
	StateDir string `yaml:"state_dir" json:"state_dir"`
	// SessionTTLSeconds bounds an absolute session lifetime to 60..86400 seconds.
	SessionTTLSeconds int `yaml:"session_ttl_seconds" json:"session_ttl_seconds"`
	// IndexMaxEvents bounds retained evidence projections to 1000..500000 entries.
	IndexMaxEvents int `yaml:"index_max_events" json:"index_max_events"`
	// TLSCertFile is the trusted PEM certificate path.
	TLSCertFile string `yaml:"tls_cert_file" json:"tls_cert_file"`
	// TLSKeyFile is the trusted PEM private key path.
	TLSKeyFile string `yaml:"tls_key_file" json:"tls_key_file"`
	// Operators contains at most 32 named operator digests.
	Operators []Operator `yaml:"operators" json:"operators"`
}

// Operator configures a named role and token digest; raw credentials are never stored here.
type Operator struct {
	// Tenants declares membership; omitted preserves default membership.
	Tenants []string `yaml:"tenants" json:"tenants"`
	// Name is a unique validated operator slug.
	Name string `yaml:"name" json:"name"`
	// Role is viewer, analyst, or admin.
	Role string `yaml:"role" json:"role"`
	// TokenSHA256 contains a 64-character hex digest, never the raw token.
	TokenSHA256 string `yaml:"token_sha256" json:"token_sha256"`
}

// TokenEnabled reports the compatibility-default token authentication policy.
func (c Console) TokenEnabled() bool { return c.TokenLogin == nil || *c.TokenLogin }

func (c *Console) defaults() {
	c.Tenants = tenant.Names(c.Tenants)
	c.LocalTenant = tenant.Local(c.LocalTenant)
	c.OIDC.defaults()
	if c.Listen == "" {
		c.Listen = "127.0.0.1:9120"
	}

	if c.SessionTTLSeconds == 0 {
		c.SessionTTLSeconds = 3600
	}

	if c.IndexMaxEvents == 0 {
		c.IndexMaxEvents = 50000
	}
}

// ConsoleStateDir resolves trusted console state configuration relative to the config file.
func (c *Config) ConsoleStateDir() string {
	if c.Console.StateDir == "" {
		return filepath.Join(c.Runtime.DataDir, "console")
	}

	if filepath.IsAbs(c.Console.StateDir) {
		return c.Console.StateDir
	}

	return filepath.Join(filepath.Dir(absClean(c.SourcePath)), c.Console.StateDir)
}

// ValidateConsole checks exposure before constructing the dedicated listener.
func (c *Config) ValidateConsole() error {
	consoleConfig := c.Console
	fail := func(message string) error {
		return fmt.Errorf("%w: console: %s", errConfig, message)
	}

	if consoleConfig.SessionTTLSeconds < 60 || consoleConfig.SessionTTLSeconds > 86400 {
		return fail("session_ttl_seconds must be within 60..86400")
	}

	if consoleConfig.IndexMaxEvents < 1000 || consoleConfig.IndexMaxEvents > 500000 {
		return fail("index_max_events must be within 1000..500000")
	}

	if (consoleConfig.TLSCertFile == "") != (consoleConfig.TLSKeyFile == "") {
		return fail("tls_cert_file and tls_key_file must be set together")
	}

	if err := consoleConfig.validateIdentity(); err != nil {
		return fail(err.Error())
	}
	if len(consoleConfig.Operators) > 32 ||
		(consoleConfig.Enabled && consoleConfig.TokenEnabled() && len(consoleConfig.Operators) == 0) {
		return fail("enabled console requires 1..32 operators")
	}

	names := map[string]bool{}
	digests := map[string]bool{}
	for _, operator := range consoleConfig.Operators {
		if !slugRe.MatchString(operator.Name) || names[operator.Name] {
			return fail("operator names must be unique slugs")
		}
		names[operator.Name] = true
		members := map[string]bool{}
		for _, name := range tenant.Membership(operator.Tenants) {
			if members[name] {
				return fail("operator tenants must be unique")
			}
			members[name] = true
			if !slices.Contains(tenant.Names(consoleConfig.Tenants), name) {
				return fail("operator tenant is undeclared")
			}
		}
		if len(operator.Tenants) > tenant.MaxTenants {
			return fail("operator tenants exceeds 32")
		}
		if operator.Role != "viewer" && operator.Role != "analyst" && operator.Role != "admin" {
			return fail("operator role must be viewer|analyst|admin")
		}
		digest, err := hex.DecodeString(operator.TokenSHA256)
		if err != nil || len(digest) != 32 {
			return fail("token_sha256 must be 64 hex characters")
		}
		key := hex.EncodeToString(digest)
		if digests[key] {
			return fail("operator digests must be unique")
		}
		digests[key] = true
	}

	if !consoleConfig.Enabled {
		return nil
	}

	if err := c.validateListen("console", consoleConfig.Listen, "http"); err != nil {
		return err
	}

	host, _, _ := net.SplitHostPort(consoleConfig.Listen)
	ip := net.ParseIP(host)
	if host != "localhost" &&
		(ip == nil ||
			!ip.IsLoopback()) &&
		(!c.Security.AllowPublicBind ||
			consoleConfig.TLSCertFile == "") {
		return fail("non-loopback listen requires TLS files and security.allow_public_bind")
	}

	return nil
}
