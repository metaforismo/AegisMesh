package config

import (
	"encoding/hex"
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/metaforismo/aegismesh/internal/console/tenant"
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
	// SessionIdleSeconds ends a browser session after this much inactivity:
	// nil means DefaultSessionIdleSeconds, 0 disables, otherwise 300..86400.
	SessionIdleSeconds *int `yaml:"session_idle_seconds" json:"session_idle_seconds"`
	// IndexMaxEvents bounds retained evidence projections to 1000..500000 entries.
	IndexMaxEvents int `yaml:"index_max_events" json:"index_max_events"`
	// TLSCertFile is the trusted PEM certificate path.
	TLSCertFile string `yaml:"tls_cert_file" json:"tls_cert_file"`
	// TLSKeyFile is the trusted PEM private key path.
	TLSKeyFile string `yaml:"tls_key_file" json:"tls_key_file"`
	// Operators contains at most 32 named operator digests.
	Operators []Operator `yaml:"operators" json:"operators"`
	// SettingsEditing is "off" (default: the console never changes settings) or
	// "console": principals with settings.manage may override the fixed
	// allowlist of console-only settings in an overlay under state_dir. The
	// overlay never writes this file.
	SettingsEditing string `yaml:"settings_editing" json:"settings_editing"`
	// KeyMaxDays bounds managed API key lifetimes to 1..365 days (default 365).
	KeyMaxDays int `yaml:"key_max_days" json:"key_max_days"`
	// KeyDefaultDays is the lifetime of keys created without one: 1..key_max_days
	// (default 90, or key_max_days when that is lower).
	KeyDefaultDays int `yaml:"key_default_days" json:"key_default_days"`
	// SignInBanner is optional plain text (at most 500 runes, newlines allowed)
	// shown on the sign-in page and once per session.
	SignInBanner string `yaml:"sign_in_banner" json:"sign_in_banner"`
	// OrganizationName is optional plain text (at most 80 runes) shown in the
	// console top bar and reports.
	OrganizationName string `yaml:"organization_name" json:"organization_name"`
	// DefaultWindow is the time window of principals without saved preferences:
	// 1h, 24h (default) or 7d.
	DefaultWindow string `yaml:"default_window" json:"default_window"`
}

// Settings editing modes.
const (
	SettingsEditingOff     = "off"
	SettingsEditingConsole = "console"
)

// Console text and key-lifetime bounds shared with the settings overlay.
const (
	MaxSignInBannerRunes     = 500
	MaxOrganizationNameRunes = 80
	MaxKeyDays               = 365
	DefaultKeyDays           = 90
)

// ValidBanner accepts at most 500 printable runes; newline is the only control allowed.
func ValidBanner(text string) bool { return plainText(text, MaxSignInBannerRunes, true) }

// ValidOrganizationName accepts at most 80 printable runes on one line.
func ValidOrganizationName(text string) bool {
	return plainText(text, MaxOrganizationNameRunes, false)
}

// ValidWindow accepts the fixed console time windows.
func ValidWindow(window string) bool { return window == "1h" || window == "24h" || window == "7d" }

func plainText(text string, max int, newlines bool) bool {
	if !utf8.ValidString(text) || utf8.RuneCountInString(text) > max || strings.TrimSpace(text) != text {
		return false
	}
	for _, r := range text {
		if r == '\n' && newlines {
			continue
		}
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
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

// DefaultSessionIdleSeconds is the idle timeout applied when the field is omitted.
const DefaultSessionIdleSeconds = 1800

// IdleSeconds returns the effective idle timeout; zero means disabled.
func (c Console) IdleSeconds() int {
	if c.SessionIdleSeconds == nil {
		return DefaultSessionIdleSeconds
	}
	return *c.SessionIdleSeconds
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

	if c.SessionIdleSeconds == nil {
		idle := DefaultSessionIdleSeconds
		c.SessionIdleSeconds = &idle
	}
	c.applyConsoleDefaults()
}

// applyConsoleDefaults fills the round-6 console fields; WithDefaults uses it too.
func (c *Console) applyConsoleDefaults() {
	if c.SettingsEditing == "" {
		c.SettingsEditing = SettingsEditingOff
	}
	if c.KeyMaxDays == 0 {
		c.KeyMaxDays = MaxKeyDays
	}
	if c.KeyDefaultDays == 0 {
		c.KeyDefaultDays = min(DefaultKeyDays, c.KeyMaxDays)
	}
	if c.DefaultWindow == "" {
		c.DefaultWindow = "24h"
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

	if idle := consoleConfig.IdleSeconds(); idle != 0 && (idle < 300 || idle > 86400) {
		return fail("session_idle_seconds must be 0 (disabled) or within 300..86400")
	}

	if consoleConfig.IndexMaxEvents < 1000 || consoleConfig.IndexMaxEvents > 500000 {
		return fail("index_max_events must be within 1000..500000")
	}

	if consoleConfig.SettingsEditing != "" && consoleConfig.SettingsEditing != SettingsEditingOff &&
		consoleConfig.SettingsEditing != SettingsEditingConsole {
		return fail("settings_editing must be off or console")
	}

	maxDays := consoleConfig.KeyMaxDays
	if maxDays == 0 {
		maxDays = MaxKeyDays
	}
	if maxDays < 1 || maxDays > MaxKeyDays {
		return fail("key_max_days must be within 1..365")
	}
	if days := consoleConfig.KeyDefaultDays; days != 0 && (days < 1 || days > maxDays) {
		return fail("key_default_days must be within 1..key_max_days")
	}

	if !ValidBanner(consoleConfig.SignInBanner) {
		return fail("sign_in_banner must be at most 500 printable characters without surrounding whitespace")
	}

	if !ValidOrganizationName(consoleConfig.OrganizationName) {
		return fail("organization_name must be at most 80 printable characters on one line without surrounding whitespace")
	}

	if consoleConfig.DefaultWindow != "" && !ValidWindow(consoleConfig.DefaultWindow) {
		return fail("default_window must be 1h, 24h or 7d")
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
