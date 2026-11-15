package config

import (
	"errors"
	"os"
	"strconv"
)

// WithDefaults normalizes programmatic console configurations like loaded files.
func (c Console) WithDefaults() Console {
	c.defaults()
	return c
}

func (c *Config) consoleEnv() error {
	stringsByName := map[string]*string{
		"LOCAL_TENANT":            &c.Console.LocalTenant,
		"OIDC_DISPLAY_NAME":       &c.Console.OIDC.DisplayName,
		"OIDC_ISSUER":             &c.Console.OIDC.Issuer,
		"OIDC_CLIENT_ID":          &c.Console.OIDC.ClientID,
		"OIDC_CLIENT_SECRET_ENV":  &c.Console.OIDC.ClientSecretEnv,
		"OIDC_CLIENT_SECRET_FILE": &c.Console.OIDC.ClientSecretFile,
		"OIDC_REDIRECT_URI":       &c.Console.OIDC.RedirectURI,
		"OIDC_ROLE_CLAIM":         &c.Console.OIDC.RoleClaim,
		"OIDC_NAME_CLAIM":         &c.Console.OIDC.NameClaim,
		"OIDC_TENANT_CLAIM":       &c.Console.OIDC.TenantClaim,
	}
	for name, target := range stringsByName {
		if value, exists := os.LookupEnv("AEGISMESH_CONSOLE_" + name); exists {
			*target = value
		}
	}
	boolsByName := map[string]*bool{
		"OIDC_ENABLED":              &c.Console.OIDC.Enabled,
		"OIDC_ALLOW_PRIVATE_EGRESS": &c.Console.OIDC.AllowPrivateEgress,
	}
	for name, target := range boolsByName {
		if value, exists := os.LookupEnv("AEGISMESH_CONSOLE_" + name); exists {
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return errors.New("console boolean environment override is invalid")
			}
			*target = parsed
		}
	}
	if value, exists := os.LookupEnv("AEGISMESH_CONSOLE_TOKEN_LOGIN"); exists {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return errors.New("console token_login environment override is invalid")
		}
		c.Console.TokenLogin = &parsed
	}
	jsonByName := map[string]any{
		"TENANTS":             &c.Console.Tenants,
		"OPERATORS":           &c.Console.Operators,
		"OIDC_ROLE_MAPPING":   &c.Console.OIDC.RoleMapping,
		"OIDC_TENANT_MAPPING": &c.Console.OIDC.TenantMapping,
	}
	for name, target := range jsonByName {
		if value, exists := os.LookupEnv("AEGISMESH_CONSOLE_" + name); exists {
			if len(value) > 64<<10 || strictJSON([]byte(value), target) != nil {
				return errors.New("console JSON environment override is invalid")
			}
		}
	}
	return nil
}
