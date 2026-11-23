package config

import (
	"encoding/json"
	"os"
	"strings"
)

// Setting provenance values reported by the console settings view.
const (
	SourceConfig  = "config"
	SourceEnv     = "env"
	SourceDefault = "default"
)

// SettingSourceKeys maps each dotted configuration key whose provenance is
// recorded to the environment variable that can override it ("" when none).
// The list is fixed at compile time; nothing request-supplied selects it.
var SettingSourceKeys = map[string]string{
	"console.token_login":               "AEGISMESH_CONSOLE_TOKEN_LOGIN",
	"console.listen":                    "AEGISMESH_CONSOLE_LISTEN",
	"console.session_ttl_seconds":       "",
	"console.session_idle_seconds":      "",
	"console.index_max_events":          "",
	"console.tls_cert_file":             "",
	"console.operators":                 "AEGISMESH_CONSOLE_OPERATORS",
	"console.tenants":                   "AEGISMESH_CONSOLE_TENANTS",
	"console.local_tenant":              "AEGISMESH_CONSOLE_LOCAL_TENANT",
	"console.state_dir":                 "",
	"console.oidc.enabled":              "AEGISMESH_CONSOLE_OIDC_ENABLED",
	"console.oidc.issuer":               "AEGISMESH_CONSOLE_OIDC_ISSUER",
	"console.oidc.client_id":            "AEGISMESH_CONSOLE_OIDC_CLIENT_ID",
	"console.oidc.role_claim":           "AEGISMESH_CONSOLE_OIDC_ROLE_CLAIM",
	"console.oidc.tenant_claim":         "AEGISMESH_CONSOLE_OIDC_TENANT_CLAIM",
	"console.oidc.role_mapping":         "AEGISMESH_CONSOLE_OIDC_ROLE_MAPPING",
	"console.oidc.tenant_mapping":       "AEGISMESH_CONSOLE_OIDC_TENANT_MAPPING",
	"runtime.data_dir":                  "AEGISMESH_DATA_DIR",
	"storage.encryption":                "",
	"storage.retention.max_events":      "",
	"storage.retention.max_age_days":    "",
	"detection.enabled":                 "",
	"detection.actions":                 "",
	"correlation.enabled":               "",
	"fleet.hub.enabled":                 "AEGISMESH_FLEET_HUB_ENABLED",
	"fleet.agent.enabled":               "AEGISMESH_FLEET_AGENT_ENABLED",
	"fleet.hub.accept_evidence":         "",
	"fleet.agent.forward_evidence":      "",
	"security.allow_public_bind":        "",
	"security.allow_privileged_ports":   "",
	"security.allow_private_llm_egress": "",
}

// settingSources reports provenance from key presence in the raw document and
// from environment variables that the loader applies. Values are never read.
func settingSources(raw []byte, ext string) map[string]string {
	var document map[string]any
	if ext == ".json" {
		_ = json.Unmarshal(raw, &document)
	} else {
		_ = yamlUnmarshalLenient(raw, &document)
	}
	sources := make(map[string]string, len(SettingSourceKeys))
	for key, env := range SettingSourceKeys {
		sources[key] = SourceDefault
		if present(document, strings.Split(key, ".")) {
			sources[key] = SourceConfig
		}
		if env != "" {
			if value, ok := os.LookupEnv(env); ok && strings.TrimSpace(value) != "" {
				sources[key] = SourceEnv
			}
		}
	}
	return sources
}

func present(document map[string]any, path []string) bool {
	var current any = document
	for _, segment := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return false
		}
		current, ok = object[segment]
		if !ok {
			return false
		}
	}
	return true
}
