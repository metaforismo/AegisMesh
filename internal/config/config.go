// Package config defines the schema-versioned AegisMesh configuration, its
// strict loader, environment overrides, and validation rules.
//
// Precedence (highest wins): command-line flags > AEGISMESH_* environment
// variables > config file > built-in defaults.
package config

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

const (
	// APIVersionV1Alpha1 is the only supported configuration schema version.
	APIVersionV1Alpha1 = "aegismesh.io/v1alpha1"

	SensorKindHTTP = "http"
	SensorKindTCP  = "tcp"
	SensorKindMCP  = "mcp"
)

// Hard caps applied at validation time so a malicious or careless config
// cannot make the runtime allocate unboundedly.
const (
	MaxSensors          = 64
	MaxRulesPerSensor   = 64
	MaxRegexLen         = 256
	MaxHTTPBodyBytes    = 64 << 10 // inline HTTP body cap per rule
	MaxHeaderCount      = 16
	MaxHeaderValueLen   = 1 << 10
	MaxBannerBytes      = 4 << 10
	MaxTCPResponseBytes = 4 << 10
	MaxMCPTools         = 32
	MaxMCPResultBytes   = 16 << 10
	MaxMCPSchemaBytes   = 8 << 10

	defaultDataDir         = "./data"
	defaultAdminListen     = "127.0.0.1:9110"
	defaultMaxBodyBytes    = 64 << 10
	defaultLineBytes       = 4096
	defaultIdleTimeoutS    = 30
	defaultSessionTimeoutS = 300
	defaultMaxEvents       = 100000
	defaultMaxAgeDays      = 30
	defaultMaxFileBytes    = 16 << 20
	defaultMaxEventBytes   = 256 << 10
)

// Config is the root configuration document.
type Config struct {
	APIVersion string   `yaml:"api_version" json:"api_version"`
	Runtime    Runtime  `yaml:"runtime"    json:"runtime"`
	Storage    Storage  `yaml:"storage"    json:"storage"`
	Admin      Admin    `yaml:"admin"      json:"admin"`
	Logging    Logging  `yaml:"logging"    json:"logging"`
	Security   Security `yaml:"security"   json:"security"`
	LLM        LLM      `yaml:"llm"        json:"llm"`
	Sensors    []Sensor `yaml:"sensors"    json:"sensors"`

	// SourcePath records where this config was loaded from; never decoded from YAML.
	SourcePath string `yaml:"-" json:"-"`
}

type Runtime struct {
	InstanceName string `yaml:"instance_name" json:"instance_name"`
	DataDir      string `yaml:"data_dir"      json:"data_dir"`
}

type Storage struct {
	Retention     Retention `yaml:"retention"       json:"retention"`
	MaxFileBytes  int64     `yaml:"max_file_bytes"  json:"max_file_bytes"`
	MaxEventBytes int       `yaml:"max_event_bytes" json:"max_event_bytes"`
}

type Retention struct {
	MaxEvents  int `yaml:"max_events"   json:"max_events"`
	MaxAgeDays int `yaml:"max_age_days" json:"max_age_days"`
}

type Admin struct {
	// Enabled is a pointer so that "unset" can default to true while an
	// explicit `enabled: false` is honored.
	Enabled *bool  `yaml:"enabled,omitempty" json:"enabled"`
	Listen  string `yaml:"listen"            json:"listen"`
}

type Logging struct {
	Level  string `yaml:"level"  json:"level"`
	Format string `yaml:"format" json:"format"`
}

// Security carries the two explicit opt-ins that relax safe defaults. Both
// default to false; both must be set deliberately by an operator.
type Security struct {
	AllowPublicBind      bool `yaml:"allow_public_bind"       json:"allow_public_bind"`
	AllowPrivilegedPorts bool `yaml:"allow_privileged_ports"  json:"allow_privileged_ports"`
}

// LLM selects the response provider backend. APIKey is populated from the
// AEGISMESH_LLM_API_KEY environment variable only — it is never read from or
// written to config files, and it is excluded from JSON serialization.
type LLM struct {
	Provider string `yaml:"provider"             json:"provider"` // "" | local | openai
	BaseURL  string `yaml:"base_url,omitempty"   json:"base_url,omitempty"`
	Model    string `yaml:"model,omitempty"      json:"model,omitempty"`
	APIKey   string `yaml:"-"                    json:"-"`
}

type Sensor struct {
	ID     string `yaml:"id"     json:"id"`
	Kind   string `yaml:"kind"   json:"kind"`
	Listen string `yaml:"listen" json:"listen"`

	// HTTP fields.
	Persona      *HTTPPersona `yaml:"persona,omitempty"      json:"persona,omitempty"`
	Rules        []HTTPRule   `yaml:"rules,omitempty"        json:"rules,omitempty"`
	Fallback     *LLMFallback `yaml:"fallback,omitempty"     json:"fallback,omitempty"`
	MaxBodyBytes int64        `yaml:"max_body_bytes,omitempty" json:"max_body_bytes,omitempty"`

	// TCP fields.
	Banner          string      `yaml:"banner,omitempty"           json:"banner,omitempty"`
	Session         *TCPSession `yaml:"session,omitempty"          json:"session,omitempty"`
	TCPResponseRule []TCPRule   `yaml:"tcp_rules,omitempty"        json:"tcp_rules,omitempty"`

	// MCP fields.
	MCPPath      string    `yaml:"path,omitempty"            json:"path,omitempty"`
	ServerName   string    `yaml:"server_name,omitempty"     json:"server_name,omitempty"`
	ServerVer    string    `yaml:"server_version,omitempty"  json:"server_version,omitempty"`
	Instructions string    `yaml:"instructions,omitempty"    json:"instructions,omitempty"`
	Tools        []MCPTool `yaml:"tools,omitempty"           json:"tools,omitempty"`
}

type HTTPPersona struct {
	ServerHeader string `yaml:"server_header" json:"server_header"`
}

type LLMFallback struct {
	Enabled       bool   `yaml:"enabled"         json:"enabled"`
	SystemPrompt  string `yaml:"system_prompt"   json:"system_prompt"`
	MaxReplyChars int    `yaml:"max_reply_chars" json:"max_reply_chars"`
}

type HTTPRule struct {
	Name      string            `yaml:"name"                json:"name"`
	PathRegex string            `yaml:"path_regex"          json:"path_regex"`
	Methods   []string          `yaml:"methods,omitempty"   json:"methods,omitempty"`
	Status    int               `yaml:"status"              json:"status"`
	Headers   map[string]string `yaml:"headers,omitempty"   json:"headers,omitempty"`
	Body      string            `yaml:"body,omitempty"      json:"body,omitempty"`
	BodyFile  string            `yaml:"body_file,omitempty" json:"body_file,omitempty"`
}

type TCPSession struct {
	MaxLineBytes       int `yaml:"max_line_bytes"        json:"max_line_bytes"`
	IdleTimeoutSeconds int `yaml:"idle_timeout_seconds"  json:"idle_timeout_seconds"`
	MaxSessionSeconds  int `yaml:"max_session_seconds"   json:"max_session_seconds"`
}

type TCPRule struct {
	Name      string `yaml:"name"      json:"name"`
	LineRegex string `yaml:"line_regex" json:"line_regex"`
	Response  string `yaml:"response"  json:"response"`
}

type MCPTool struct {
	Name        string   `yaml:"name"                   json:"name"`
	Description string   `yaml:"description"            json:"description"`
	InputSchema FlexJSON `yaml:"input_schema,omitempty" json:"input_schema,omitempty"`
	ResultJSON  string   `yaml:"result_json"            json:"result_json"`
}

// FlexJSON accepts JSON either inline (as a quoted JSON string) or as a native
// nested YAML/JSON object, normalizing both to raw JSON bytes. It exists so
// tool schemas stay copy-paste friendly in both formats.
type FlexJSON []byte

func (f *FlexJSON) UnmarshalYAML(value *yaml.Node) error {
	var v any
	if err := value.Decode(&v); err != nil {
		return fmt.Errorf("input_schema: %v", err)
	}
	switch tv := v.(type) {
	case nil:
		*f = nil
	case string:
		if !json.Valid([]byte(tv)) {
			return fmt.Errorf("input_schema: string is not valid JSON")
		}
		*f = FlexJSON(tv)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("input_schema: %v", err)
		}
		*f = b
	}
	return nil
}

// MarshalJSON emits the raw bytes verbatim so API output stays real JSON.
func (f FlexJSON) MarshalJSON() ([]byte, error) {
	if len(f) == 0 {
		return []byte("null"), nil
	}
	return f, nil
}
