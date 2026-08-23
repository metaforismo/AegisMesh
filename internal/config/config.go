// Package config defines the schema-versioned AegisMesh configuration, its
// strict loader, environment overrides, and validation rules.
//
// Precedence (highest wins): command-line flags > AEGISMESH_* environment
// variables > config file > built-in defaults.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

const (
	// APIVersionV1Alpha1 is the only supported configuration schema version.
	// Additive optional fields may extend this version when they carry safe
	// defaults and leave existing semantics untouched (ADR-0003, ADR-0009).
	APIVersionV1Alpha1 = "aegismesh.io/v1alpha1"

	SensorKindHTTP = "http"
	SensorKindTCP  = "tcp"
	SensorKindMCP  = "mcp"
	SensorKindSSH  = "ssh"
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

	// SSH identification and session bounds. The defaults keep the sensor
	// useful for observation while limiting handshake work and connection
	// lifetime on an untrusted network.
	DefaultSSHServerVersion           = "SSH-2.0-AegisMesh"
	DefaultSSHListen                  = "127.0.0.1:2222"
	MaxSSHServerVersionBytes          = 128
	DefaultSSHHandshakeTimeoutSeconds = 10
	MaxSSHHandshakeTimeoutSeconds     = 60
	DefaultSSHMaxSessionSeconds       = 30
	MaxSSHSessionSeconds              = 300
	DefaultSSHMaxAuthAttempts         = 3
	MaxSSHAuthAttempts                = 6

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

	// Provider transport defaults and hard caps.
	DefaultLLMTimeoutSeconds = 20
	MaxLLMTimeoutSeconds     = 120
	DefaultLLMResponseBytes  = 1 << 20
	MaxLLMResponseBytes      = 8 << 20
	DefaultAPIKeyFileBytes   = 4 << 10
	MaxAPIKeyFileBytes       = 64 << 10
	DefaultOllamaBaseURL     = "http://127.0.0.1:11434/v1"

	// Detection evaluation bounds.
	MaxDetectInputBytes    = 64 << 10 // engine never evaluates more than this per interaction
	DefaultDetectionMaxLen = 8 << 10

	// Extension supervisor bounds.
	MaxExtensions             = 4
	DefaultExtensionQueueSize = 256
	MinExtensionQueueSize     = 16
	MaxExtensionQueueSize     = 4096
	DefaultExtensionFlushSecs = 2
	MinExtensionFlushSecs     = 1
	MaxExtensionFlushSecs     = 10

	// Webhook sink bounds.
	DefaultWebhookQueueSize   = 512
	MinWebhookQueueSize       = 16
	MaxWebhookQueueSize       = 8192
	DefaultWebhookBatchSize   = 32
	MinWebhookBatchSize       = 1
	MaxWebhookBatchSize       = 256
	DefaultWebhookFlushSecs   = 5
	MinWebhookFlushSecs       = 1
	MaxWebhookFlushSecs       = 60
	DefaultWebhookTimeoutSecs = 10
	MinWebhookTimeoutSecs     = 1
	MaxWebhookTimeoutSecs     = 60
	DefaultWebhookMaxRetries  = 3
	MaxWebhookMaxRetries      = 8
	MaxWebhookSecretFileBytes = 4096

	// Correlation engine schema bounds. Numeric limits mirror
	// internal/correlate.Options clamps; rule ids are validated against the
	// correlate registry itself (single source of truth).
	DefaultCorrelationWindowSecs   = 600 // 10m
	MinCorrelationWindowSecs       = 60  // engine max window is 1h
	MaxCorrelationWindowSecs       = 3600
	DefaultCorrelationPerSrcEvents = 64
	MinCorrelationPerSrcEvents     = 8
	MaxCorrelationPerSrcEvents     = 512
	DefaultCorrelationMaxSources   = 4096
	MinCorrelationMaxSources       = 64
	MaxCorrelationMaxSources       = 65536
)

// Config is the root configuration document.
type Config struct {
	APIVersion  string      `yaml:"api_version" json:"api_version"`
	Runtime     Runtime     `yaml:"runtime"     json:"runtime"`
	Storage     Storage     `yaml:"storage"     json:"storage"`
	Admin       Admin       `yaml:"admin"       json:"admin"`
	Logging     Logging     `yaml:"logging"     json:"logging"`
	Security    Security    `yaml:"security"    json:"security"`
	LLM         LLM         `yaml:"llm"         json:"llm"`
	Detection   Detection   `yaml:"detection,omitempty" json:"detection,omitempty"`
	Extensions  Extensions  `yaml:"extensions,omitempty" json:"extensions,omitempty"`
	Webhook     Webhook     `yaml:"webhook,omitempty"    json:"webhook,omitempty"`
	Correlation Correlation `yaml:"correlation,omitempty" json:"correlation,omitempty"`
	Sensors     []Sensor    `yaml:"sensors"    json:"sensors"`

	// SourcePath records where this config was loaded from; never decoded from YAML.
	SourcePath string `yaml:"-" json:"-"`
}

// Extensions configures optional out-of-process observer extensions. They run
// as digest-verified (optionally ed25519-signed) subprocesses and receive
// observation envelopes data-only: their replies are acks/errors and can
// never influence decoy behavior, evidence, or policy.
type Extensions struct {
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// Manifests lists paths to extension manifest files (ext.aegismesh.io/v1alpha1).
	Manifests []string `yaml:"manifests,omitempty" json:"manifests,omitempty"`
	// QueueSize bounds the per-extension delivery queue. Full queues drop
	// (counted), never block sensors.
	QueueSize int `yaml:"queue_size,omitempty" json:"queue_size,omitempty"`
	// ShutdownFlushSeconds bounds how long shutdown waits for queued
	// observations to be delivered before extensions are stopped.
	ShutdownFlushSeconds int `yaml:"shutdown_flush_seconds,omitempty" json:"shutdown_flush_seconds,omitempty"`
	// Ed25519PubKeyHex optionally requires every manifest to carry a valid
	// signature by this key. Empty means digest-only verification.
	Ed25519PubKeyHex string `yaml:"ed25519_pubkey_hex,omitempty" json:"ed25519_pubkey_hex,omitempty"`
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

// Security carries the explicit opt-ins that relax safe defaults. All default
// to false; each must be set deliberately by an operator.
type Security struct {
	AllowPublicBind      bool `yaml:"allow_public_bind"       json:"allow_public_bind"`
	AllowPrivilegedPorts bool `yaml:"allow_privileged_ports"  json:"allow_privileged_ports"`

	// AllowPrivateLLMEgress permits LLM provider endpoints on RFC1918/ULA
	// addresses (corporate gateways). Cloud-metadata and link-local targets
	// remain denied unconditionally regardless of this flag.
	AllowPrivateLLMEgress bool `yaml:"allow_private_llm_egress,omitempty" json:"allow_private_llm_egress,omitempty"`
}

// LLM selects the response provider backend.
//
// Secrets never live in the config file. API credentials are referenced
// indirectly: api_key_env names an environment variable, api_key_file names a
// file relative to the config directory. The resolved secret is held only in
// memory, is excluded from JSON serialization, and is never logged. The
// legacy AEGISMESH_LLM_API_KEY environment override still works and takes
// precedence over both references (documented precedence: env > file > none).
type LLM struct {
	// Provider selects the backend: "" | "local" | "ollama" | "openai".
	// "openai" means any OpenAI-compatible chat-completions endpoint; Ollama
	// exposes one at http://127.0.0.1:11434/v1.
	Provider string `yaml:"provider"             json:"provider"`
	BaseURL  string `yaml:"base_url,omitempty"   json:"base_url,omitempty"`
	Model    string `yaml:"model,omitempty"      json:"model,omitempty"`

	APIKey     string `yaml:"-"                     json:"-"`
	APIKeyEnv  string `yaml:"api_key_env,omitempty"  json:"api_key_env,omitempty"`
	APIKeyFile string `yaml:"api_key_file,omitempty" json:"api_key_file,omitempty"`

	// Transport bounds. TimeoutSeconds covers one Complete call end to end.
	TimeoutSeconds   int   `yaml:"timeout_seconds,omitempty"     json:"timeout_seconds,omitempty"`
	MaxResponseBytes int64 `yaml:"max_response_bytes,omitempty"  json:"max_response_bytes,omitempty"`
}

// Detection configures the prompt-injection / abuse detection engine applied
// to inbound interactions before evidence emission.
type Detection struct {
	// Enabled defaults to true; set false explicitly to run pure decoys with
	// no analysis. Actions then degrade to observe for every interaction.
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled"`

	// MaxInputBytes bounds how much of any single interaction the engine will
	// evaluate; content beyond this is counted as RES-001 excessive input.
	MaxInputBytes int `yaml:"max_input_bytes,omitempty" json:"max_input_bytes,omitempty"`

	// DisabledRules excludes rules by stable ID. Unknown IDs fail validation
	// so typos cannot silently disable nothing.
	DisabledRules []string `yaml:"disabled_rules,omitempty" json:"disabled_rules,omitempty"`

	// Actions maps detection severity to the enforcement action applied when
	// that severity fires (highest severity wins). Values:
	// observe|tag|throttle|isolate|refuse.
	Actions DetectionActions `yaml:"actions,omitempty" json:"actions,omitempty"`

	// ThrottlePerMinute caps how many interactions per minute PER SENSOR may
	// carry a detection signal (any finding) before further signaled ones get
	// the throttle action until the minute window resets. Benign traffic does
	// not count. Default 600; set 1..100000.
	ThrottlePerMinute int `yaml:"throttle_per_minute,omitempty" json:"throttle_per_minute,omitempty"`
}

// DetectionActions maps severities to actions. Defaults (safe by design —
// decoy availability first, escalation is an operator decision):
// info=observe low=tag medium=isolate high=refuse.
type DetectionActions struct {
	Info   string `yaml:"info"   json:"info"`
	Low    string `yaml:"low"    json:"low"`
	Medium string `yaml:"medium" json:"medium"`
	High   string `yaml:"high"   json:"high"`
}

func (d Detection) IsEnabled() bool { return d.Enabled == nil || *d.Enabled }

// IsEnabled reports whether observer extensions are configured on.
func (e Extensions) IsEnabled() bool { return e.Enabled != nil && *e.Enabled }

// Webhook configures an optional outbound evidence stream. The evidence
// store remains authoritative; the webhook is a best-effort, bounded,
// HMAC-signed delivery to an SSRF-validated destination (see internal/egress).
type Webhook struct {
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// URL is the collector endpoint. Validated against the egress policy at
	// load time: https beyond loopback, cloud metadata permanently denied,
	// private ranges only via security.allow_private_llm_egress.
	URL string `yaml:"url,omitempty" json:"url,omitempty"`
	// HMAC secret via reference (env var NAME or config-relative file path),
	// never an inline value. Exactly one may be set.
	HMACSecretEnv  string `yaml:"hmac_secret_env,omitempty" json:"hmac_secret_env,omitempty"`
	HMACSecretFile string `yaml:"hmac_secret_file,omitempty" json:"hmac_secret_file,omitempty"`
	// QueueSize bounds pending events; full queue drops (counted).
	QueueSize int `yaml:"queue_size,omitempty" json:"queue_size,omitempty"`
	// BatchSize bounds events per POST body.
	BatchSize int `yaml:"batch_size,omitempty" json:"batch_size,omitempty"`
	// FlushIntervalSeconds sends partial batches after this idle period.
	FlushIntervalSeconds int `yaml:"flush_interval_seconds,omitempty" json:"flush_interval_seconds,omitempty"`
	// TimeoutSeconds bounds each HTTP attempt.
	TimeoutSeconds int `yaml:"timeout_seconds,omitempty" json:"timeout_seconds,omitempty"`
	// MaxRetries caps retry attempts per batch (exponential backoff + jitter).
	MaxRetries int `yaml:"max_retries,omitempty" json:"max_retries,omitempty"`
	// AllowLoopbackHTTP opts into cleartext http for loopback collectors
	// (local development only). Metadata stays denied regardless.
	AllowLoopbackHTTP bool `yaml:"allow_loopback_http,omitempty" json:"allow_loopback_http,omitempty"`
}

// IsEnabled reports whether the webhook sink is configured on.
func (w Webhook) IsEnabled() bool { return w.Enabled != nil && *w.Enabled }

// Correlation configures the bounded in-memory correlation engine that turns
// per-source observation streams into signals (COR-001..COR-004). Zero values
// mean defaults; bounds mirror internal/correlate.Options clamps. Signals are
// observations for operators, never automated enforcement inputs.
type Correlation struct {
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// DisabledRules lists rule ids (e.g. COR-004) to suppress; unknown ids
	// are rejected at load time so typos never silently disable nothing.
	DisabledRules []string `yaml:"disabled_rules,omitempty" json:"disabled_rules,omitempty"`
	// WindowSeconds is the event-time lookback per source.
	WindowSeconds int `yaml:"window_seconds,omitempty" json:"window_seconds,omitempty"`
	// PerSourceEvents caps each source's ring buffer.
	PerSourceEvents int `yaml:"per_source_events,omitempty" json:"per_source_events,omitempty"`
	// MaxSources caps tracked sources (oldest-first eviction).
	MaxSources int `yaml:"max_sources,omitempty" json:"max_sources,omitempty"`
}

// IsEnabled reports whether the correlation engine is configured on.
func (c Correlation) IsEnabled() bool { return c.Enabled != nil && *c.Enabled }

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
	MCPPath      string        `yaml:"path,omitempty"            json:"path,omitempty"`
	ServerName   string        `yaml:"server_name,omitempty"     json:"server_name,omitempty"`
	ServerVer    string        `yaml:"server_version,omitempty"  json:"server_version,omitempty"`
	Instructions string        `yaml:"instructions,omitempty"    json:"instructions,omitempty"`
	Tools        []MCPTool     `yaml:"tools,omitempty"           json:"tools,omitempty"`
	Resources    []MCPResource `yaml:"resources,omitempty"       json:"resources,omitempty"`
	Prompts      []MCPPrompt   `yaml:"prompts,omitempty"         json:"prompts,omitempty"`

	// SSH fields.
	SSH *SSHConfig `yaml:"ssh,omitempty" json:"ssh,omitempty"`
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

// SSHConfig contains bounded protocol settings for the synthetic SSH
// authentication sensor. It never contains host-key paths or credentials.
type SSHConfig struct {
	// ServerVersion is the SSH identification string sent by the decoy.
	// It must begin with SSH-2.0- and contain printable ASCII only.
	ServerVersion string `yaml:"server_version" json:"server_version"`
	// HandshakeTimeoutSeconds bounds the protocol handshake.
	HandshakeTimeoutSeconds int `yaml:"handshake_timeout_seconds" json:"handshake_timeout_seconds"`
	// MaxSessionSeconds bounds the lifetime of an authenticated connection.
	MaxSessionSeconds int `yaml:"max_session_seconds" json:"max_session_seconds"`
	// MaxAuthAttempts bounds synthetic authentication attempts per connection.
	MaxAuthAttempts int `yaml:"max_auth_attempts" json:"max_auth_attempts"`

	present sshConfigPresence
}

type sshConfigPresence struct {
	serverVersion    bool
	handshakeTimeout bool
	maxSession       bool
	maxAuthAttempts  bool
}

// UnmarshalYAML records field presence so omitted nested settings can receive
// safe defaults while explicit empty, null, and zero field values reach validation.
func (c *SSHConfig) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("ssh configuration must be a mapping")
	}
	var present sshConfigPresence
	for i := 0; i < len(node.Content); i += 2 {
		switch node.Content[i].Value {
		case "server_version":
			present.serverVersion = true
		case "handshake_timeout_seconds":
			present.handshakeTimeout = true
		case "max_session_seconds":
			present.maxSession = true
		case "max_auth_attempts":
			present.maxAuthAttempts = true
		default:
			return fmt.Errorf("field %s not found in type config.SSHConfig", node.Content[i].Value)
		}
	}
	type plain SSHConfig
	var decoded plain
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	*c = SSHConfig(decoded)
	c.present = present
	return nil
}

// UnmarshalJSON preserves the same omitted-versus-explicit contract as YAML
// while retaining strict rejection of unknown nested fields.
func (c *SSHConfig) UnmarshalJSON(data []byte) error {
	type plain SSHConfig
	var decoded plain
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*c = SSHConfig(decoded)
	c.present = sshConfigPresence{
		serverVersion:    fields["server_version"] != nil,
		handshakeTimeout: fields["handshake_timeout_seconds"] != nil,
		maxSession:       fields["max_session_seconds"] != nil,
		maxAuthAttempts:  fields["max_auth_attempts"] != nil,
	}
	return nil
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

const (
	MaxMCPResources = 32
	MaxMCPPrompts   = 32
)

// MCPResource is a decoy static resource exposed via resources/read. Content
// is config-provided and synthetic; the URI scheme is decorative (e.g.
// decoy://...) and never dereferenced by the runtime.
type MCPResource struct {
	URI         string `yaml:"uri"         json:"uri"`
	Name        string `yaml:"name"        json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	MIMEType    string `yaml:"mime_type,omitempty"   json:"mime_type,omitempty"`
	Text        string `yaml:"text"        json:"text"`
}

// MCPPrompt is a decoy prompt template returned by prompts/get. Arguments are
// declared but always substituted verbatim into canned text — no evaluation,
// no templating language, nothing attacker-supplied is interpreted.
type MCPPrompt struct {
	Name        string         `yaml:"name"          json:"name"`
	Description string         `yaml:"description,omitempty" json:"description,omitempty"`
	Arguments   []MCPPromptArg `yaml:"arguments,omitempty" json:"arguments,omitempty"`
	Messages    []string       `yaml:"messages"      json:"messages"`
}

type MCPPromptArg struct {
	Name        string `yaml:"name"                  json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Required    bool   `yaml:"required,omitempty"    json:"required,omitempty"`
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
