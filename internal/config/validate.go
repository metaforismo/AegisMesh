package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/metaforismo/aegismesh/internal/detect"
)

var (
	slugRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)
	toolNameRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.-]{0,127}$`)
	headerKeyRe = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+\-.^_` + "`" + `|~]{1,128}$`)
	methodRe    = regexp.MustCompile(`^[A-Z]{1,16}$`)
	envNameRe   = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
	uriRe       = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]{1,31}:[^\s]{1,512}$`)

	allowedCommon = map[string]bool{"id": true, "kind": true, "listen": true}
	allowedByKind = map[string]map[string]bool{
		SensorKindHTTP: {"persona": true, "rules": true, "fallback": true, "max_body_bytes": true},
		SensorKindTCP:  {"banner": true, "session": true, "tcp_rules": true},
		SensorKindMCP: {"path": true, "server_name": true, "server_version": true, "instructions": true, "tools": true,
			"resources": true, "prompts": true},
	}
)

// IsEnabled reports whether the admin listener should run. Default: enabled.
func (a Admin) IsEnabled() bool { return a.Enabled == nil || *a.Enabled }

// Validate performs all structural and safety checks. It fails closed with
// errors that name the offending file location conceptually ("sensor[2].id").
func (c *Config) Validate() error {
	if c.APIVersion != APIVersionV1Alpha1 {
		return fmt.Errorf("%w: api_version %q unsupported (want %q)", errConfig, c.APIVersion, APIVersionV1Alpha1)
	}
	if c.Runtime.InstanceName != "" && !slugRe.MatchString(c.Runtime.InstanceName) {
		return fmt.Errorf("%w: runtime.instance_name %q must match %s", errConfig, c.Runtime.InstanceName, slugRe)
	}

	if n := len(c.Sensors); n == 0 {
		return fmt.Errorf("%w: at least one sensor is required", errConfig)
	} else if n > MaxSensors {
		return fmt.Errorf("%w: %d sensors exceeds cap of %d", errConfig, n, MaxSensors)
	}

	seen := map[string]bool{}
	for i := range c.Sensors {
		s := &c.Sensors[i]
		if !slugRe.MatchString(s.ID) {
			return fmt.Errorf("%w: sensors[%d].id %q must match %s", errConfig, i, s.ID, slugRe)
		}
		if seen[s.ID] {
			return fmt.Errorf("%w: sensors[%d].id %q duplicates an earlier sensor id", errConfig, i, s.ID)
		}
		seen[s.ID] = true

		switch s.Kind {
		case SensorKindHTTP, SensorKindTCP, SensorKindMCP:
		default:
			return fmt.Errorf("%w: sensors[%d].kind %q must be one of http|tcp|mcp", errConfig, i, s.Kind)
		}
		if err := c.validateListen(fmt.Sprintf("sensors[%d]", i), s.Listen, s.Kind); err != nil {
			return err
		}
		switch s.Kind {
		case SensorKindHTTP:
			if err := validateHTTPSensor(s); err != nil {
				return fmt.Errorf("%w: http sensor %q: %v", errConfig, s.ID, err)
			}
		case SensorKindTCP:
			if err := validateTCPSensor(s); err != nil {
				return fmt.Errorf("%w: tcp sensor %q: %v", errConfig, s.ID, err)
			}
		case SensorKindMCP:
			if err := validateMCPSensor(s); err != nil {
				return fmt.Errorf("%w: mcp sensor %q: %v", errConfig, s.ID, err)
			}
		}
	}

	if err := c.validateAdmin(); err != nil {
		return err
	}
	switch c.Logging.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("%w: logging.level %q must be debug|info|warn|error", errConfig, c.Logging.Level)
	}
	switch c.Logging.Format {
	case "json", "text":
	default:
		return fmt.Errorf("%w: logging.format %q must be json|text", errConfig, c.Logging.Format)
	}
	switch c.LLM.Provider {
	case "", "local":
	case "ollama":
		// base_url defaults to the standard local endpoint in applyDefaults.
	case "openai":
		if strings.TrimSpace(c.LLM.BaseURL) == "" {
			return fmt.Errorf("%w: llm.base_url is required when llm.provider=openai", errConfig)
		}
	default:
		return fmt.Errorf("%w: llm.provider %q must be local|ollama|openai", errConfig, c.LLM.Provider)
	}
	if err := validateLLM(&c.LLM); err != nil {
		return fmt.Errorf("%w: %v", errConfig, err)
	}
	if err := ValidateDetection(c.Detection); err != nil {
		return fmt.Errorf("%w: %v", errConfig, err)
	}
	if err := ValidateExtensions(c.Extensions); err != nil {
		return fmt.Errorf("%w: %v", errConfig, err)
	}
	if c.Storage.MaxFileBytes < 4096 {
		return fmt.Errorf("%w: storage.max_file_bytes must be >= 4096", errConfig)
	}
	if c.Storage.MaxEventBytes < 1024 {
		return fmt.Errorf("%w: storage.max_event_bytes must be >= 1024", errConfig)
	}
	if c.Storage.Retention.MaxEvents <= 0 || c.Storage.Retention.MaxEvents > 10_000_000 {
		return fmt.Errorf("%w: storage.retention.max_events must be within 1..10000000", errConfig)
	}
	if c.Storage.Retention.MaxAgeDays <= 0 || c.Storage.Retention.MaxAgeDays > 3650 {
		return fmt.Errorf("%w: storage.retention.max_age_days must be within 1..3650", errConfig)
	}
	return nil
}

// validateListen enforces the bind policy: loopback by default; public binds
// and privileged ports each require their global opt-in.
func (c *Config) validateListen(where, addr, kind string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%w: %s.listen %q: expected host:port (%v)", errConfig, where, addr, err)
	}
	port, err := parsePort(portStr)
	if err != nil {
		return fmt.Errorf("%w: %s.listen %q: %v", errConfig, where, addr, err)
	}
	if port != 0 && port < 1024 && !c.Security.AllowPrivilegedPorts {
		return fmt.Errorf("%w: %s.listen %q uses privileged port %d; set security.allow_privileged_ports=true only if you understand the risk", errConfig, where, addr, port)
	}
	public, err := isPublicBind(host)
	if err != nil {
		return fmt.Errorf("%w: %s.listen %q: %v", errConfig, where, addr, err)
	}
	if public && !c.Security.AllowPublicBind {
		return fmt.Errorf("%w: %s.listen %q binds beyond loopback; decoys must never face production networks by accident — set security.allow_public_bind=true to override deliberately", errConfig, where, addr)
	}
	return nil
}

func (c *Config) validateAdmin() error {
	if !c.Admin.IsEnabled() {
		return nil
	}
	host, portStr, err := net.SplitHostPort(c.Admin.Listen)
	if err != nil {
		return fmt.Errorf("%w: admin.listen %q: expected host:port (%v)", errConfig, c.Admin.Listen, err)
	}
	port, err := parsePort(portStr)
	if err != nil {
		return fmt.Errorf("%w: admin.listen %q: %v", errConfig, c.Admin.Listen, err)
	}
	loop, err := isLoopbackHost(host)
	if err != nil {
		return fmt.Errorf("%w: admin.listen %q: %v", errConfig, c.Admin.Listen, err)
	}
	if !loop {
		return fmt.Errorf("%w: admin.listen %q must stay on loopback (health/metrics are internal surface; this is an invariant, not a preference)", errConfig, c.Admin.Listen)
	}
	if port != 0 && port < 1024 && !c.Security.AllowPrivilegedPorts {
		return fmt.Errorf("%w: admin.listen %q uses a privileged port; set security.allow_privileged_ports=true to override", errConfig, c.Admin.Listen)
	}
	return nil
}

// parsePort accepts 1..65535 plus 0, which means "OS assigns an ephemeral
// port" — useful for parallel test runs and for operators who deliberately
// don't care which unprivileged port a decoy uses.
func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(s)
	if err != nil || p < 0 || p > 65535 {
		return 0, fmt.Errorf("port %q out of range 0..65535", s)
	}
	return p, nil
}

func isLoopbackHost(host string) (bool, error) {
	if host == "" || host == "localhost" {
		return true, nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false, nil
	}
	return ip.IsLoopback(), nil
}

// isPublicBind reports whether the address exposes more than loopback.
// Hostnames resolve nothing at config time; any non-loopback literal or
// resolvable-looking name is treated as public and needs opt-in.
func isPublicBind(host string) (bool, error) {
	loop, err := isLoopbackHost(host)
	if err != nil {
		return true, err
	}
	return !loop, nil
}

func validateHTTPSensor(s *Sensor) error {
	if len(s.Rules) == 0 {
		return fmt.Errorf("at least one rules[] entry is required")
	}
	if len(s.Rules) > MaxRulesPerSensor {
		return fmt.Errorf("%d rules exceed cap of %d", len(s.Rules), MaxRulesPerSensor)
	}
	if s.MaxBodyBytes > 4<<20 {
		return fmt.Errorf("max_body_bytes %d exceeds hard cap 4MiB", s.MaxBodyBytes)
	}
	for i := range s.Rules {
		r := &s.Rules[i]
		where := fmt.Sprintf("rules[%d]", i)
		if r.Name != "" && !slugRe.MatchString(r.Name) {
			return fmt.Errorf("%s.name %q must match %s", where, r.Name, slugRe)
		}
		if len(r.PathRegex) == 0 || len(r.PathRegex) > MaxRegexLen {
			return fmt.Errorf("%s.path_regex must be 1..%d bytes", where, MaxRegexLen)
		}
		if _, err := regexp.Compile(r.PathRegex); err != nil {
			return fmt.Errorf("%s.path_regex does not compile: %v", where, err)
		}
		for _, m := range r.Methods {
			if !methodRe.MatchString(m) {
				return fmt.Errorf("%s.methods entry %q is not a valid HTTP method token", where, m)
			}
		}
		if r.Status < 100 || r.Status > 599 {
			return fmt.Errorf("%s.status %d out of range 100..599", where, r.Status)
		}
		if len(r.Headers) > MaxHeaderCount {
			return fmt.Errorf("%s.headers exceeds %d entries", where, MaxHeaderCount)
		}
		for k, v := range r.Headers {
			if !headerKeyRe.MatchString(k) {
				return fmt.Errorf("%s.headers key %q is not a valid header name", where, k)
			}
			if len(v) > MaxHeaderValueLen {
				return fmt.Errorf("%s.headers[%s] value exceeds %d bytes", where, k, MaxHeaderValueLen)
			}
		}
		if r.BodyFile != "" {
			if r.Body != "" {
				return fmt.Errorf("%s: set either body or body_file, not both", where)
			}
			if err := safeRelative(r.BodyFile); err != nil {
				return fmt.Errorf("%s.body_file: %v", where, err)
			}
		} else if len(r.Body) > MaxHTTPBodyBytes {
			return fmt.Errorf("%s.body is %d bytes; inline bodies cap at %d — use body_file for larger content", where, len(r.Body), MaxHTTPBodyBytes)
		}
	}
	if s.Fallback != nil {
		f := s.Fallback
		if f.SystemPrompt == "" {
			return fmt.Errorf("fallback.system_prompt is required when a fallback block is present")
		}
		if len(f.SystemPrompt) > 4096 {
			return fmt.Errorf("fallback.system_prompt exceeds 4096 bytes")
		}
		if f.MaxReplyChars < 0 || f.MaxReplyChars > 16384 {
			return fmt.Errorf("fallback.max_reply_chars must be within 0..16384")
		}
	}
	return nil
}

func validateTCPSensor(s *Sensor) error {
	if len(s.Banner) > MaxBannerBytes {
		return fmt.Errorf("banner exceeds %d bytes", MaxBannerBytes)
	}
	if len(s.TCPResponseRule) > MaxRulesPerSensor {
		return fmt.Errorf("%d tcp_rules exceed cap of %d", len(s.TCPResponseRule), MaxRulesPerSensor)
	}
	sess := s.Session
	if sess.MaxLineBytes <= 0 || sess.MaxLineBytes > 64<<10 {
		return fmt.Errorf("session.max_line_bytes must be within 1..65536")
	}
	if sess.IdleTimeoutSeconds <= 0 || sess.IdleTimeoutSeconds > 3600 {
		return fmt.Errorf("session.idle_timeout_seconds must be within 1..3600")
	}
	if sess.MaxSessionSeconds <= 0 || sess.MaxSessionSeconds > 86400 {
		return fmt.Errorf("session.max_session_seconds must be within 1..86400")
	}
	for i := range s.TCPResponseRule {
		r := &s.TCPResponseRule[i]
		where := fmt.Sprintf("tcp_rules[%d]", i)
		if r.Name != "" && !slugRe.MatchString(r.Name) {
			return fmt.Errorf("%s.name %q must match %s", where, r.Name, slugRe)
		}
		if len(r.LineRegex) == 0 || len(r.LineRegex) > MaxRegexLen {
			return fmt.Errorf("%s.line_regex must be 1..%d bytes", where, MaxRegexLen)
		}
		if _, err := regexp.Compile(r.LineRegex); err != nil {
			return fmt.Errorf("%s.line_regex does not compile: %v", where, err)
		}
		if len(r.Response) > MaxTCPResponseBytes {
			return fmt.Errorf("%s.response exceeds %d bytes", where, MaxTCPResponseBytes)
		}
	}
	return nil
}

// validateLLM enforces the secret-reference and transport-bound rules.
// Secrets are never present in the file itself; only references are.
func validateLLM(l *LLM) error {
	if l.APIKeyEnv != "" && !envNameRe.MatchString(l.APIKeyEnv) {
		return fmt.Errorf("llm.api_key_env %q must be an environment variable NAME (A-Z, digits, underscore)", l.APIKeyEnv)
	}
	if l.APIKeyEnv != "" && l.APIKeyFile != "" {
		return fmt.Errorf("set either llm.api_key_env or llm.api_key_file, not both")
	}
	if l.APIKeyFile != "" {
		if err := safeRelative(l.APIKeyFile); err != nil {
			return fmt.Errorf("llm.api_key_file: %v", err)
		}
	}
	switch l.Provider {
	case "ollama", "openai":
		if strings.TrimSpace(l.Model) == "" {
			return fmt.Errorf("llm.model is required when llm.provider=%s", l.Provider)
		}
		if len(l.Model) > 128 {
			return fmt.Errorf("llm.model exceeds 128 bytes")
		}
		if strings.TrimSpace(l.BaseURL) == "" {
			return fmt.Errorf("llm.base_url is required when llm.provider=%s", l.Provider)
		}
	}
	if l.TimeoutSeconds < 0 || l.TimeoutSeconds > MaxLLMTimeoutSeconds {
		return fmt.Errorf("llm.timeout_seconds must be within 0..%d (0 = default %ds)", MaxLLMTimeoutSeconds, DefaultLLMTimeoutSeconds)
	}
	if l.MaxResponseBytes < 0 || l.MaxResponseBytes > MaxLLMResponseBytes {
		return fmt.Errorf("llm.max_response_bytes must be within 0..%d (0 = default %d)", MaxLLMResponseBytes, DefaultLLMResponseBytes)
	}
	return nil
}

// ValidActions lists the enforcement actions a severity may map to.
var ValidActions = []string{"observe", "tag", "throttle", "isolate", "refuse"}

// ValidateDetection checks the detection section against the engine's rule
// registry. It lives behind narrow functions so config never depends on
// engine internals.
func ValidateDetection(d Detection) error {
	if d.MaxInputBytes < 0 || d.MaxInputBytes > MaxDetectInputBytes {
		return fmt.Errorf("detection.max_input_bytes must be within 0..%d (0 = default %d)", MaxDetectInputBytes, DefaultDetectionMaxLen)
	}
	if err := detect.ValidateRuleIDs(d.DisabledRules); err != nil {
		return err
	}
	valid := map[string]bool{}
	for _, a := range ValidActions {
		valid[a] = true
	}
	for sev, act := range map[string]string{
		"info": d.Actions.Info, "low": d.Actions.Low,
		"medium": d.Actions.Medium, "high": d.Actions.High,
	} {
		if !valid[act] {
			return fmt.Errorf("detection.actions.%s %q must be one of %s", sev, act, strings.Join(ValidActions, "|"))
		}
	}
	if d.ThrottlePerMinute < 0 || d.ThrottlePerMinute > 100000 {
		return fmt.Errorf("detection.throttle_per_minute must be within 0..100000 (0 = default)")
	}
	return nil
}

// ValidateExtensions enforces the observer-extension bounds. Manifest file
// existence and verification happen at Build time (fail-closed), not here.
func ValidateExtensions(e Extensions) error {
	if !e.IsEnabled() {
		return nil // disabled sections may hold nothing at all
	}
	if len(e.Manifests) == 0 {
		return fmt.Errorf("extensions.enabled=true requires at least one extensions.manifests entry")
	}
	if len(e.Manifests) > MaxExtensions {
		return fmt.Errorf("at most %d extensions are supported, got %d", MaxExtensions, len(e.Manifests))
	}
	seen := map[string]bool{}
	for _, m := range e.Manifests {
		if strings.TrimSpace(m) == "" {
			return fmt.Errorf("extensions.manifests entries must be non-empty")
		}
		if seen[m] {
			return fmt.Errorf("extensions.manifests entry %q is duplicated", m)
		}
		seen[m] = true
	}
	if e.QueueSize != 0 && (e.QueueSize < MinExtensionQueueSize || e.QueueSize > MaxExtensionQueueSize) {
		return fmt.Errorf("extensions.queue_size must be within %d..%d (0 = default %d)",
			MinExtensionQueueSize, MaxExtensionQueueSize, DefaultExtensionQueueSize)
	}
	if e.ShutdownFlushSeconds != 0 && (e.ShutdownFlushSeconds < MinExtensionFlushSecs || e.ShutdownFlushSeconds > MaxExtensionFlushSecs) {
		return fmt.Errorf("extensions.shutdown_flush_seconds must be within %d..%d (0 = default %d)",
			MinExtensionFlushSecs, MaxExtensionFlushSecs, DefaultExtensionFlushSecs)
	}
	if e.Ed25519PubKeyHex != "" {
		key, err := hex.DecodeString(e.Ed25519PubKeyHex)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return fmt.Errorf("extensions.ed25519_pubkey_hex must be %d-byte hex ed25519 public key", ed25519.PublicKeySize)
		}
	}
	return nil
}

func validateMCPSensor(s *Sensor) error {
	if !strings.HasPrefix(s.MCPPath, "/") || strings.ContainsAny(s.MCPPath, "?#") {
		return fmt.Errorf("path %q must start with '/' and contain no query or fragment", s.MCPPath)
	}
	if len(s.Instructions) > 4096 {
		return fmt.Errorf("instructions exceeds 4096 bytes")
	}
	if n := len(s.Tools); n == 0 {
		return fmt.Errorf("at least one canary tool is required (an MCP endpoint without tools serves no deception purpose)")
	} else if n > MaxMCPTools {
		return fmt.Errorf("%d tools exceed cap of %d", n, MaxMCPTools)
	}
	if len(s.Resources) > MaxMCPResources {
		return fmt.Errorf("%d resources exceed cap of %d", len(s.Resources), MaxMCPResources)
	}
	if err := validateMCPResources(s.Resources); err != nil {
		return err
	}
	if len(s.Prompts) > MaxMCPPrompts {
		return fmt.Errorf("%d prompts exceed cap of %d", len(s.Prompts), MaxMCPPrompts)
	}
	if err := validateMCPPrompts(s.Prompts); err != nil {
		return err
	}
	names := map[string]bool{}
	for i := range s.Tools {
		t := &s.Tools[i]
		where := fmt.Sprintf("tools[%d]", i)
		if !toolNameRe.MatchString(t.Name) {
			return fmt.Errorf("%s.name %q is not a valid MCP tool name", where, t.Name)
		}
		if names[t.Name] {
			return fmt.Errorf("%s.name %q duplicates an earlier tool name", where, t.Name)
		}
		names[t.Name] = true
		if len(t.Description) == 0 || len(t.Description) > 2048 {
			return fmt.Errorf("%s.description must be 1..2048 bytes", where)
		}
		result := []byte(t.ResultJSON)
		if !json.Valid(result) {
			return fmt.Errorf("%s.result_json is not valid JSON", where)
		}
		if len(result) > MaxMCPResultBytes {
			return fmt.Errorf("%s.result_json exceeds %d bytes", where, MaxMCPResultBytes)
		}
		var schema any
		if len(t.InputSchema) > 0 {
			if !json.Valid(t.InputSchema) {
				return fmt.Errorf("%s.input_schema is not valid JSON", where)
			}
			if err := json.Unmarshal(t.InputSchema, &schema); err != nil || !isObject(schema) {
				return fmt.Errorf("%s.input_schema must be a JSON object", where)
			}
			if len(t.InputSchema) > MaxMCPSchemaBytes {
				return fmt.Errorf("%s.input_schema exceeds %d bytes", where, MaxMCPSchemaBytes)
			}
		}
	}
	return nil
}

// CheckKindFields rejects config fields that do not apply to the sensor's
// kind, so a typo like putting `banner` on an HTTP sensor fails loudly.
// It works on the raw document because Go decoding cannot see what was absent.
func CheckKindFields(raw []byte, ext string) error {
	type envelope struct {
		Sensors []map[string]any `yaml:"sensors" json:"sensors"`
	}
	var e envelope
	var err error
	if strings.EqualFold(ext, ".json") {
		err = json.Unmarshal(raw, &e)
	} else {
		err = yamlUnmarshalLenient(raw, &e)
	}
	if err != nil {
		// Strict decoding already reported structural problems.
		return nil
	}
	for i, m := range e.Sensors {
		kind, _ := m["kind"].(string)
		allowed := allowedByKind[kind]
		if allowed == nil {
			continue // kind validity handled by Validate
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sortStrings(keys)
		for _, k := range keys {
			if !allowedCommon[k] && !allowed[k] {
				return fmt.Errorf("%w: sensors[%d]: field %q does not apply to kind=%q", errConfig, i, k, kind)
			}
		}
	}
	return nil
}

func safeRelative(p string) error {
	if filepath.IsAbs(p) {
		return fmt.Errorf("must be relative to the config file directory")
	}
	clean := filepath.Clean(p)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("must not traverse outside the config directory")
	}
	return nil
}

// ResolveBodyFile resolves a rule body_file relative to the config directory,
// enforcing containment, and returns its contents.
func (c *Config) ResolveBodyFile(rel string) ([]byte, error) {
	base := filepath.Dir(c.SourcePath)
	full := filepath.Join(base, filepath.Clean(rel))
	absBase, err := filepath.Abs(base)
	if err != nil {
		return nil, err
	}
	absFull, err := filepath.Abs(full)
	if err != nil {
		return nil, err
	}
	if absFull != absBase && !strings.HasPrefix(absFull, absBase+string(filepath.Separator)) {
		return nil, fmt.Errorf("body_file %q resolves outside the config directory", rel)
	}
	b, err := os.ReadFile(absFull) //nolint:gosec // containment verified above
	if err != nil {
		return nil, err
	}
	if len(b) > MaxHTTPBodyBytes {
		return nil, fmt.Errorf("body_file %q is %d bytes; cap is %d", rel, len(b), MaxHTTPBodyBytes)
	}
	return b, nil
}

// validateMCPResources checks decoy resource definitions. URIs are decorative
// labels returned verbatim to clients; they are never dereferenced, but they
// must still be well-formed so agent clients do not choke on garbage.
func validateMCPResources(resources []MCPResource) error {
	seen := map[string]bool{}
	for i := range resources {
		r := &resources[i]
		where := fmt.Sprintf("resources[%d]", i)
		if !uriRe.MatchString(r.URI) || len(r.URI) > 512 {
			return fmt.Errorf("%s.uri %q is not a valid absolute URI", where, r.URI)
		}
		if seen[r.URI] {
			return fmt.Errorf("%s.uri %q duplicates an earlier resource URI", where, r.URI)
		}
		seen[r.URI] = true
		if len(r.Name) == 0 || len(r.Name) > 256 {
			return fmt.Errorf("%s.name must be 1..256 bytes", where)
		}
		if len(r.Description) > 2048 {
			return fmt.Errorf("%s.description exceeds 2048 bytes", where)
		}
		if r.MIMEType != "" && (len(r.MIMEType) > 128 || strings.ContainsAny(r.MIMEType, " ;,\r\n")) {
			return fmt.Errorf("%s.mime_type %q is not a bare media type", where, r.MIMEType)
		}
		if len(r.Text) == 0 || len(r.Text) > MaxMCPResultBytes {
			return fmt.Errorf("%s.text must be 1..%d bytes", where, MaxMCPResultBytes)
		}
	}
	return nil
}

// validateMCPPrompts checks decoy prompt templates. Messages are canned text;
// argument names are substituted verbatim at read time with no templating
// language beyond exact-name replacement.
func validateMCPPrompts(prompts []MCPPrompt) error {
	seen := map[string]bool{}
	for i := range prompts {
		p := &prompts[i]
		where := fmt.Sprintf("prompts[%d]", i)
		if !toolNameRe.MatchString(p.Name) {
			return fmt.Errorf("%s.name %q is not a valid MCP prompt name", where, p.Name)
		}
		if seen[p.Name] {
			return fmt.Errorf("%s.name %q duplicates an earlier prompt name", where, p.Name)
		}
		seen[p.Name] = true
		if len(p.Description) > 2048 {
			return fmt.Errorf("%s.description exceeds 2048 bytes", where)
		}
		if len(p.Arguments) > 16 {
			return fmt.Errorf("%s.arguments exceed cap of 16", where)
		}
		argNames := map[string]bool{}
		total := 0
		for j := range p.Messages {
			m := p.Messages[j]
			total += len(m)
			if len(m) == 0 {
				return fmt.Errorf("%s.messages[%d] is empty", where, j)
			}
			if len(m) > MaxMCPResultBytes {
				return fmt.Errorf("%s.messages[%d] exceeds %d bytes", where, j, MaxMCPResultBytes)
			}
		}
		if total > MaxMCPResultBytes {
			return fmt.Errorf("%s.messages total %d bytes exceeds %d", where, total, MaxMCPResultBytes)
		}
		if n := len(p.Messages); n == 0 || n > 8 {
			return fmt.Errorf("%s.messages must contain 1..8 entries, has %d", where, n)
		}
		for j := range p.Arguments {
			a := &p.Arguments[j]
			aw := fmt.Sprintf("%s.arguments[%d]", where, j)
			if !toolNameRe.MatchString(a.Name) {
				return fmt.Errorf("%s.name %q is not a valid argument name", aw, a.Name)
			}
			if argNames[a.Name] {
				return fmt.Errorf("%s.name duplicates an earlier argument", aw)
			}
			argNames[a.Name] = true
			if len(a.Description) > 512 {
				return fmt.Errorf("%s.description exceeds 512 bytes", aw)
			}
		}
	}
	return nil
}

func isObject(v any) bool {
	_, ok := v.(map[string]any)
	return ok
}

func sortStrings(s []string) { sort.Strings(s) }
