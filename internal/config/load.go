package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var errConfig = errors.New("config")

// Load reads, strictly decodes, applies defaults and environment overrides,
// then validates the configuration at path.
func Load(path string) (*Config, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: no config path given (run `aegismesh init` or pass --config)", errConfig)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // path is an explicit operator flag
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %v", errConfig, path, err)
	}
	var c Config
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		err = strictJSON(raw, &c)
	default: // .yaml, .yml, anything else: YAML is a superset of JSON
		err = strictYAML(raw, &c)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", errConfig, filepath.Base(path), err)
	}
	c.SourcePath = path
	if err := CheckKindFields(raw, strings.ToLower(filepath.Ext(path))); err != nil {
		return nil, err
	}
	c.applyDefaults()
	if err := c.applyEnvOverrides(); err != nil {
		return nil, fmt.Errorf("%w: environment override: %v", errConfig, err)
	}
	// Relative data_dir resolves against the config file's directory, never
	// the process CWD, so `aegismesh run --config somewhere/mesh.yaml` behaves
	// identically from any working directory.
	if !filepath.IsAbs(c.Runtime.DataDir) {
		base := filepath.Dir(absClean(path))
		c.Runtime.DataDir = filepath.Join(base, c.Runtime.DataDir)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func absClean(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}

func strictYAML(b []byte, v any) error {
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		return translateDecodeError(err)
	}
	return nil
}

func strictJSON(b []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return translateDecodeError(err)
	}
	return nil
}

// yamlUnmarshalLenient is used only for best-effort presence checks
// (CheckKindFields); strict decoding owns real error reporting.
func yamlUnmarshalLenient(b []byte, v any) error {
	return yaml.Unmarshal(b, v)
}

// translateDecodeError turns decoder errors into operator-actionable messages.
func translateDecodeError(err error) error {
	msg := err.Error()
	var te *yaml.TypeError
	if errors.As(err, &te) {
		out := make([]string, 0, len(te.Errors))
		for _, e := range te.Errors {
			e = strings.TrimPrefix(e, "yaml: unmarshal errors:")
			e = strings.TrimSpace(e)
			if strings.Contains(e, "not found in type") {
				e += " — unknown field; check spelling against schema " + APIVersionV1Alpha1
			}
			out = append(out, e)
		}
		return fmt.Errorf("schema mismatch: %s", strings.Join(out, "; "))
	}
	if strings.Contains(msg, "unknown field") {
		return fmt.Errorf("unknown field; check spelling against schema %s: %v", APIVersionV1Alpha1, err)
	}
	return err
}

func (c *Config) applyDefaults() {
	if c.Runtime.DataDir == "" {
		c.Runtime.DataDir = defaultDataDir
	}
	if c.Runtime.InstanceName == "" {
		c.Runtime.InstanceName = "default"
	}
	if c.Storage.MaxFileBytes == 0 {
		c.Storage.MaxFileBytes = defaultMaxFileBytes
	}
	if c.Storage.MaxEventBytes == 0 {
		c.Storage.MaxEventBytes = defaultMaxEventBytes
	}
	if c.Storage.Retention.MaxEvents == 0 {
		c.Storage.Retention.MaxEvents = defaultMaxEvents
	}
	if c.Storage.Retention.MaxAgeDays == 0 {
		c.Storage.Retention.MaxAgeDays = defaultMaxAgeDays
	}
	if c.Admin.Listen == "" {
		c.Admin.Listen = defaultAdminListen
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}
	if c.LLM.Provider == "" {
		c.LLM.Provider = "local"
	}
	for i := range c.Sensors {
		s := &c.Sensors[i]
		switch s.Kind {
		case SensorKindHTTP:
			if s.MaxBodyBytes == 0 {
				s.MaxBodyBytes = defaultMaxBodyBytes
			}
			if s.Persona == nil {
				s.Persona = &HTTPPersona{ServerHeader: "AegisMesh"}
			}
			if s.Fallback != nil && s.Fallback.Enabled && s.Fallback.MaxReplyChars == 0 {
				s.Fallback.MaxReplyChars = 2048
			}
		case SensorKindTCP:
			if s.Session == nil {
				s.Session = &TCPSession{}
			}
			if s.Session.MaxLineBytes == 0 {
				s.Session.MaxLineBytes = defaultLineBytes
			}
			if s.Session.IdleTimeoutSeconds == 0 {
				s.Session.IdleTimeoutSeconds = defaultIdleTimeoutS
			}
			if s.Session.MaxSessionSeconds == 0 {
				s.Session.MaxSessionSeconds = defaultSessionTimeoutS
			}
		case SensorKindMCP:
			if s.MCPPath == "" {
				s.MCPPath = "/mcp"
			}
			if s.ServerName == "" {
				s.ServerName = "aegismesh-canary"
			}
			if s.ServerVer == "" {
				s.ServerVer = "1.0.0"
			}
		}
	}
}

// applyEnvOverrides implements the documented AEGISMESH_* override set.
// Only a deliberately small surface is overridable; everything else must be
// edited in the file so configs stay reviewable.
func (c *Config) applyEnvOverrides() error {
	setString := func(dst *string, key string) error {
		if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
			*dst = strings.TrimSpace(v)
		}
		return nil
	}
	if err := setString(&c.Runtime.DataDir, "AEGISMESH_DATA_DIR"); err != nil {
		return err
	}
	if err := setString(&c.Admin.Listen, "AEGISMESH_ADMIN_LISTEN"); err != nil {
		return err
	}
	if v, ok := os.LookupEnv("AEGISMESH_ADMIN_ENABLED"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("AEGISMESH_ADMIN_ENABLED=%q is not a boolean", v)
		}
		c.Admin.Enabled = &b
	}
	if err := setString(&c.Logging.Level, "AEGISMESH_LOG_LEVEL"); err != nil {
		return err
	}
	if err := setString(&c.LLM.APIKey, "AEGISMESH_LLM_API_KEY"); err != nil {
		return err
	}
	if err := setString(&c.LLM.BaseURL, "AEGISMESH_LLM_BASE_URL"); err != nil {
		return err
	}
	return nil
}
