package config

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/metaforismo/aegismesh/internal/egress"
	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
)

// Fleet configures the separate optional inventory hub and outbound reporting agent.
type Fleet struct {
	// Hub configures the dedicated inbound machine API.
	Hub FleetHub `yaml:"hub" json:"hub"`
	// Agent configures signed outbound status and separately consented evidence reporting.
	Agent FleetAgent `yaml:"agent" json:"agent"`
}

// FleetHub never dials agents and provides no remote control capability.
type FleetHub struct {
	// AcceptEvidence explicitly opts into receiving redacted node evidence.
	AcceptEvidence EvidenceConsent `yaml:"accept_evidence" json:"accept_evidence"`
	// Enabled opts into inventory enrollment and heartbeat reception.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Listen defaults to the dedicated loopback authority 127.0.0.1:9130.
	Listen string `yaml:"listen" json:"listen"`
	// StateDir holds private atomic registry, token and replay state.
	StateDir string `yaml:"state_dir" json:"state_dir"`
	// TLSCertFile selects an operator-controlled PEM certificate.
	TLSCertFile string `yaml:"tls_cert_file" json:"tls_cert_file"`
	// TLSKeyFile selects the corresponding private PEM key.
	TLSKeyFile string `yaml:"tls_key_file" json:"tls_key_file"`
}

// FleetAgent holds references, never an inline enrollment credential.
type FleetAgent struct {
	// ForwardEvidence explicitly consents to disclosure of redacted evidence to the hub.
	ForwardEvidence EvidenceConsent `yaml:"forward_evidence" json:"forward_evidence"`
	// Enabled opts into bounded outbound inventory reporting.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// HubURL is an origin-only http(s) URL checked by shared egress classification.
	HubURL string `yaml:"hub_url" json:"hub_url"`
	// StateDir holds the local owner-only identity seed.
	StateDir string `yaml:"state_dir" json:"state_dir"`
	// NodeName is the proposed immutable slug; empty uses runtime.instance_name.
	NodeName string `yaml:"node_name" json:"node_name"`
	// EnrollmentTokenFile is a private config-relative credential reference.
	EnrollmentTokenFile string `yaml:"enrollment_token_file" json:"enrollment_token_file"`
	// EnrollmentTokenEnv names an environment variable containing the token.
	EnrollmentTokenEnv string `yaml:"enrollment_token_env" json:"enrollment_token_env"`
	// HubCAFile optionally augments system roots with a bounded PEM trust bundle.
	HubCAFile string `yaml:"hub_ca_file" json:"hub_ca_file"`
	// AllowPrivateEgress explicitly permits RFC1918/ULA hubs; metadata stays denied.
	AllowPrivateEgress bool `yaml:"allow_private_egress" json:"allow_private_egress"`
	// HeartbeatIntervalSeconds defaults to 30 and must be within 10..300.
	HeartbeatIntervalSeconds int `yaml:"heartbeat_interval_seconds" json:"heartbeat_interval_seconds"`
}

// EvidenceConsent is an off-by-default evidence confidentiality boundary.
type EvidenceConsent struct {
	// Enabled explicitly opts into experimental best-effort forwarding with counted loss.
	Enabled bool `yaml:"enabled" json:"enabled"`
}

func (c *Config) fleetDefaults() {
	if c.Fleet.Hub.Listen == "" {
		c.Fleet.Hub.Listen = "127.0.0.1:9130"
	}
	if c.Fleet.Agent.HeartbeatIntervalSeconds == 0 {
		c.Fleet.Agent.HeartbeatIntervalSeconds = 30
	}
}

func (c *Config) fleetEnv() error {
	stringsByName := map[string]*string{
		"HUB_LISTEN":                  &c.Fleet.Hub.Listen,
		"HUB_STATE_DIR":               &c.Fleet.Hub.StateDir,
		"HUB_TLS_CERT_FILE":           &c.Fleet.Hub.TLSCertFile,
		"HUB_TLS_KEY_FILE":            &c.Fleet.Hub.TLSKeyFile,
		"AGENT_HUB_URL":               &c.Fleet.Agent.HubURL,
		"AGENT_STATE_DIR":             &c.Fleet.Agent.StateDir,
		"AGENT_NODE_NAME":             &c.Fleet.Agent.NodeName,
		"AGENT_ENROLLMENT_TOKEN_FILE": &c.Fleet.Agent.EnrollmentTokenFile,
		"AGENT_ENROLLMENT_TOKEN_ENV":  &c.Fleet.Agent.EnrollmentTokenEnv,
		"AGENT_HUB_CA_FILE":           &c.Fleet.Agent.HubCAFile,
	}
	for name, target := range stringsByName {
		if value, exists := os.LookupEnv("AEGISMESH_FLEET_" + name); exists {
			*target = value
		}
	}
	boolsByName := map[string]*bool{
		"HUB_ACCEPT_EVIDENCE_ENABLED":    &c.Fleet.Hub.AcceptEvidence.Enabled,
		"AGENT_FORWARD_EVIDENCE_ENABLED": &c.Fleet.Agent.ForwardEvidence.Enabled,
		"HUB_ENABLED":                    &c.Fleet.Hub.Enabled,
		"AGENT_ENABLED":                  &c.Fleet.Agent.Enabled,
		"AGENT_ALLOW_PRIVATE_EGRESS":     &c.Fleet.Agent.AllowPrivateEgress,
	}
	for name, target := range boolsByName {
		if value, exists := os.LookupEnv("AEGISMESH_FLEET_" + name); exists {
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return fmt.Errorf("fleet %s must be a boolean", name)
			}
			*target = parsed
		}
	}
	if value, exists := os.LookupEnv("AEGISMESH_FLEET_AGENT_HEARTBEAT_INTERVAL_SECONDS"); exists {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("fleet heartbeat interval must be an integer")
		}
		c.Fleet.Agent.HeartbeatIntervalSeconds = parsed
	}
	return nil
}

// FleetStateDir resolves trusted state roots independently for each role.
func (c *Config) FleetStateDir(agent bool) string {
	configured := c.Fleet.Hub.StateDir
	suffix := "fleet-hub"
	if agent {
		configured = c.Fleet.Agent.StateDir
		suffix = "fleet-agent"
	}
	if configured == "" {
		return filepath.Join(c.Runtime.DataDir, suffix)
	}
	if filepath.IsAbs(configured) {
		return configured
	}
	return filepath.Join(filepath.Dir(absClean(c.SourcePath)), configured)
}

// FleetNodeName returns the configured identity name or the local instance name.
func (c *Config) FleetNodeName() string {
	if c.Fleet.Agent.NodeName != "" {
		return c.Fleet.Agent.NodeName
	}
	return c.Runtime.InstanceName
}

// ValidateFleet rejects unsafe exposure and outbound policy before listener construction.
func (c *Config) ValidateFleet() error {
	hubConfig := c.Fleet.Hub
	agentConfig := c.Fleet.Agent
	fail := func(message string) error {
		return fmt.Errorf("%w: fleet: %s", errConfig, message)
	}
	if hubConfig.AcceptEvidence.Enabled && !hubConfig.Enabled {
		return fail("hub.accept_evidence.enabled requires hub.enabled")
	}
	if agentConfig.ForwardEvidence.Enabled && !agentConfig.Enabled {
		return fail("agent.forward_evidence.enabled requires agent.enabled")
	}
	if hubConfig.Enabled && agentConfig.Enabled {
		return fail("hub and agent roles cannot both be enabled in an operator config; compose tests in process")
	}
	if agentConfig.HeartbeatIntervalSeconds < 10 || agentConfig.HeartbeatIntervalSeconds > 300 {
		return fail("agent.heartbeat_interval_seconds must be within 10..300")
	}
	if agentConfig.NodeName != "" && !protocol.NameValid(agentConfig.NodeName) {
		return fail("agent.node_name must be a 3..64 character slug")
	}
	if (hubConfig.TLSCertFile == "") != (hubConfig.TLSKeyFile == "") {
		return fail("hub TLS certificate and key must be supplied together")
	}
	if agentConfig.EnrollmentTokenFile != "" && agentConfig.EnrollmentTokenEnv != "" {
		return fail("agent enrollment token references are mutually exclusive")
	}
	if agentConfig.EnrollmentTokenEnv != "" && !envNameRe.MatchString(agentConfig.EnrollmentTokenEnv) {
		return fail("agent.enrollment_token_env must be an environment variable name")
	}
	if agentConfig.EnrollmentTokenFile != "" {
		path := filepath.Clean(agentConfig.EnrollmentTokenFile)
		if filepath.IsAbs(path) || path == ".." || strings.HasPrefix(path, ".."+string(filepath.Separator)) {
			return fail("agent.enrollment_token_file must remain inside the config directory")
		}
	}
	if hubConfig.Enabled {
		if err := c.validateListen("fleet.hub", hubConfig.Listen, "http"); err != nil {
			return err
		}
		host, _, _ := net.SplitHostPort(hubConfig.Listen)
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) && hubConfig.TLSCertFile == "" {
			return fail("non-loopback hub.listen requires TLS")
		}
	}
	if agentConfig.HubURL != "" || agentConfig.Enabled {
		url, err := egress.ValidateURL(egress.Policy{
			AllowLoopback: true,
			AllowPrivate:  agentConfig.AllowPrivateEgress,
		}, agentConfig.HubURL)
		if err != nil || url.Path != "" && url.Path != "/" || url.RawPath != "" || url.ForceQuery {
			return fail("agent.hub_url must be an allowed http(s) origin; non-loopback requires TLS")
		}
	}
	if agentConfig.Enabled && !protocol.NameValid(c.FleetNodeName()) {
		return fail("agent requires a valid node name")
	}
	if (hubConfig.Enabled || agentConfig.Enabled) && c.FleetStateDir(false) == c.FleetStateDir(true) {
		return fail("hub and agent state directories must differ")
	}
	return nil
}

// ResolveFleetToken reads a bounded credential reference before listeners bind, without exposing its value in errors.
func (c *Config) ResolveFleetToken() (string, error) {
	agent := c.Fleet.Agent
	value := ""
	if agent.EnrollmentTokenEnv != "" {
		value = os.Getenv(agent.EnrollmentTokenEnv)
	} else if agent.EnrollmentTokenFile != "" {
		root, err := os.OpenRoot(filepath.Dir(absClean(c.SourcePath)))
		if err != nil {
			return "", fmt.Errorf("fleet enrollment token: cannot open config directory")
		}
		defer root.Close()
		info, err := root.Lstat(agent.EnrollmentTokenFile)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return "", fmt.Errorf("fleet enrollment token: reference must be a regular mode 0600 file")
		}
		file, err := root.Open(agent.EnrollmentTokenFile)
		if err != nil {
			return "", fmt.Errorf("fleet enrollment token: cannot open reference")
		}
		defer file.Close()
		body, err := io.ReadAll(io.LimitReader(file, 4097))
		if err != nil || len(body) > 4096 {
			return "", fmt.Errorf("fleet enrollment token: reference exceeds 4096 bytes or is unreadable")
		}
		value = string(body)
	} else {
		return "", nil
	}
	value = strings.TrimSpace(value)
	if !protocol.Hex(value, 32) {
		return "", fmt.Errorf("fleet enrollment token: reference must contain a 256-bit lowercase hex token")
	}
	return value, nil
}
