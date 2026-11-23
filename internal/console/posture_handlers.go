package console

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/posture"
)

// PostureFacts derives the secret-free posture snapshot from the validated
// effective configuration once. Token values, digests, URLs and secret
// references are reduced to booleans, counts and identifiers here.
func PostureFacts(cfg *config.Config) posture.Facts {
	decoys, markers := DecoyCatalog(cfg)
	families := map[string][]string{}
	for _, decoy := range decoys {
		families[decoy.ID] = decoy.SurfaceFamilies
	}
	facts := posture.Facts{
		Sensors:               []posture.Sensor{},
		Honeytokens:           []posture.Token{},
		ConsoleEnabled:        cfg.Console.Enabled,
		ConsoleListen:         cfg.Console.Listen,
		ConsoleTLS:            cfg.Console.TLSCertFile != "",
		TokenLogin:            cfg.Console.TokenEnabled(),
		OIDC:                  cfg.Console.OIDC.Enabled,
		OperatorRoles:         map[string]int{},
		AllowPublicBind:       cfg.Security.AllowPublicBind,
		AllowPrivilegedPorts:  cfg.Security.AllowPrivilegedPorts,
		AllowPrivateLLMEgress: cfg.Security.AllowPrivateLLMEgress,
		LLMProvider:           cfg.LLM.Provider,
		LLMEndpointLoopback:   loopbackURL(cfg.LLM.BaseURL),
		DetectionEnabled:      cfg.Detection.IsEnabled(),
		DetectionDisabled:     append([]string{}, cfg.Detection.DisabledRules...),
		Actions: map[string]string{
			"info": cfg.Detection.Actions.Info, "low": cfg.Detection.Actions.Low,
			"medium": cfg.Detection.Actions.Medium, "high": cfg.Detection.Actions.High,
		},
		CorrelationEnabled:  cfg.Correlation.IsEnabled(),
		CorrelationDisabled: append([]string{}, cfg.Correlation.DisabledRules...),
		Webhook:             cfg.Webhook.IsEnabled(),
		FleetForwarding:     cfg.Fleet.Agent.Enabled && cfg.Fleet.Agent.ForwardEvidence.Enabled,
		FleetHubCAPinned:    cfg.Fleet.Agent.HubCAFile != "",
		EncryptionAtRest:    cfg.Storage.Encryption != nil && cfg.Storage.Encryption.Enabled,
	}
	for _, operator := range cfg.Console.Operators {
		facts.OperatorRoles[operator.Role]++
	}
	for _, sensor := range cfg.Sensors {
		bodyFiles := false
		for _, rule := range sensor.Rules {
			bodyFiles = bodyFiles || rule.BodyFile != ""
		}
		facts.Sensors = append(facts.Sensors, posture.Sensor{
			ID: sensor.ID, Kind: sensor.Kind, Listen: sensor.Listen,
			SurfaceFamilies: append([]string{}, families[sensor.ID]...),
			MCPEnvironment:  sensor.Environment != nil,
			LLMFallback:     sensor.Fallback != nil && sensor.Fallback.Enabled,
			BodyFiles:       bodyFiles,
		})
	}
	for _, marker := range markers {
		facts.Honeytokens = append(facts.Honeytokens, posture.Token{ID: marker.ID, Kind: marker.Kind, Planted: len(marker.SensorIDs) > 0})
	}
	return facts
}

func loopbackURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return false
	}
	host := parsed.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) posture(w http.ResponseWriter, r *http.Request, _ caller) {
	if _, ok := query(w, r); !ok {
		return
	}
	boundedJSON(w, posture.Evaluate(s.postureFacts, posture.FromSnapshot(s.index.Analysis()), time.Now()))
}
