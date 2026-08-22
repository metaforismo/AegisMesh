package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/detect"
	"github.com/metaforismo/aegismesh/internal/version"
)

func versionInfo() version.Info { return version.Get() }

type validateCmd struct {
	env *Env
	g   globals
}

func newValidateCmd(env *Env) *validateCmd { return &validateCmd{env: env} }

func (c *validateCmd) Name() string  { return "validate" }
func (c *validateCmd) Usage() string { return "validate --config FILE [--effective] [--json]" }
func (c *validateCmd) Help() string {
	return `Strictly parse and validate a configuration without starting anything.

With --effective, also preview the resolved policy: provider and egress
classification, detection rules with the severity-to-action mapping, and
per-sensor capabilities including MCP decoy surface. Still side-effect
free — nothing is started, contacted, or written.

Exits non-zero with an actionable message on the first problem. Suitable for
CI pipelines and pre-commit hooks.`
}

func (c *validateCmd) Run(_ context.Context, args []string) error {
	fs := newFlagSet(c.Name())
	addGlobalFlags(fs, &c.g)
	cfgPath := fs.String("config", "mesh.yaml", "path to mesh.yaml")
	effective := fs.Bool("effective", false, "preview resolved provider/detection/sensor policy")
	if err := fs.Parse(args); err != nil {
		return Usagef("%v", err)
	}
	if fs.NArg() > 0 {
		return Usagef("unexpected argument %q", fs.Arg(0))
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if !*effective {
		if c.g.jsonOut {
			type out struct {
				OK         bool   `json:"ok"`
				ConfigPath string `json:"config_path"`
				Schema     string `json:"schema"`
				Sensors    int    `json:"sensors"`
			}
			return writeJSON(c.env.Out, out{OK: true, ConfigPath: cfg.SourcePath, Schema: cfg.APIVersion, Sensors: len(cfg.Sensors)})
		}
		printValidateSummary(c.env.Out, cfg)
		return nil
	}
	rep := buildEffectiveReport(cfg)
	if c.g.jsonOut {
		return writeJSON(c.env.Out, rep)
	}
	printValidateSummary(c.env.Out, cfg)
	renderEffectiveHuman(c.env.Out, cfg, rep)
	return nil
}

func printValidateSummary(w io.Writer, cfg *config.Config) {
	fmt.Fprintf(w, "ok: %s (schema %s, %d sensor(s))\n",
		cfg.SourcePath, cfg.APIVersion, len(cfg.Sensors))
	for i := range cfg.Sensors {
		s := &cfg.Sensors[i]
		extra := ""
		switch s.Kind {
		case config.SensorKindHTTP:
			extra = fmt.Sprintf("%d rule(s)", len(s.Rules))
		case config.SensorKindTCP:
			extra = fmt.Sprintf("%d tcp_rule(s)", len(s.TCPResponseRule))
		case config.SensorKindMCP:
			extra = fmt.Sprintf("%d tool(s)", len(s.Tools))
		}
		fmt.Fprintf(w, "  %-20s %-5s %s %s\n", s.ID, s.Kind, s.Listen, extra)
	}
}

func renderEffectiveHuman(w io.Writer, cfg *config.Config, rep effectiveReport) {
	class, base := classifyProviderEndpoint(cfg)
	fmt.Fprintf(w, "\neffective policy\n")
	fmt.Fprintf(w, "  provider: %s (%s)\n", cfg.LLM.Provider, class)
	if base != "" {
		fmt.Fprintf(w, "  endpoint: %s\n", base)
	}
	if rep.Webhook != nil {
		fmt.Fprintf(w, "  webhook: %s (%s)%s\n", rep.Webhook.Host, rep.Webhook.Class,
			map[bool]string{true: "", false: " — UNSIGNED"}[rep.Webhook.Signed])
	}
	d := rep.Detection
	state := "disabled"
	if d.Enabled {
		state = fmt.Sprintf("enabled — %d/%d rules active", d.RulesEnabled, d.RulesEnabled+len(d.DisabledRules))
	}
	fmt.Fprintf(w, "  detection: %s\n", state)
	if len(d.DisabledRules) > 0 {
		fmt.Fprintf(w, "    disabled: %s\n", strings.Join(d.DisabledRules, ", "))
	}
	fmt.Fprintf(w, "    actions: info=%s low=%s medium=%s high=%s\n",
		d.Actions["info"], d.Actions["low"], d.Actions["medium"], d.Actions["high"])
	fmt.Fprintf(w, "    bounds: max_input=%dB throttle=%d/min\n", d.MaxInputBytes, d.ThrottlePerMinute)
	if c := rep.Correlation; c.Enabled {
		fmt.Fprintf(w, "  correlation: enabled — window=%ds per_source_events=%d max_sources=%d\n",
			c.WindowSeconds, c.PerSourceEvents, c.MaxSources)
		if len(c.DisabledRules) > 0 {
			fmt.Fprintf(w, "    disabled: %s\n", strings.Join(c.DisabledRules, ", "))
		}
	} else {
		fmt.Fprintf(w, "  correlation: off (default)\n")
	}
	for _, s := range rep.Sensors {
		caps := []string{}
		if s.HTTPRules > 0 {
			caps = append(caps, fmt.Sprintf("%d rule(s)", s.HTTPRules))
		}
		if s.TCPRules > 0 {
			caps = append(caps, fmt.Sprintf("%d tcp_rule(s)", s.TCPRules))
		}
		if s.Tools > 0 {
			caps = append(caps, fmt.Sprintf("%d tool(s)", s.Tools))
		}
		if s.Resources > 0 {
			caps = append(caps, fmt.Sprintf("%d resource(s)", s.Resources))
		}
		if s.Prompts > 0 {
			caps = append(caps, fmt.Sprintf("%d prompt(s)", s.Prompts))
		}
		if s.Fallback {
			caps = append(caps, "llm-fallback")
		}
		fmt.Fprintf(w, "    %-20s %-5s %s\n", s.ID, s.Kind, strings.Join(caps, ", "))
	}
}

type effectiveReport struct {
	ConfigPath  string           `json:"config_path"`
	Provider    string           `json:"provider"`
	EgressClass string           `json:"egress_class"`
	BaseURL     string           `json:"base_url,omitempty"`
	Detection   detectionSummary `json:"detection"`
	Webhook     *webhookSummary  `json:"webhook,omitempty"`
	Correlation correlationSum   `json:"correlation"`
	Sensors     []sensorSummary  `json:"sensors"`
}

// correlationSum mirrors the resolved correlation section for operators.
type correlationSum struct {
	Enabled         bool     `json:"enabled"`
	WindowSeconds   int      `json:"window_seconds,omitempty"`
	PerSourceEvents int      `json:"per_source_events,omitempty"`
	MaxSources      int      `json:"max_sources,omitempty"`
	DisabledRules   []string `json:"disabled_rules,omitempty"`
}

type webhookSummary struct {
	Enabled bool   `json:"enabled"`
	Host    string `json:"host,omitempty"`
	Signed  bool   `json:"signed"`
	Class   string `json:"egress_class,omitempty"`
}

type detectionSummary struct {
	Enabled           bool              `json:"enabled"`
	RulesEnabled      int               `json:"rules_enabled"`
	DisabledRules     []string          `json:"disabled_rules,omitempty"`
	MaxInputBytes     int               `json:"max_input_bytes"`
	Actions           map[string]string `json:"actions"`
	ThrottlePerMinute int               `json:"throttle_per_minute"`
}

type sensorSummary struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Listen    string `json:"listen"`
	HTTPRules int    `json:"http_rules,omitempty"`
	TCPRules  int    `json:"tcp_rules,omitempty"`
	Tools     int    `json:"mcp_tools,omitempty"`
	Resources int    `json:"mcp_resources,omitempty"`
	Prompts   int    `json:"mcp_prompts,omitempty"`
	Fallback  bool   `json:"llm_fallback,omitempty"`
}

func buildEffectiveReport(cfg *config.Config) effectiveReport {
	class, base := classifyProviderEndpoint(cfg)
	totalRules := len(detect.KnownRuleIDs())
	rep := effectiveReport{
		ConfigPath:  cfg.SourcePath,
		Provider:    cfg.LLM.Provider,
		EgressClass: class,
		BaseURL:     base,
		Detection: detectionSummary{
			Enabled:       cfg.Detection.IsEnabled(),
			RulesEnabled:  totalRules - len(cfg.Detection.DisabledRules),
			DisabledRules: cfg.Detection.DisabledRules,
			MaxInputBytes: cfg.Detection.MaxInputBytes,
			Actions: map[string]string{
				"info": cfg.Detection.Actions.Info, "low": cfg.Detection.Actions.Low,
				"medium": cfg.Detection.Actions.Medium, "high": cfg.Detection.Actions.High,
			},
			ThrottlePerMinute: cfg.Detection.ThrottlePerMinute,
		},
	}
	if rep.Detection.ThrottlePerMinute == 0 {
		rep.Detection.ThrottlePerMinute = 600 // documented default
	}
	if cfg.Webhook.IsEnabled() {
		class, u, _ := classifyWebhookEndpoint(cfg)
		rep.Webhook = &webhookSummary{
			Enabled: true,
			Signed:  cfg.Webhook.HMACSecretEnv != "" || cfg.Webhook.HMACSecretFile != "",
			Class:   class,
		}
		if u != nil {
			rep.Webhook.Host = u.Host
		}
	}
	rep.Correlation = correlationSum{
		Enabled:         cfg.Correlation.IsEnabled(),
		WindowSeconds:   cfg.Correlation.WindowSeconds,
		PerSourceEvents: cfg.Correlation.PerSourceEvents,
		MaxSources:      cfg.Correlation.MaxSources,
		DisabledRules:   cfg.Correlation.DisabledRules,
	}
	for i := range cfg.Sensors {
		s := &cfg.Sensors[i]
		ss := sensorSummary{ID: s.ID, Kind: s.Kind, Listen: s.Listen,
			HTTPRules: len(s.Rules), TCPRules: len(s.TCPResponseRule),
			Tools: len(s.Tools), Resources: len(s.Resources), Prompts: len(s.Prompts),
			Fallback: s.Fallback != nil && s.Fallback.Enabled,
		}
		rep.Sensors = append(rep.Sensors, ss)
	}
	return rep
}
