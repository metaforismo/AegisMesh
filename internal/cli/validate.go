package cli

import (
	"context"
	"fmt"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/version"
)

func versionInfo() version.Info { return version.Get() }

type validateCmd struct {
	env *Env
	g   globals
}

func newValidateCmd(env *Env) *validateCmd { return &validateCmd{env: env} }

func (c *validateCmd) Name() string  { return "validate" }
func (c *validateCmd) Usage() string { return "validate --config FILE [--json]" }
func (c *validateCmd) Help() string {
	return `Strictly parse and validate a configuration without starting anything.

Exits non-zero with an actionable message on the first problem. Suitable for
CI pipelines and pre-commit hooks.`
}

func (c *validateCmd) Run(_ context.Context, args []string) error {
	fs := newFlagSet(c.Name())
	addGlobalFlags(fs, &c.g)
	cfgPath := fs.String("config", "mesh.yaml", "path to mesh.yaml")
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
	if c.g.jsonOut {
		type out struct {
			OK         bool   `json:"ok"`
			ConfigPath string `json:"config_path"`
			Schema     string `json:"schema"`
			Sensors    int    `json:"sensors"`
		}
		return writeJSON(c.env.Out, out{OK: true, ConfigPath: cfg.SourcePath, Schema: cfg.APIVersion, Sensors: len(cfg.Sensors)})
	}
	fmt.Fprintf(c.env.Out, "ok: %s (schema %s, %d sensor(s))\n",
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
		fmt.Fprintf(c.env.Out, "  %-20s %-5s %s %s\n", s.ID, s.Kind, s.Listen, extra)
	}
	return nil
}
