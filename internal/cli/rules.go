package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/metaforismo/aegismesh/internal/rulecatalog"
)

type rulesCmd struct {
	env *Env
	g   globals
}

func newRulesCmd(env *Env) *rulesCmd { return &rulesCmd{env: env} }

func (c *rulesCmd) Name() string  { return "rules" }
func (c *rulesCmd) Usage() string { return "rules list [--family detection|correlation]" }
func (c *rulesCmd) Help() string {
	return `List every rule the binaries can emit, read-only.

Detection findings (PI-*/EXF-*/ESC-*/OBS-*/RES-*) and correlation signals
(COR-*) come from one catalog derived from the owning engine registries.
Output order is deterministic; --json emits {"rules":[...]} with stable keys.

  rules list                        all rules, human table
  rules list --family correlation   one family only
  rules list --json                 machine-readable`
}

func (c *rulesCmd) Run(_ context.Context, args []string) error {
	if len(args) == 0 || args[0] != "list" {
		return Usagef("choose a subcommand: list")
	}
	fs := newFlagSet("rules list")
	addGlobalFlags(fs, &c.g)
	family := fs.String("family", "", "filter by family: detection or correlation")
	if err := fs.Parse(args[1:]); err != nil {
		return Usagef("%v", err)
	}
	if fs.NArg() > 0 {
		return Usagef("unexpected argument %q", fs.Arg(0))
	}
	if *family != "" && !rulecatalog.ValidFamily(*family) {
		return Usagef("unknown family %q (want %s)", *family, strings.Join(rulecatalog.Families(), "|"))
	}

	entries := rulecatalog.All()
	if *family != "" {
		filtered := entries[:0] // reuse backing array; All() returned a fresh slice
		for _, e := range entries {
			if e.Family == *family {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}

	if c.g.jsonOut {
		return writeJSON(c.env.Out, struct {
			Rules []rulecatalog.Entry `json:"rules"`
		}{Rules: entries})
	}

	fmt.Fprintf(c.env.Out, "%-9s %-12s %-7s %-7s %s\n", "ID", "FAMILY", "CLASS", "SEV", "SUMMARY")
	for _, e := range entries {
		sev := e.Severity
		if sev == "" {
			sev = "-"
		}
		fmt.Fprintf(c.env.Out, "%-9s %-12s %-7s %-7s %s\n", e.ID, e.Family, e.Class, sev, e.Summary)
	}
	return nil
}
