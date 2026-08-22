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

func (c *rulesCmd) Name() string { return "rules" }
func (c *rulesCmd) Usage() string {
	return "rules list [--family detection|correlation] | rules explain RULE_ID"
}
func (c *rulesCmd) Help() string {
	return `List and explain every rule the binaries can emit, read-only.

Detection findings (PI-*/EXF-*/ESC-*/OBS-*/RES-*) and correlation signals
(COR-*) come from one catalog derived from the owning engine registries.
Output order is deterministic; --json emits stable keys.

  rules list                        all rules, human table
  rules list --family correlation   one family only
  rules list --json                 machine-readable
  rules explain PI-001              one rule's metadata`
}

func (c *rulesCmd) Run(_ context.Context, args []string) error {
	if len(args) == 0 {
		return Usagef("choose a subcommand: list or explain")
	}
	switch args[0] {
	case "list":
		return c.list(args[1:])
	case "explain":
		return c.explain(args[1:])
	default:
		return Usagef("unknown rules subcommand %q", args[0])
	}
}

func (c *rulesCmd) list(args []string) error {
	fs := newFlagSet("rules list")
	addGlobalFlags(fs, &c.g)
	family := fs.String("family", "", "filter by family: detection or correlation")
	if err := fs.Parse(args); err != nil {
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

func (c *rulesCmd) explain(args []string) error {
	// Explicit scan instead of flag.Parse: the natural form is
	// "rules explain RULE_ID --json", but the flag package stops at the
	// first positional. Accept --json anywhere; reject unknown flags with a
	// precise message. explain has no value flags, so order never matters.
	jsonOut := c.g.jsonOut
	var pos []string
	for _, a := range args {
		switch a {
		case "--json":
			jsonOut = true
		default:
			if strings.HasPrefix(a, "-") && a != "-" && a != "--" {
				return Usagef("unknown flag %q for rules explain (only --json is supported)", a)
			}
			pos = append(pos, a)
		}
	}
	if len(pos) != 1 || pos[0] == "" {
		return Usagef("exactly one RULE_ID is required (e.g. rules explain PI-001)")
	}

	entry, ok := rulecatalog.Lookup(pos[0])
	if !ok {
		return Usagef("unknown rule id %q%s", pos[0], suggestRuleIDs(pos[0]))
	}

	if jsonOut {
		return writeJSON(c.env.Out, entry)
	}
	sev := entry.Severity
	if sev == "" {
		sev = "-"
	}
	fmt.Fprintf(c.env.Out, "ID:        %s\n", entry.ID)
	fmt.Fprintf(c.env.Out, "FAMILY:    %s\n", entry.Family)
	fmt.Fprintf(c.env.Out, "CLASS:     %s\n", entry.Class)
	fmt.Fprintf(c.env.Out, "SEVERITY:  %s\n", sev)
	fmt.Fprintf(c.env.Out, "SUMMARY:   %s\n", entry.Summary)
	return nil
}

// suggestRuleIDs builds deterministic, fuzz-free suggestions for a failed
// lookup. Only two exact mechanisms ever produce a "did you mean": a
// case-insensitive full-id match, or a case-sensitive prefix matching exactly
// one id. Ambiguous prefixes and everything else get the candidate list —
// the CLI never guesses between multiple rules.
func suggestRuleIDs(input string) string {
	all := rulecatalog.All()
	ids := make([]string, len(all))
	for i, e := range all {
		ids[i] = e.ID
	}
	// Lookup failed, so any case-insensitive hit is by construction a
	// case-only miss of exactly one known id.
	for _, id := range ids {
		if strings.EqualFold(id, input) {
			return fmt.Sprintf("; did you mean %s?", id)
		}
	}
	var prefix []string
	for _, id := range ids {
		if strings.HasPrefix(id, input) {
			prefix = append(prefix, id)
		}
	}
	switch {
	case len(prefix) == 1:
		return fmt.Sprintf("; did you mean %s?", prefix[0])
	case len(prefix) > 1:
		return fmt.Sprintf("; known rules with this prefix: %s", strings.Join(prefix, ", "))
	default:
		return fmt.Sprintf("; known rules: %s", strings.Join(ids, ", "))
	}
}
