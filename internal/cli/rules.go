package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/metaforismo/aegismesh/internal/rulecatalog"
	"github.com/metaforismo/aegismesh/internal/rulesinput"
	"github.com/metaforismo/aegismesh/internal/ruletest"
)

type rulesCmd struct {
	env *Env
	g   globals
}

func newRulesCmd(env *Env) *rulesCmd { return &rulesCmd{env: env} }

func (c *rulesCmd) Name() string { return "rules" }
func (c *rulesCmd) Usage() string {
	return "rules list [--family detection|correlation] | rules explain RULE_ID | rules test (--text TEXT|--file PATH|--stdin)"
}
func (c *rulesCmd) Help() string {
	return `List, explain, and test every rule the binaries can emit, read-only.

Detection findings (PI-*/EXF-*/ESC-*/OBS-*/RES-*) and correlation signals
(COR-*) come from one catalog derived from the owning engine registries.
Output order is deterministic; --json emits stable keys.

  rules list                        all rules, human table
  rules list --family correlation   one family only
  rules list --json                 machine-readable
  rules explain PI-001              one rule's metadata

rules test evaluates exactly one explicitly declared offline document
against the DETECTION rule set without any sensor, storage, or network.
Exactly one of --text, --file, or --stdin must be given; ambiguity or
absence is an error, never a fallback:

  rules test --text "hello"         evaluate inline text
  rules test --file doc.txt         evaluate a named local file
  rules test --stdin < doc.txt      evaluate the wired stdin stream
  rules test --text "..." --json    machine-readable

Findings are signals, not proof: zero matches exits successfully.`
}

func (c *rulesCmd) Run(_ context.Context, args []string) error {
	if len(args) == 0 {
		return Usagef("choose a subcommand: list, explain, or test")
	}
	switch args[0] {
	case "list":
		return c.list(args[1:])
	case "explain":
		return c.explain(args[1:])
	case "test":
		return c.test(args[1:])
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

// test evaluates exactly one explicitly declared offline document against the
// DETECTION rule set (capabilities 4d-1..4d-3 wired together). The input
// flags are mutually exclusive by presence — not by value — so `--text ""`
// is a declared empty literal that fails as empty input, never as a missing
// source, and a dash positional is never silently promoted to stdin.
//
// Loader and evaluator errors are returned unwrapped so their typed
// categories (errors.Is targets) survive to the caller; every message those
// seams produce is content-free by contract. The one exception this command
// must handle at its own boundary is *fs.PathError, which embeds the
// verbatim path argument; sanitizePathError reduces it to the base name.
func (c *rulesCmd) test(args []string) error {
	fs := newFlagSet("rules test")
	addGlobalFlags(fs, &c.g)
	text := fs.String("text", "", "inline document text (literal source)")
	file := fs.String("file", "", "named local file holding the document")
	stdin := fs.Bool("stdin", false, "read the document from the wired stdin stream")
	if err := fs.Parse(args); err != nil {
		return Usagef("%v", err)
	}
	if fs.NArg() > 0 {
		return Usagef("unexpected argument %q (a dash is not stdin; pass --stdin explicitly)", fs.Arg(0))
	}

	// Explicitness differs by flag type, deliberately: string sources are
	// selected by mere presence (--text "" is a declared empty literal),
	// while a boolean is selected only when true (--stdin=false is simply
	// off). Presence comes from Visit, never from parsed values.
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	var picked []string
	if given["text"] {
		picked = append(picked, "--text")
	}
	if given["file"] {
		picked = append(picked, "--file")
	}
	if *stdin {
		picked = append(picked, "--stdin")
	}
	switch {
	case len(picked) == 0:
		return Usagef("exactly one input source is required: --text TEXT, --file PATH, or --stdin")
	case len(picked) > 1:
		return Usagef("input sources are mutually exclusive; got %s", strings.Join(picked, " and "))
	}

	var src rulesinput.Source
	switch picked[0] {
	case "--text":
		src = rulesinput.Source{Kind: rulesinput.KindLiteral, Text: *text}
	case "--file":
		src = rulesinput.Source{Kind: rulesinput.KindFile, Path: *file}
	case "--stdin":
		if c.env.Stdin == nil {
			return fmt.Errorf("rules test: --stdin selected but no stdin stream is wired into this process")
		}
		src = rulesinput.Source{Kind: rulesinput.KindStdin, Stdin: c.env.Stdin}
	}

	in, err := rulesinput.Load(src)
	if err != nil {
		return sanitizePathError(err)
	}
	res, err := ruletest.Evaluate(in)
	if err != nil {
		return err
	}

	if c.g.jsonOut {
		type sourceOut struct {
			Kind  string `json:"kind"`
			Name  string `json:"name"`
			Bytes int    `json:"bytes"`
		}
		return writeJSON(c.env.Out, struct {
			Source   sourceOut          `json:"source"`
			Findings []ruletest.Finding `json:"findings"`
		}{
			Source:   sourceOut{Kind: string(res.Kind), Name: res.Name, Bytes: res.Bytes},
			Findings: res.Findings,
		})
	}

	label := string(res.Kind)
	if res.Name != label {
		label += " " + res.Name
	}
	fmt.Fprintf(c.env.Out, "SOURCE:    %s (%d bytes)\n", label, res.Bytes)
	fmt.Fprintf(c.env.Out, "MATCHES:   %d\n", len(res.Findings))
	for _, f := range res.Findings {
		fmt.Fprintf(c.env.Out, "  %-9s %-8s %-8s %s\n", f.RuleID, f.Severity, f.Class, f.Summary)
	}
	return nil
}

// sanitizePathError rewrites os-level failures so the full caller-supplied
// path embedded in *fs.PathError never reaches output; only the base name,
// the failed operation, and the wrapped cause remain. Every other error is
// returned unchanged.
func sanitizePathError(err error) error {
	var perr *fs.PathError
	if errors.As(err, &perr) {
		return fmt.Errorf("%w (%s %s)", perr.Err, perr.Op, filepath.Base(perr.Path))
	}
	return err
}
