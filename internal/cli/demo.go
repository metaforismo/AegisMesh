package cli

import (
	"bytes"
	"context"
	"fmt"
	"os/signal"
	"strings"
	"syscall"

	"github.com/metaforismo/aegismesh/internal/demo"
	"github.com/metaforismo/aegismesh/internal/demoseed"
)

type demoCmd struct {
	env *Env
	run func(context.Context) (demo.Summary, error)
}

func newDemoCmd(env *Env) *demoCmd {
	return &demoCmd{env: env, run: demo.Run}
}

func (c *demoCmd) Name() string  { return "demo" }
func (c *demoCmd) Usage() string { return "demo [--json] [--console [--seed small|large]]" }
func (c *demoCmd) Help() string {
	return `Run a self-contained, synthetic AegisMesh scenario on loopback.

The command starts HTTP, TCP, MCP and authentication-only SSH sensors on
OS-assigned unprivileged ports, drives synthetic interactions through each
and an AI enumeration / one-token probe / honeytoken / agent marker sequence,
verifies the stored evidence and its observation hashes, generates a dry-run
recommendations, stops every listener, and removes its private temporary data.

With --console, retains the synthetic evidence on an OS-assigned loopback
console until interrupted and prints a fresh admin token once. The embedded
operator UI is served at the printed URL alongside the console API. Cannot
combine with --json.

With --console --seed small|large, first writes clearly synthetic historical
evidence into the same private temporary store: about 2,000 (small) or 50,000
(large) observations over the previous seven days from documentation-range
sources (TEST-NET and 2001:db8::/32), plus the correlation signals they
trigger. Every seeded observation is marked "synthetic": true, passes the same
redaction, and is removed with the rest of the temporary state. Correlation is
enabled for the seeded run. Output is deterministic for a given start time.

It accepts no config, API key, path, port or destination. It uses no cloud
service or external egress and never performs enforcement.`
}

func (c *demoCmd) Run(ctx context.Context, args []string) error {
	var jsonOut, consoleFlag strictBoolFlag
	fs := newFlagSet(c.Name())
	fs.Var(&jsonOut, "json", "emit machine-readable JSON output")
	fs.Var(&consoleFlag, "console", "keep synthetic evidence behind a loopback console until interrupted")
	var seedFlag strictValueFlag
	fs.Var(&seedFlag, "seed", "with --console: seed synthetic history (small|large)")
	if err := fs.Parse(args); err != nil {
		return Usagef("%v", err)
	}
	if fs.NArg() > 0 {
		return Usagef("unexpected argument %q (demo takes flags only)", fs.Arg(0))
	}

	profile := seedFlag.String()
	if len(seedFlag.values) > 0 {
		if !consoleFlag.Value() {
			return Usagef("--seed requires --console")
		}
		if _, err := demoseed.Lookup(profile); err != nil {
			return Usagef("--seed: %v", err)
		}
	}

	runCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if consoleFlag.Value() {
		if jsonOut.Value() {
			return Usagef("--console and --json cannot be combined")
		}
		_, err := demo.RunConsoleSeeded(runCtx, profile, func(info demo.ConsoleInfo) error {
			if info.Seeded.Events > 0 {
				if _, e := fmt.Fprintf(c.env.Out, "Seeded: %d synthetic observations and %d correlation signals from %d documentation-range sources (profile %s)\n",
					info.Seeded.Events, info.Seeded.Signals, info.Seeded.Sources, info.Seeded.Profile); e != nil {
					return e
				}
			}
			_, e := fmt.Fprintf(c.env.Out, "Console: http://%s\nOperator: demo-admin (admin)\nToken (save now): %s\nSynthetic evidence only. Press Ctrl-C to stop and remove temporary state.\n", info.Addr, info.Token)
			return e
		})
		return err
	}
	summary, err := c.run(runCtx)
	if err != nil {
		return err
	}

	var output bytes.Buffer
	if jsonOut.Value() {
		if err := writeJSON(&output, summary); err != nil {
			return err
		}
	} else {
		writeDemoHuman(&output, summary)
	}
	_, err = c.env.Out.Write(output.Bytes())
	return err
}

func writeDemoHuman(output *bytes.Buffer, summary demo.Summary) {
	fmt.Fprintln(output, "AEGISMESH DEMO: PASS")
	fmt.Fprintf(output, "mode: %s\n", summary.Mode)
	fmt.Fprintf(output, "network: %s (OS-assigned unprivileged ports)\n", summary.Network)
	fmt.Fprintf(output, "egress: %s\n", summary.Egress)
	fmt.Fprintf(output, "sensors: %s\n", strings.Join(summary.Sensors, ", "))
	fmt.Fprintf(output, "evidence: %d observations (%d interaction, %d canary invocation)\n",
		summary.Events, summary.Interactions, summary.CanaryInvocations)
	fmt.Fprintf(output, "AI observations: %s\n", strings.Join(summary.DetectionRules, ", "))
	fmt.Fprintln(output, "integrity: verified observation payload hashes")
	fmt.Fprintf(output, "recommendations: %d dry-run proposal (no enforcement)\n", summary.Recommendations)
	fmt.Fprintln(output, "semantics: observation, not incident")
	fmt.Fprintln(output, "shutdown: listeners released")
	fmt.Fprintln(output, "cleanup: complete")
}
