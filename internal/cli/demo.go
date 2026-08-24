package cli

import (
	"bytes"
	"context"
	"fmt"
	"os/signal"
	"strings"
	"syscall"

	"github.com/metaforismo/aegismesh/internal/demo"
)

type demoCmd struct {
	env *Env
	run func(context.Context) (demo.Summary, error)
}

func newDemoCmd(env *Env) *demoCmd {
	return &demoCmd{env: env, run: demo.Run}
}

func (c *demoCmd) Name() string  { return "demo" }
func (c *demoCmd) Usage() string { return "demo [--json]" }
func (c *demoCmd) Help() string {
	return `Run a self-contained, synthetic AegisMesh scenario on loopback.

The command starts HTTP, TCP, MCP and authentication-only SSH sensors on
OS-assigned unprivileged ports, drives one fixed interaction through each,
verifies the stored evidence and its observation hashes, generates a dry-run
recommendation, stops every listener, and removes its private temporary data.

It accepts no config, API key, path, port or destination. It uses no cloud
service or external egress and never performs enforcement.`
}

func (c *demoCmd) Run(ctx context.Context, args []string) error {
	var jsonOut strictBoolFlag
	fs := newFlagSet(c.Name())
	fs.Var(&jsonOut, "json", "emit machine-readable JSON output")
	if err := fs.Parse(args); err != nil {
		return Usagef("%v", err)
	}
	if fs.NArg() > 0 {
		return Usagef("unexpected argument %q (demo takes flags only)", fs.Arg(0))
	}

	runCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
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
	fmt.Fprintln(output, "integrity: verified observation payload hashes")
	fmt.Fprintf(output, "recommendations: %d dry-run proposal (no enforcement)\n", summary.Recommendations)
	fmt.Fprintln(output, "semantics: observation, not incident")
	fmt.Fprintln(output, "shutdown: listeners released")
	fmt.Fprintln(output, "cleanup: complete")
}
