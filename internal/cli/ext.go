package cli

import (
	"context"
	"errors"
	"fmt"
)

type extCmd struct {
	env *Env
	g   globals
}

func newExtCmd(env *Env) *extCmd { return &extCmd{env: env} }

func (c *extCmd) Name() string  { return "ext" }
func (c *extCmd) Usage() string { return "ext verify MANIFEST | ext run --manifest FILE" }
func (c *extCmd) Help() string {
	return `Inspect, verify, and run capability-scoped extensions.

Extensions are untrusted code: they always execute out-of-process behind a
digest-verified manifest. The runtime never loads or spawns them implicitly.

  ext verify  --manifest FILE   validate schema + digest (+ signature if keyed)
  ext run     --manifest FILE   run the extension through the reference host`
}

func (c *extCmd) Run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return Usagef("choose a subcommand: verify or run")
	}
	switch args[0] {
	case "verify":
		return c.verify(args[1:])
	case "run":
		return c.runExt(ctx, args[1:])
	default:
		return Usagef("unknown ext subcommand %q", args[0])
	}
}

func (c *extCmd) verify(args []string) error {
	fs := newFlagSet("ext verify")
	addGlobalFlags(fs, &c.g)
	mf := fs.String("manifest", "", "path to extension manifest")
	pub := fs.String("pubkey", "", "ed25519 public key file (hex); optional")
	fs.Parse(args) //nolint:errcheck // rendered below
	if *mf == "" {
		return Usagef("--manifest is required")
	}
	res, err := runVerify(*mf, *pub)
	if err != nil {
		return err
	}
	if c.g.jsonOut {
		return writeJSON(c.env.Out, res)
	}
	fmt.Fprintf(c.env.Out, "manifest %s: %s\n", res.ManifestPath, res.Status)
	for _, w := range res.Warnings {
		fmt.Fprintf(c.env.Out, "  warning: %s\n", w)
	}
	fmt.Fprintf(c.env.Out, "  name=%s version=%s permissions=%v\n", res.Name, res.Version, res.Permissions)
	if res.SignatureChecked {
		fmt.Fprintf(c.env.Out, "  signature: verified\n")
	} else if len(res.Warnings) > 0 && containsStr(res.Warnings, "no signature present") {
		fmt.Fprintln(c.env.Out, "  signature: absent (digest-only verification)")
	}
	return nil
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func (c *extCmd) runExt(ctx context.Context, args []string) error {
	fs := newFlagSet("ext run")
	addGlobalFlags(fs, &c.g)
	mf := fs.String("manifest", "", "path to extension manifest")
	input := fs.String("input", "", "single request payload to deliver (JSON)")
	pub := fs.String("pubkey", "", "ed25519 public key file (hex); optional")
	fs.Parse(args) //nolint:errcheck // rendered below
	if *mf == "" {
		return Usagef("--manifest is required")
	}
	out, err := runExtension(ctx, *mf, *input, *pub)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("extension exceeded its deadline and was revoked")
		}
		return err
	}
	return writeJSON(c.env.Out, out)
}
