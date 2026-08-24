package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

type extCmd struct {
	env *Env
	g   globals
}

func newExtCmd(env *Env) *extCmd { return &extCmd{env: env} }

func (c *extCmd) Name() string { return "ext" }
func (c *extCmd) Usage() string {
	return "ext verify --manifest FILE | ext run --manifest FILE [--input JSON]"
}
func (c *extCmd) Help() string {
	return `Inspect, verify, and run capability-scoped extensions.

Extensions are untrusted code: they execute out-of-process behind an explicitly
configured, digest-verified observe-only manifest. The runtime starts only the
manifests listed by an operator when extensions.enabled is true.

  ext verify  --manifest FILE   validate schema + digest (+ signature if keyed)
  ext run     --manifest FILE   send one synthetic observation probe; extension output never becomes policy`
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
	var mf, pub strictValueFlag
	fs.Var(&mf, "manifest", "path to extension manifest")
	fs.Var(&pub, "pubkey", "ed25519 public key file (hex); optional")
	if err := fs.Parse(args); err != nil {
		return Usagef("%v", err)
	}
	if fs.NArg() > 0 {
		return Usagef("unexpected argument %q (ext verify takes flags only)", fs.Arg(0))
	}
	manifestPath, err := requiredExactPath("--manifest", mf.values)
	if err != nil {
		return Usagef("%v", err)
	}
	pubKeyPath, err := optionalExactPath("--pubkey", pub.values)
	if err != nil {
		return Usagef("%v", err)
	}
	res, err := runVerify(manifestPath, pubKeyPath)
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
	var mf, input, pub strictValueFlag
	fs.Var(&mf, "manifest", "path to extension manifest")
	fs.Var(&input, "input", "synthetic observation payload (JSON)")
	fs.Var(&pub, "pubkey", "ed25519 public key file (hex); optional")
	if err := fs.Parse(args); err != nil {
		return Usagef("%v", err)
	}
	if fs.NArg() > 0 {
		return Usagef("unexpected argument %q (ext run takes flags only)", fs.Arg(0))
	}
	manifestPath, err := requiredExactPath("--manifest", mf.values)
	if err != nil {
		return Usagef("%v", err)
	}
	pubKeyPath, err := optionalExactPath("--pubkey", pub.values)
	if err != nil {
		return Usagef("%v", err)
	}
	payload := ""
	if len(input.values) == 1 {
		if input.values[0] == "" || strings.TrimSpace(input.values[0]) == "" {
			return Usagef("--input must not be empty or whitespace")
		}
		payload = input.values[0]
	}
	out, err := runExtension(ctx, manifestPath, payload, pubKeyPath)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("extension exceeded its deadline and was revoked")
		}
		return err
	}
	return writeJSON(c.env.Out, out)
}

func requiredExactPath(name string, values []string) (string, error) {
	if len(values) != 1 {
		return "", fmt.Errorf("%s is required", name)
	}
	return validateExactPath(name, values[0])
}

func optionalExactPath(name string, values []string) (string, error) {
	if len(values) == 0 {
		return "", nil
	}
	return validateExactPath(name, values[0])
}

func validateExactPath(name, value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.HasPrefix(value, "-") || strings.Contains(value, ",") {
		return "", fmt.Errorf("%s must be one non-empty path without surrounding whitespace, commas, or a leading '-'", name)
	}
	return value, nil
}
