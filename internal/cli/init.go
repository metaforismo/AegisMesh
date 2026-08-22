package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/metaforismo/aegismesh/internal/config"
)

// Env carries injected IO for one CLI process.
type Env struct {
	Out io.Writer
	Err io.Writer
}

type initCmd struct {
	env *Env
	g   globals
}

func newInitCmd(env *Env) *initCmd { return &initCmd{env: env} }

func (c *initCmd) Name() string  { return "init" }
func (c *initCmd) Usage() string { return "init [--dir DIR] [--profile local|ollama|remote] [--force]" }
func (c *initCmd) Help() string {
	return `Scaffold a safe local AegisMesh workspace with a demo config.

Profiles:
  local    deterministic offline provider, zero egress, no key (default)
  ollama   responses via a local Ollama daemon at its OpenAI-compatible
           endpoint (loopback cleartext http permitted for this profile)
  remote   generic OpenAI-compatible endpoint; the key is referenced by
           environment variable NAME (OPENAI_API_KEY) — never embedded

Creates mesh.yaml and a short README in the target directory. Existing
files are never overwritten unless --force is given.`
}

func (c *initCmd) Run(_ context.Context, args []string) error {
	fs := newFlagSet(c.Name())
	addGlobalFlags(fs, &c.g)
	dir := fs.String("dir", ".", "target directory for the workspace")
	profile := fs.String("profile", "local", "provider profile: local|ollama|remote")
	force := fs.Bool("force", false, "overwrite existing files")
	if err := fs.Parse(args); err != nil {
		return Usagef("%v", err)
	}
	if fs.NArg() > 0 {
		return Usagef("unexpected argument %q", fs.Arg(0))
	}
	valid := false
	for _, p := range config.ValidProfiles() {
		if p == *profile {
			valid = true
			break
		}
	}
	if !valid {
		return Usagef("unknown --profile %q (valid: %s)", *profile, strings.Join(config.ValidProfiles(), "|"))
	}
	written, err := config.ScaffoldProfile(*dir, config.Profile(*profile), *force)
	if err != nil {
		return err
	}
	next := "aegismesh doctor --config " + joinDir(*dir, "mesh.yaml")
	if c.g.jsonOut {
		type out struct {
			Wrote   []string `json:"wrote"`
			Profile string   `json:"profile"`
			NextCmd string   `json:"next_command"`
		}
		return writeJSON(c.env.Out, out{Wrote: written, Profile: *profile, NextCmd: next})
	}
	fmt.Fprintln(c.env.Out, "wrote:")
	for _, p := range written {
		fmt.Fprintf(c.env.Out, "  %s\n", p)
	}
	if *profile == "remote" {
		fmt.Fprintln(c.env.Out, "\nthe generated config references OPENAI_API_KEY by name;")
		fmt.Fprintln(c.env.Out, "export that variable before running — never put the key in mesh.yaml")
	}
	if *profile == "ollama" {
		fmt.Fprintln(c.env.Out, "\nrequires a local Ollama daemon (ollama pull llama3); without one")
		fmt.Fprintln(c.env.Out, "the decoy falls back to static responses on provider errors")
	}
	fmt.Fprintf(c.env.Out, "\nnext: %s\n", next)
	return nil
}

func joinDir(dir, name string) string {
	if dir == "" || dir == "." {
		return name
	}
	return dir + "/" + name
}

// Constructors are exported here rather than in each file to keep the
// command surface visible in one place per file naming.
