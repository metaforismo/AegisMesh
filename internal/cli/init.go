package cli

import (
	"context"
	"fmt"
	"io"

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
func (c *initCmd) Usage() string { return "init [--dir DIR] [--force]" }
func (c *initCmd) Help() string {
	return `Scaffold a safe local AegisMesh workspace with a demo config.

Creates mesh.yaml (loopback-only sensors, synthetic data only) and a short
README in the target directory. Existing files are never overwritten unless
--force is given.`
}

func (c *initCmd) Run(_ context.Context, args []string) error {
	fs := newFlagSet(c.Name())
	addGlobalFlags(fs, &c.g)
	dir := fs.String("dir", ".", "target directory for the workspace")
	force := fs.Bool("force", false, "overwrite existing files")
	if err := fs.Parse(args); err != nil {
		return Usagef("%v", err)
	}
	if fs.NArg() > 0 {
		return Usagef("unexpected argument %q", fs.Arg(0))
	}
	written, err := config.Scaffold(*dir, *force)
	if err != nil {
		return err
	}
	next := "aegismesh doctor --config " + joinDir(*dir, "mesh.yaml")
	if c.g.jsonOut {
		type out struct {
			Wrote   []string `json:"wrote"`
			NextCmd string   `json:"next_command"`
		}
		return writeJSON(c.env.Out, out{Wrote: written, NextCmd: next})
	}
	fmt.Fprintln(c.env.Out, "wrote:")
	for _, p := range written {
		fmt.Fprintf(c.env.Out, "  %s\n", p)
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
