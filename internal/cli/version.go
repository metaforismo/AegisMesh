package cli

import (
	"context"
	"fmt"
)

type versionCmd struct {
	env *Env
	g   globals
}

func newVersionCmd(env *Env) *versionCmd { return &versionCmd{env: env} }

func (c *versionCmd) Name() string  { return "version" }
func (c *versionCmd) Usage() string { return "version [--json]" }
func (c *versionCmd) Help() string {
	return `Print build information: version, commit, build date, toolchain.`
}

func (c *versionCmd) Run(_ context.Context, args []string) error {
	fs := newFlagSet(c.Name())
	addGlobalFlags(fs, &c.g)
	if err := fs.Parse(args); err != nil {
		return Usagef("%v", err)
	}
	info := versionInfo()
	if c.g.jsonOut {
		return writeJSON(c.env.Out, info)
	}
	fmt.Fprintf(c.env.Out, "aegismesh %s (commit %s, built %s, %s)\n",
		info.Version, info.Commit, info.BuildDate, info.GoVersion)
	return nil
}
