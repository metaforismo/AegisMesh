package cli

import (
	"context"
	"fmt"

	"github.com/metaforismo/aegismesh/internal/honeytoken"
	"gopkg.in/yaml.v3"
)

type honeytokenCmd struct{ env *Env }

func NewHoneytokenCmd(env *Env) Command { return &honeytokenCmd{env} }
func (c *honeytokenCmd) Name() string   { return "honeytoken" }
func (c *honeytokenCmd) Usage() string {
	return "honeytoken new --kind credential|agent_canary --format openai|anthropic|aws|github|generic --id SLUG"
}
func (c *honeytokenCmd) Help() string {
	return "Generate a synthetic honeytoken config snippet. Never use real credentials as honeytokens."
}
func (c *honeytokenCmd) Run(_ context.Context, args []string) error {
	if len(args) == 0 || args[0] != "new" {
		return Usagef("choose subcommand: new")
	}
	fs := newFlagSet("honeytoken new")
	kind := fs.String("kind", "", "credential or agent_canary")
	format := fs.String("format", "generic", "synthetic format: openai|anthropic|aws|github|generic")
	id := fs.String("id", "", "unique lowercase slug")
	if err := fs.Parse(args[1:]); err != nil {
		return Usagef("%v", err)
	}
	if fs.NArg() != 0 {
		return Usagef("unexpected positional argument")
	}
	token, err := honeytoken.Generate(*id, *kind, *format)
	if err != nil {
		return Usagef("%v", err)
	}
	b, err := yaml.Marshal(struct {
		Tokens []honeytoken.Token `yaml:"honeytokens"`
	}{[]honeytoken.Token{token}})
	if err != nil {
		return fmt.Errorf("honeytoken: encode snippet: %w", err)
	}
	_, err = c.env.Out.Write(append([]byte("# Synthetic only. Never use real credentials as honeytokens.\n"), b...))
	return err
}
