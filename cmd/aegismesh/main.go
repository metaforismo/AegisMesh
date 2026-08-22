// Command aegismesh is the AegisMesh CLI entrypoint.
package main

import (
	"context"
	"os"

	"github.com/metaforismo/aegismesh/internal/cli"
)

func main() {
	env := &cli.Env{Out: os.Stdout, Err: os.Stderr, Stdin: os.Stdin}
	app := cli.NewApp("aegismesh", "local-first deception, detection, and evidence", env.Out, env.Err)
	commands := []cli.Command{
		cli.NewInitCmd(env),
		cli.NewDoctorCmd(env),
		cli.NewHealthcheckCmd(env),
		cli.NewValidateCmd(env),
		cli.NewRunCmd(env),
		cli.NewInspectCmd(env),
		cli.NewMigrateCmd(env),
		cli.NewRulesCmd(env),
		cli.NewExtCmd(env),
		cli.NewVersionCmd(env),
		cli.NewCompletionCmd(env),
	}
	if err := app.Register(commands...); err != nil {
		env.Err.Write([]byte(err.Error() + "\n"))
		os.Exit(2)
	}
	os.Exit(app.Run(context.Background(), os.Args[1:]))
}
