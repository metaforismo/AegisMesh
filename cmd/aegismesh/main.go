// Command aegismesh is the AegisMesh CLI entrypoint.
package main

import (
	"context"
	"os"

	"github.com/metaforismo/aegismesh/internal/cli"
	"github.com/metaforismo/aegismesh/internal/sensorproc"
)

func main() {
	if sensorproc.IsBuiltinWorkerInvocation(os.Args) {
		if err := sensorproc.RunBuiltinWorker(context.Background(), os.Stdin, os.Stdout); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	env := &cli.Env{Out: os.Stdout, Err: os.Stderr, Stdin: os.Stdin}
	app := cli.NewApp("aegismesh", "local-first deception, detection, and evidence", env.Out, env.Err)
	commands := []cli.Command{
		cli.NewInitCmd(env),
		cli.NewDoctorCmd(env),
		cli.NewHealthcheckCmd(env),
		cli.NewValidateCmd(env),
		cli.NewRunCmd(env),
		cli.NewDemoCmd(env),
		cli.NewInspectCmd(env),
		cli.NewRecommendCmd(env),
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
