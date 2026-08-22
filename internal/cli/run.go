package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/runtime"
)

type runCmd struct {
	env *Env
	g   globals
}

func newRunCmd(env *Env) *runCmd { return &runCmd{env: env} }

func (c *runCmd) Name() string  { return "run" }
func (c *runCmd) Usage() string { return "run --config FILE [--dry-run]" }
func (c *runCmd) Help() string {
	return `Start the configured deception sensors and record evidence until Ctrl-C.

All listeners bind per config (loopback and unprivileged ports by default).
The admin listener serves /healthz /readyz /metrics /version on its own
loopback port. Graceful shutdown on SIGINT/SIGTERM.

--dry-run binds every listener, verifies it can serve, then immediately stops:
useful in CI to prove a config is runnable without leaving anything listening.`
}

func (c *runCmd) Run(_ context.Context, args []string) error {
	fs := newFlagSet(c.Name())
	addGlobalFlags(fs, &c.g)
	cfgPath := fs.String("config", "mesh.yaml", "path to mesh.yaml")
	dryRun := fs.Bool("dry-run", false, "bind listeners, verify, then stop")
	if err := fs.Parse(args); err != nil {
		return Usagef("%v", err)
	}
	if fs.NArg() > 0 {
		return Usagef("unexpected argument %q", fs.Arg(0))
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	log := newLogger(c.env.Err, cfg.Logging.Level, cfg.Logging.Format)
	sys, err := runtime.Build(cfg, log)
	if err != nil {
		return err
	}

	if *dryRun {
		return c.dryRun(cfg, sys, log)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(c.env.Out, "aegismesh starting: %d sensor(s), evidence in %s\n", len(cfg.Sensors), cfg.Runtime.DataDir)
	for i := range cfg.Sensors {
		fmt.Fprintf(c.env.Out, "  %-20s %-5s %s\n", cfg.Sensors[i].ID, cfg.Sensors[i].Kind, cfg.Sensors[i].Listen)
	}
	if cfg.Admin.IsEnabled() {
		fmt.Fprintf(c.env.Out, "  %-20s %-5s %s (/healthz /readyz /metrics /version)\n", "admin", "", cfg.Admin.Listen)
	}
	fmt.Fprintf(c.env.Out, "press Ctrl-C to stop\n")

	err = sys.Run(ctx)
	if err == nil {
		fmt.Fprintln(c.env.Out, "stopped cleanly; evidence retained")
	}
	return err
}

func (c *runCmd) dryRun(cfg *config.Config, sys *runtime.System, log *slog.Logger) error {
	ctx, cancel := context.WithTimeout(context.Background(), startTimeoutCLI())
	defer cancel()
	if err := sys.Start(ctx); err != nil {
		return fmt.Errorf("dry-run failed: %v", err)
	}
	sys.Stop(context.Background())
	if c.g.jsonOut {
		type out struct {
			DryRun  bool     `json:"dry_run"`
			OK      bool     `json:"ok"`
			Sensors []string `json:"sensors"`
		}
		ids := make([]string, 0, len(cfg.Sensors))
		for i := range cfg.Sensors {
			ids = append(ids, cfg.Sensors[i].ID)
		}
		return writeJSON(c.env.Out, out{DryRun: true, OK: true, Sensors: ids})
	}
	fmt.Fprintf(c.env.Out, "dry-run ok: all %d sensor(s) bound and stopped cleanly\n", len(cfg.Sensors))
	return nil
}

func startTimeoutCLI() time.Duration { return 15 * time.Second }

func newLogger(w interface{ Write(p []byte) (int, error) }, level, format string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: slogLevel(level)}
	var h slog.Handler
	if format == "text" {
		h = slog.NewTextHandler(os.Stderr, opts)
	} else {
		h = slog.NewJSONHandler(os.Stderr, opts)
	}
	return slog.New(h)
}
