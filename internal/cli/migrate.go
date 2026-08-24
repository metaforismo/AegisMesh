package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/migrate/beelzebub"
)

type migrateCmd struct {
	env *Env
	g   globals
}

func newMigrateCmd(env *Env) *migrateCmd { return &migrateCmd{env: env} }

func (c *migrateCmd) Name() string { return "migrate" }
func (c *migrateCmd) Usage() string {
	return "migrate beelzebub FILE... [--out DIR] [--write] [--force]"
}
func (c *migrateCmd) Help() string {
	return `Clean-room importer for publicly documented Beelzebub YAML service files.

Behavior:
  - Dry-run by default: prints a compatibility report and writes nothing.
  - Never modifies source files.
  - --write emits one translated AegisMesh config per translatable file into
    --out (refusing to overwrite without --force).
  - Unsupported fields are listed exactly; privileged-port or public-bind
    implications are reported, never auto-enabled.

Supported sources: http, tcp, mcp, and SSH service documents. SSH imports map
only protocol, address, and a derived sensor id; authentication remains
synthetic and commands, plugins, passwords, personas, and host keys are
reported unsupported. Core files produce a report only; Telnet remains fully
unsupported.`
}

func (c *migrateCmd) Run(_ context.Context, args []string) error {
	if len(args) == 0 || args[0] != "beelzebub" {
		return Usagef("first argument must be 'beelzebub' (the only migration target)")
	}
	fs := newFlagSet("migrate beelzebub")
	addGlobalFlags(fs, &c.g)
	outDir := fs.String("out", "./migrated", "directory for generated configs (with --write)")
	write := fs.Bool("write", false, "write translated configs (default: dry-run)")
	force := fs.Bool("force", false, "allow overwriting generated files")
	// flag.Parse stops at the first positional argument, but operators write
	// `migrate beelzebub FILE --write` naturally. Peel off one positional per
	// pass so flags may appear anywhere.
	files := []string{}
	remaining := args[1:]
	for {
		if err := fs.Parse(remaining); err != nil {
			return Usagef("%v", err)
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		files = append(files, rest[0])
		remaining = rest[1:]
	}
	if len(files) == 0 {
		return Usagef("at least one source FILE is required")
	}

	results := make([]*beelzebub.Result, 0, len(files))
	var importErrs []error
	for _, f := range files {
		raw, err := os.ReadFile(f) //nolint:gosec // explicit operator-provided path
		if err != nil {
			importErrs = append(importErrs, fmt.Errorf("read %s: %v", f, err))
			continue
		}
		res, err := beelzebub.ImportFile(f, raw)
		if err != nil {
			importErrs = append(importErrs, err)
			continue
		}
		results = append(results, res)
	}

	report := map[string]any{
		"dry_run":      !*write,
		"sources":      len(files),
		"translatable": countSensors(results),
		"results":      results,
	}
	for _, e := range importErrs {
		fmt.Fprintln(c.env.Err, "error:", e)
	}
	if len(importErrs) > 0 {
		// Refusals (credential material, unreadable sources) must fail the
		// command: silent zero-exit migrations would let unsafe input slip
		// through CI unnoticed.
		return fmt.Errorf("%d of %d source file(s) could not be imported", len(importErrs), len(files))
	}

	emitBytes, emitErr := beelzebub.EmitConfig(results)
	if emitErr != nil && *write {
		return fmt.Errorf("nothing to write: %v", emitErr)
	}
	var validation string
	if emitErr == nil {
		validation = validateGenerated(emitBytes)
		report["generated_validation"] = validation
	} else {
		report["generated_validation"] = "skipped: " + emitErr.Error()
	}

	if !*write {
		if c.g.jsonOut {
			return writeJSON(c.env.Out, report)
		}
		c.renderHuman(report, results, validation)
		fmt.Fprintf(c.env.Err, "\ndry-run only; re-run with --write to create files under %s\n", *outDir)
		return nil
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return fmt.Errorf("create out dir: %v", err)
	}
	written := []string{}
	for _, f := range files {
		res := resultFor(results, f)
		if res == nil || res.Sensor == nil {
			continue
		}
		dst := filepath.Join(*outDir, beelzebub.EmittedName(f))
		if _, err := os.Stat(dst); err == nil && !*force {
			return fmt.Errorf("refusing to overwrite existing %s (pass --force)", dst)
		}
		b, err := beelzebub.EmitConfig([]*beelzebub.Result{res})
		if err != nil {
			return err
		}
		if err := os.WriteFile(dst, b, 0o644); err != nil { //nolint:gosec // generated config is meant to be reviewed/editable
			return fmt.Errorf("write %s: %v", dst, err)
		}
		written = append(written, dst)
	}
	report["written"] = written
	if c.g.jsonOut {
		return writeJSON(c.env.Out, report)
	}
	c.renderHuman(report, results, validation)
	for _, w := range written {
		fmt.Fprintf(c.env.Out, "wrote %s\n", w)
	}
	return nil
}

func countSensors(rs []*beelzebub.Result) int {
	n := 0
	for _, r := range rs {
		if r != nil && r.Sensor != nil {
			n++
		}
	}
	return n
}

func resultFor(rs []*beelzebub.Result, src string) *beelzebub.Result {
	base := filepath.Base(src)
	for _, r := range rs {
		if r.Source == base {
			return r
		}
	}
	return nil
}

// validateGenerated round-trips the emitted document through the strict loader
// so the report states plainly whether the result would run today.
func validateGenerated(b []byte) string {
	tmp, err := os.CreateTemp("", "aegismesh-migrate-*.yaml")
	if err != nil {
		return "error: " + err.Error()
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return "error: " + err.Error()
	}
	if err := tmp.Close(); err != nil {
		return "error: " + err.Error()
	}
	if _, err := config.Load(name); err != nil {
		return "FAIL: " + err.Error() + " — expected when privileged ports/public binds need an explicit decision"
	}
	return "ok: generated config passes strict validation"
}

func (c *migrateCmd) renderHuman(report map[string]any, results []*beelzebub.Result, validation string) {
	fmt.Fprintf(c.env.Out, "compatibility report (%d source(s), %d translatable)\n",
		report["sources"], report["translatable"])
	for _, r := range results {
		fmt.Fprintf(c.env.Out, "\n%s — detected: %s\n", r.Source, r.Detected)
		for _, m := range r.Mapped {
			fmt.Fprintf(c.env.Out, "  mapped        %s\n", m)
		}
		for _, u := range r.Unsupported {
			fmt.Fprintf(c.env.Out, "  unsupported   %s: %s\n", u.Path, u.Reason)
			if u.Note != "" {
				fmt.Fprintf(c.env.Out, "                  note: %s\n", u.Note)
			}
		}
		for _, n := range r.Notes {
			fmt.Fprintf(c.env.Out, "  note          %s\n", n)
		}
	}
	if validation != "" {
		fmt.Fprintf(c.env.Out, "\ngenerated config validation: %s\n", validation)
	}
}
