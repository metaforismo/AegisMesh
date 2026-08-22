package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/storage"
)

type inspectCmd struct {
	env *Env
	g   globals
}

func newInspectCmd(env *Env) *inspectCmd { return &inspectCmd{env: env} }

func (c *inspectCmd) Name() string  { return "inspect" }
func (c *inspectCmd) Usage() string { return "inspect <list|show|export> [flags]" }
func (c *inspectCmd) Help() string {
	return `Read and export recorded evidence.

  inspect list   --data-dir DIR [--limit N] [--sensor ID] [--kind KIND] [--verify]
  inspect show   --data-dir DIR --id EVENT_ID [--verify]
  inspect export --data-dir DIR --out FILE.ndjson [--verify]

Events are observations of decoy interactions — they are not incidents and do
not prove compromise. --verify recomputes each event's integrity hash while
reading; failures are reported per line and counted.`
}

func (c *inspectCmd) Run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return Usagef("choose a subcommand: list, show, or export")
	}
	switch args[0] {
	case "list":
		return c.list(args[1:])
	case "show":
		return c.show(args[1:])
	case "export":
		return c.export(args[1:])
	default:
		return Usagef("unknown inspect subcommand %q", args[0])
	}
}

func (c *inspectCmd) openReader(fs *flag.FlagSet, dataDir *string) (*storage.Reader, error) {
	if err := fs.Parse(nil); err != nil {
		return nil, err
	}
	if strings.TrimSpace(*dataDir) == "" {
		return nil, Usagef("--data-dir is required")
	}
	return storage.NewReader(*dataDir)
}

func (c *inspectCmd) list(args []string) error {
	fs := newFlagSet("inspect list")
	addGlobalFlags(fs, &c.g)
	dataDir := fs.String("data-dir", "./data", "evidence directory")
	limit := fs.Int("limit", 20, "max events to print")
	sensorID := fs.String("sensor", "", "filter by sensor id")
	kind := fs.String("kind", "", "filter by sensor kind (http|tcp|mcp)")
	verify := fs.Bool("verify", false, "recompute integrity hashes while reading")
	fs.Parse(args) //nolint:errcheck // rendered below on error
	r, err := storage.NewReader(*dataDir)
	if err != nil {
		return err
	}
	type row struct {
		Time           string `json:"time"`
		ID             string `json:"id"`
		Classification string `json:"classification"`
		Sensor         string `json:"sensor"`
		Kind           string `json:"kind"`
		IntegrityOK    *bool  `json:"integrity_ok,omitempty"`
	}
	var rows []row
	var corrupt int
	err = r.ForEach(func(e event.Envelope) error {
		if *sensorID != "" && e.Sensor.ID != *sensorID {
			return nil
		}
		if *kind != "" && e.Sensor.Kind != *kind {
			return nil
		}
		if len(rows) >= *limit {
			return nil
		}
		var okp *bool
		if *verify {
			ok := e.VerifyIntegrity() == nil
			okp = &ok
		}
		rows = append(rows, row{
			Time: e.Time.UTC().Format(timeLayout), ID: e.ID,
			Classification: e.Classification, Sensor: e.Sensor.ID,
			Kind: e.Sensor.Kind, IntegrityOK: okp,
		})
		return nil
	}, func(line string, cerr error) { corrupt++ })
	if err != nil {
		return err
	}
	if c.g.jsonOut {
		return writeJSON(c.env.Out, map[string]any{"events": rows, "corrupt_lines": corrupt})
	}
	if len(rows) == 0 {
		fmt.Fprintln(c.env.Out, "no events recorded yet")
		return nil
	}
	w := tabWriter(c.env.Out)
	fmt.Fprintf(w, "TIME\tID\tCLASS\tSENSOR\tKIND%s\n", verifyHeader(*verify))
	for _, rw := range rows {
		extra := ""
		if rw.IntegrityOK != nil {
			extra = fmt.Sprintf("\t%v", *rw.IntegrityOK)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s%s\n", rw.Time, short(rw.ID), rw.Classification, rw.Sensor, rw.Kind, extra)
	}
	w.Flush()
	if corrupt > 0 {
		fmt.Fprintf(c.env.Out, "\nwarning: %d corrupt line(s) skipped\n", corrupt)
	}
	return nil
}

func verifyHeader(v bool) string {
	if v {
		return "\tINTEGRITY"
	}
	return ""
}

func (c *inspectCmd) show(args []string) error {
	fs := newFlagSet("inspect show")
	addGlobalFlags(fs, &c.g)
	dataDir := fs.String("data-dir", "./data", "evidence directory")
	id := fs.String("id", "", "event id to display")
	verify := fs.Bool("verify", true, "verify this event's integrity hash")
	fs.Parse(args) //nolint:errcheck // see list()
	if strings.TrimSpace(*id) == "" {
		return Usagef("--id is required")
	}
	r, err := storage.NewReader(*dataDir)
	if err != nil {
		return err
	}
	var found *event.Envelope
	var matches int
	err = r.ForEach(func(e event.Envelope) error {
		if e.ID == *id || strings.HasPrefix(e.ID, *id) {
			matches++
			found = &e
			if e.ID == *id {
				return io.EOF // exact match wins; stop immediately
			}
		}
		return nil
	}, nil)
	if err != nil && err != io.EOF {
		return err
	}
	switch {
	case found == nil:
		return fmt.Errorf("no event with id %s in %s", *id, *dataDir)
	case matches > 1:
		return fmt.Errorf("id prefix %s is ambiguous (%d events); use a longer prefix", *id, matches)
	}
	integrityErr := error(nil)
	if *verify {
		integrityErr = found.VerifyIntegrity()
	}
	payload := map[string]any{
		"envelope": found,
		"verified": *verify && integrityErr == nil,
	}
	if integrityErr != nil {
		payload["integrity_error"] = integrityErr.Error()
	}
	return writeJSON(c.env.Out, payload)
}

func (c *inspectCmd) export(args []string) error {
	fs := newFlagSet("inspect export")
	addGlobalFlags(fs, &c.g)
	dataDir := fs.String("data-dir", "./data", "evidence directory")
	outPath := fs.String("out", "", "output NDJSON file ('-' for stdout)")
	verify := fs.Bool("verify", true, "refuse to export events failing integrity checks")
	fs.Parse(args) //nolint:errcheck // see list()
	if *outPath == "" {
		return Usagef("--out FILE.ndjson is required (or '-' for stdout)")
	}
	r, err := storage.NewReader(*dataDir)
	if err != nil {
		return err
	}
	var w io.Writer = os.Stdout
	if *outPath != "-" {
		f, ferr := os.Create(*outPath)
		if ferr != nil {
			return fmt.Errorf("create %s: %v", *outPath, ferr)
		}
		defer f.Close()
		w = f
	}
	count, bad := 0, 0
	err = r.ForEach(func(e event.Envelope) error {
		if *verify {
			if verr := e.VerifyIntegrity(); verr != nil {
				bad++
				fmt.Fprintf(c.env.Err, "skipping tampered/invalid event %s: %v\n", e.ID, verr)
				return nil
			}
		}
		count++
		line, merr := marshalLine(e)
		if merr != nil {
			bad++
			return nil
		}
		if _, werr := w.Write(append(line, '\n')); werr != nil {
			return werr
		}
		return nil
	}, nil)
	if err != nil {
		return err
	}
	if bad > 0 {
		fmt.Fprintf(c.env.Err, "warning: %d event(s) skipped during export\n", bad)
	}
	if c.g.jsonOut || *outPath != "-" {
		fmt.Fprintf(c.env.Err, "exported %d event(s)\n", count)
	} else if !c.g.jsonOut {
		fmt.Fprintf(c.env.Err, "exported %d event(s) to stdout\n", count)
	}
	return nil
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

const timeLayout = "15:04:05.000"

var (
	_ = context.Background
	_ = os.Exit
)
