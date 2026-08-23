package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/metaforismo/aegismesh/internal/detect"
	"github.com/metaforismo/aegismesh/internal/ecsexport"
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

  inspect list   --data-dir DIR [--limit N] [--sensor ID] [--kind KIND] [--finding RULE_ID] [--classification CLASS] [--verify]
  inspect show   --data-dir DIR --id EVENT_ID [--verify]
  inspect export --data-dir DIR --out FILE.ndjson [--profile ecs] [--verify]

Events are observations of decoy interactions — they are not incidents and do
not prove compromise. --verify recomputes each event's integrity hash while
reading; failures are reported per line and counted. --finding filters to
events where the named detection rule fired (e.g. --finding PI-001).
--classification filters to exactly one evidence class (interaction,
canary_invocation, correlation_signal); it applies before --limit, so
--limit N caps matching rows. Export keeps the native envelope by default;
--profile ecs emits the documented ECS-compatible mapping while preserving
the complete native envelope under the aegismesh field.`
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
	finding := fs.String("finding", "", "only events where this detection rule id fired (e.g. PI-001)")
	var class singleValueFlag
	fs.Var(&class, "classification", "filter to one evidence class (interaction|canary_invocation|correlation_signal)")
	verify := fs.Bool("verify", false, "recompute integrity hashes while reading")
	if err := fs.Parse(args); err != nil {
		return Usagef("%v", err)
	}
	if fs.NArg() > 0 {
		return Usagef("unexpected argument %q (inspect list takes flags only)", fs.Arg(0))
	}
	classification := ""
	if len(class.values) > 1 {
		return Usagef("--classification given %d times; pass it at most once (want %s)",
			len(class.values), strings.Join(eventClassifications, "|"))
	}
	if len(class.values) == 1 {
		classification = class.values[0]
		if !isValidClassification(classification) {
			return Usagef("unknown classification %q (want %s)", classification, strings.Join(eventClassifications, "|"))
		}
	}
	if *finding != "" {
		if err := detect.ValidateRuleIDs([]string{*finding}); err != nil {
			return Usagef("%v", err)
		}
	}
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
		if *finding != "" && !observationHasFinding(e.Observation, *finding) {
			return nil
		}
		if classification != "" && e.Classification != classification {
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
	if err := fs.Parse(args); err != nil {
		return Usagef("%v", err)
	}
	if fs.NArg() > 0 {
		return Usagef("unexpected argument %q (inspect show takes flags only)", fs.Arg(0))
	}
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
	var profile singleValueFlag
	fs.Var(&profile, "profile", "export mapping profile (ecs)")
	verify := fs.Bool("verify", true, "refuse to export events failing integrity checks")
	if err := fs.Parse(args); err != nil {
		return Usagef("%v", err)
	}
	if fs.NArg() > 0 {
		return Usagef("unexpected argument %q (inspect export takes flags only)", fs.Arg(0))
	}
	if strings.TrimSpace(*outPath) == "" {
		return Usagef("--out FILE.ndjson is required (or '-' for stdout)")
	}
	if len(profile.values) > 1 {
		return Usagef("--profile given %d times; pass it at most once (want ecs)", len(profile.values))
	}
	profileName := ""
	if len(profile.values) == 1 {
		profileName = profile.values[0]
		if profileName != "ecs" {
			return Usagef("unknown export profile %q (want ecs)", profileName)
		}
	}
	r, err := storage.NewReader(*dataDir)
	if err != nil {
		return err
	}
	tempDir := os.TempDir()
	if *outPath != "-" {
		tempDir = filepath.Dir(*outPath)
	}
	staged, err := os.CreateTemp(tempDir, ".aegismesh-export-*")
	if err != nil {
		return fmt.Errorf("stage export: %v", err)
	}
	stagedPath := staged.Name()
	defer os.Remove(stagedPath)
	defer staged.Close()

	count, bad := 0, 0
	err = r.ForEach(func(e event.Envelope) error {
		if *verify {
			if verr := e.VerifyIntegrity(); verr != nil {
				bad++
				fmt.Fprintf(c.env.Err, "skipping tampered/invalid event %s: %v\n", e.ID, verr)
				return nil
			}
		}
		var line []byte
		var merr error
		if profileName == "ecs" {
			line, merr = ecsexport.Marshal(e)
		} else {
			line, merr = marshalLine(e)
		}
		if merr != nil {
			bad++
			return nil
		}
		if _, werr := staged.Write(append(line, '\n')); werr != nil {
			return werr
		}
		count++
		return nil
	}, func(_ string, _ error) { bad++ })
	if err != nil {
		return err
	}
	if *verify && bad > 0 {
		return fmt.Errorf("integrity verification failed for %d event(s); output was not changed", bad)
	}
	if bad > 0 {
		fmt.Fprintf(c.env.Err, "warning: %d event(s) skipped during export\n", bad)
	}
	if err := staged.Sync(); err != nil {
		return fmt.Errorf("sync staged export: %v", err)
	}
	if *outPath == "-" {
		if _, err := staged.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("rewind staged export: %v", err)
		}
		if _, err := io.Copy(c.env.Out, staged); err != nil {
			return fmt.Errorf("write export to stdout: %v", err)
		}
	} else {
		if err := staged.Close(); err != nil {
			return fmt.Errorf("close staged export: %v", err)
		}
		if err := os.Rename(stagedPath, *outPath); err != nil {
			return fmt.Errorf("replace %s: %v", *outPath, err)
		}
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

// eventClassifications is derived from the owning constants in internal/event
// so this filter cannot drift from the classifications envelopes validate.
// Order here is the deterministic order used in every error message.
var eventClassifications = []string{
	event.ClassificationInteraction,
	event.ClassificationCanaryHit,
	event.ClassificationCorrelationSignal,
}

func isValidClassification(v string) bool {
	for _, c := range eventClassifications {
		if v == c {
			return true
		}
	}
	return false
}

type singleValueFlag struct{ values []string }

func (f *singleValueFlag) String() string {
	if len(f.values) == 0 {
		return ""
	}
	return f.values[len(f.values)-1]
}

func (f *singleValueFlag) Set(v string) error { f.values = append(f.values, v); return nil }

// observationHasFinding reports whether an observation payload carries a
// detection finding with the given rule id. Unknown observation shapes simply
// do not match — evidence from older versions stays readable.
func observationHasFinding(obs json.RawMessage, ruleID string) bool {
	var probe struct {
		Detection *struct {
			Findings []struct {
				RuleID string `json:"rule_id"`
			} `json:"findings"`
		} `json:"detection"`
	}
	if json.Unmarshal(obs, &probe) != nil || probe.Detection == nil {
		return false
	}
	for _, f := range probe.Detection.Findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}
