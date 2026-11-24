package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console"
	"github.com/metaforismo/aegismesh/internal/console/settings"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/posture"
)

type postureCmd struct{ env *Env }

// NewPostureCmd constructs the static configuration and evidence review command.
func NewPostureCmd(env *Env) Command { return &postureCmd{env: env} }
func (c *postureCmd) Name() string   { return "posture" }
func (c *postureCmd) Usage() string {
	return "posture --config FILE [--data-dir DIR] [--identity FILE ...] [--json]"
}
func (c *postureCmd) Help() string {
	return `Review the validated configuration and retained evidence with fixed checks.

  posture --config mesh.yaml
  posture --config mesh.yaml --json

Runs checks POS-001..POS-022 (exposure, access, deception, detection,
evidence) over a secret-free snapshot of the config and the newest 8192
verified local envelopes in --data-dir (default: the config's runtime.data_dir).
When console.settings_editing is console, risks accepted in the console are
read (never written) from the console state directory and shown as
"accepted"; if that state cannot be read the review says so and shows the
checks unaccepted. Managed accounts are not read offline.
If evidence cannot be read (missing directory, encryption without --identity,
corrupt lines), evidence checks report "Not evaluated" instead of failing.
Advisory only: it starts, contacts and changes nothing, and a clean review is
not a security guarantee. Exit codes: 0 review printed (whatever the
statuses), 1 config or output failure, 2 invalid arguments.`
}

func (c *postureCmd) Run(_ context.Context, args []string) error {
	var configPath, dataDir strictValueFlag
	var jsonOut strictBoolFlag
	var identities identityFilesFlag
	fs := newFlagSet(c.Name())
	fs.Var(&configPath, "config", "path to mesh.yaml (required)")
	fs.Var(&dataDir, "data-dir", "evidence directory (default: runtime.data_dir)")
	fs.Var(&jsonOut, "json", "emit machine-readable JSON output")
	fs.Var(&identities, "identity", "native age/X25519 identity file (repeatable)")
	if err := parseIdentityFlags(fs, args); err != nil {
		return Usagef("%v", err)
	}
	if fs.NArg() != 0 {
		return Usagef("unexpected argument %q (posture takes flags only)", fs.Arg(0))
	}
	if len(configPath.values) != 1 || configPath.values[0] == "" {
		return Usagef("--config is required")
	}
	cfg, err := loadConfig(configPath.values[0])
	if err != nil {
		return err
	}
	dir := cfg.Runtime.DataDir
	if len(dataDir.values) == 1 {
		if err := validateDataDir(dataDir.values[0]); err != nil {
			return Usagef("%v", err)
		}
		dir = dataDir.values[0]
	}
	facts := console.PostureFacts(cfg)
	evidence := c.readEvidence(dir, identities)
	report := posture.Evaluate(&facts, evidence, cliNow())
	note := ""
	if cfg.Console.WithDefaults().SettingsEditing != config.SettingsEditingConsole {
		report = posture.Accept(report, nil)
		note = "none (console.settings_editing is off)"
	} else if accepted, err := settings.ReadAccepted(filepath.Join(cfg.ConsoleStateDir(), "settings"), cliNow()); err != nil {
		reason := "unreadable or invalid"
		if errors.Is(err, os.ErrNotExist) {
			reason = "not found"
		}
		note = "could not read console state (" + reason + "); checks are shown unaccepted"
	} else {
		applied := map[string]posture.Acceptance{}
		for id, acceptance := range accepted {
			applied[id] = posture.Acceptance{By: acceptance.By, ByName: acceptance.ByName, Reason: acceptance.Reason,
				Until: acceptance.Until.UTC().Format(time.RFC3339)}
		}
		report = posture.Accept(report, applied)
		note = fmt.Sprintf("%d read from console state", len(applied))
	}
	var out bytes.Buffer
	if jsonOut.Value() {
		if err := writeJSON(&out, report); err != nil {
			return err
		}
	} else {
		writePostureHuman(&out, report, note)
	}
	_, err = c.env.Out.Write(out.Bytes())
	return err
}

// readEvidence keeps only the newest AnalysisLimit projected summaries, like the
// console's analysis snapshot, so large directories are reviewed rather than refused.
func (c *postureCmd) readEvidence(dir string, identities identityFilesFlag) posture.Evidence {
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return posture.Unavailable("the evidence directory does not exist yet.")
	}
	reader, err := identities.openReader(dir, false)
	if err != nil {
		fmt.Fprintf(c.env.Err, "posture: evidence not read: %v\n", err)
		return posture.Unavailable("evidence could not be opened (encrypted evidence needs --identity).")
	}
	type item struct {
		summary evidenceindex.Summary
		envelope
	}
	ring := []item{}
	total, corrupt := 0, 0
	notices, err := reader.ForEachVerified(func(e event.Envelope) error {
		if e.Validate() != nil || e.VerifyIntegrity() != nil || !evidenceindex.ValidID(e.ID) {
			corrupt++
			return nil
		}
		summary, _, _ := evidenceindex.Project(e)
		ring = append(ring, item{summary, envelope{e.Time.UnixNano(), e.ID}})
		total++
		if len(ring) > 2*evidenceindex.AnalysisLimit {
			ring = newest(ring, func(a, b item) bool { return a.envelope.newer(b.envelope) })
		}
		return nil
	}, func(_ string, _ error) { corrupt++ })
	reportOpenSegments(c.env.Err, notices)
	if err != nil {
		fmt.Fprintf(c.env.Err, "posture: evidence not read: %v\n", err)
		return posture.Unavailable("evidence could not be read (encrypted evidence needs --identity).")
	}
	if corrupt > 0 {
		return posture.Unavailable(fmt.Sprintf("%d malformed or unverifiable evidence line(s); run 'aegismesh inspect list --verify'.", corrupt))
	}
	ring = newest(ring, func(a, b item) bool { return a.envelope.newer(b.envelope) })
	snapshot := evidenceindex.Snapshot{Limit: evidenceindex.AnalysisLimit, Truncated: total > evidenceindex.AnalysisLimit}
	for _, entry := range ring {
		snapshot.Events = append(snapshot.Events, entry.summary)
	}
	return posture.FromSnapshot(snapshot)
}

type envelope struct {
	nanos int64
	id    string
}

func (a envelope) newer(b envelope) bool {
	if a.nanos != b.nanos {
		return a.nanos > b.nanos
	}
	return a.id < b.id
}

// newest sorts newest first and keeps at most AnalysisLimit entries.
func newest[T any](items []T, less func(a, b T) bool) []T {
	sort.Slice(items, func(i, j int) bool { return less(items[i], items[j]) })
	return items[:min(len(items), evidenceindex.AnalysisLimit)]
}

func writePostureHuman(w io.Writer, r posture.Report, note string) {
	fmt.Fprintf(w, "POSTURE REVIEW: %d attention, %d ok, %d info, %d accepted\n%s\naccepted risks: %s\n",
		r.Summary.Attention, r.Summary.OK, r.Summary.Info, r.Summary.Accepted, r.Disclaimer, note)
	for _, c := range r.Checks {
		fmt.Fprintf(w, "\n%s  %-9s  %-9s  %s\n", c.ID, c.Status, c.Area, c.Title)
		fmt.Fprintf(w, "         %s\n", c.Detail)
		if c.Accepted != nil {
			fmt.Fprintf(w, "         accepted by %s until %s: %s\n", c.Accepted.By, c.Accepted.Until, c.Accepted.Reason)
		}
		if c.Recommendation != "" {
			fmt.Fprintf(w, "         -> %s\n", c.Recommendation)
		}
		fmt.Fprintf(w, "         see %s\n", c.Doc)
	}
	if strings.TrimSpace(r.GeneratedAt) != "" {
		fmt.Fprintf(w, "\ngenerated at %s\n", r.GeneratedAt)
	}
}
