package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/metaforismo/aegismesh/internal/console"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/evidenceview"
)

// cliNow is the CLI's clock; tests replace it for deterministic golden output.
var cliNow = time.Now

var campaignIDFlag = regexp.MustCompile(`^cmp_[0-9a-f]{12}$`)

type campaignsCmd struct{ env *Env }

// NewCampaignsCmd constructs the local campaign grouping command.
func NewCampaignsCmd(env *Env) Command { return &campaignsCmd{env: env} }
func (c *campaignsCmd) Name() string   { return "campaigns" }
func (c *campaignsCmd) Usage() string {
	return "campaigns --data-dir DIR [--id cmp_ID] [--identity FILE ...] [--require-sealed] [--json]"
}
func (c *campaignsCmd) Help() string {
	return `Group local sessions from different sources that followed the same steps.

  campaigns --data-dir ./data
  campaigns --data-dir ./data --id cmp_3f9a1c2b7d10 --json

Reads at most 8192 verified envelopes (failing closed on larger input), builds
sessions exactly as the console does, normalises each session's steps into
redacted shapes and groups sessions from at least two source keys whose first
eight collapsed steps match (exact match for shorter sequences, at least three
steps). A campaign is shared behaviour, not proof of a shared operator.
Shapes are attacker-influenced text. Campaign IDs here use the tenant "local"
and therefore differ from console IDs for the same evidence.
--id prints one campaign with its representative steps; unknown IDs exit 1.`
}

func (c *campaignsCmd) Run(ctx context.Context, args []string) error {
	var dir, id strictValueFlag
	var jsonOut, sealed strictBoolFlag
	var identities identityFilesFlag
	fs := newFlagSet(c.Name())
	fs.Var(&dir, "data-dir", "local evidence directory (required)")
	fs.Var(&id, "id", "show one campaign (cmp_ + 12 hex)")
	fs.Var(&jsonOut, "json", "emit machine-readable JSON output")
	fs.Var(&sealed, "require-sealed", "require final segment seals")
	fs.Var(&identities, "identity", "native age/X25519 identity file (repeatable)")
	if err := parseIdentityFlags(fs, args); err != nil {
		return Usagef("%v", err)
	}
	if fs.NArg() != 0 {
		return Usagef("unexpected argument %q (campaigns takes flags only)", fs.Arg(0))
	}
	if len(dir.values) != 1 {
		return Usagef("--data-dir is required")
	}
	if err := validateDataDir(dir.values[0]); err != nil {
		return Usagef("%v", err)
	}
	if len(id.values) == 1 && !campaignIDFlag.MatchString(id.values[0]) {
		return Usagef("--id must be cmp_ followed by 12 lowercase hex characters")
	}
	envelopes, err := localEvidence(ctx, dir.values[0], identities, sealed.Value(), c.env.Err)
	if err != nil {
		return err
	}
	snapshot := localSnapshot(envelopes)
	set := evidenceview.Campaigns("local", evidenceview.Sessions("local", snapshot.Events))
	now := cliNow()
	var out bytes.Buffer
	if len(id.values) == 0 {
		list := console.ListCampaigns(set, snapshot, now)
		if jsonOut.Value() {
			err = writeJSON(&out, list)
		} else {
			writeCampaignsHuman(&out, list)
		}
	} else {
		var detail *evidenceview.CampaignDetail
		for _, campaign := range set.Campaigns {
			if campaign.ID == id.values[0] {
				d := campaign.Detail()
				detail = &d
			}
		}
		if detail == nil {
			return fmt.Errorf("campaign %s is not present in the analysed evidence", id.values[0])
		}
		if jsonOut.Value() {
			err = writeJSON(&out, struct {
				evidenceview.CampaignDetail
				GeneratedAt string                 `json:"generated_at"`
				Bounds      evidenceindex.Snapshot `json:"bounds"`
			}{*detail, now.UTC().Format(time.RFC3339Nano), snapshot})
		} else {
			writeCampaignDetailHuman(&out, *detail)
		}
	}
	if err != nil {
		return err
	}
	_, err = c.env.Out.Write(out.Bytes())
	return err
}

// localSnapshot projects verified local envelopes newest first, as the console index does.
func localSnapshot(envelopes []event.Envelope) evidenceindex.Snapshot {
	sorted := append([]event.Envelope{}, envelopes...)
	sort.Slice(sorted, func(i, j int) bool {
		if !sorted[i].Time.Equal(sorted[j].Time) {
			return sorted[i].Time.After(sorted[j].Time)
		}
		return sorted[i].ID < sorted[j].ID
	})
	snapshot := evidenceindex.Snapshot{
		Events:  []evidenceindex.Summary{},
		Index:   evidenceindex.Stats{Events: len(sorted), Capacity: evidenceindex.AnalysisLimit, History: "unavailable"},
		Scanned: min(len(sorted), evidenceindex.AnalysisLimit),
		Limit:   evidenceindex.AnalysisLimit, Truncated: len(sorted) > evidenceindex.AnalysisLimit,
	}
	if len(sorted) > 0 {
		snapshot.Index.Oldest = sorted[len(sorted)-1].Time.UTC().Format(time.RFC3339Nano)
	}
	for _, e := range sorted[:snapshot.Scanned] {
		summary, _, _ := evidenceindex.Project(e)
		snapshot.Events = append(snapshot.Events, summary)
	}
	return snapshot
}

func writeCampaignsHuman(w io.Writer, list console.CampaignList) {
	fmt.Fprintf(w, "CAMPAIGNS: %d (scanned %d sessions; shared behaviour, not attribution)\n", list.TotalCampaigns, list.ScannedSessions)
	if list.Truncated {
		fmt.Fprintln(w, "note: output or session scan was capped; older or extra campaigns are not shown")
	}
	for _, c := range list.Items {
		fmt.Fprintf(w, "\n%s  %s\n", c.ID, c.Label)
		fmt.Fprintf(w, "  basis: %s\n", strings.Join(c.Basis, ", "))
		fmt.Fprintf(w, "  sources: %d (%s)  sessions: %d  events: %d\n", c.SourceCount, strings.Join(c.Sources, ", "), c.SessionCount, c.EventCount)
		fmt.Fprintf(w, "  seen: %s .. %s\n", c.FirstSeen, c.LastSeen)
		fmt.Fprintf(w, "  severity: %s  stages: %s  rules: %s\n", dash(c.MaxSeverity), dash(strings.Join(c.Stages, ", ")), dash(strings.Join(c.RuleIDs, ", ")))
	}
}

func writeCampaignDetailHuman(w io.Writer, d evidenceview.CampaignDetail) {
	fmt.Fprintf(w, "CAMPAIGN %s  %s\n", d.ID, d.Label)
	fmt.Fprintf(w, "basis: %s\nsources: %d (%s)\n\nsteps (shapes are attacker-influenced text):\n", strings.Join(d.Basis, ", "), d.SourceCount, strings.Join(d.Sources, ", "))
	for _, s := range d.Steps {
		fmt.Fprintf(w, "  %2d  %-4s %-26s %d/%d  %s\n", s.Index, s.SensorKind, s.Stage, s.Sessions, d.SessionCount, s.Shape)
	}
	fmt.Fprintln(w, "\nsessions:")
	for _, s := range d.Sessions {
		fmt.Fprintf(w, "  %s  %-15s %d events  actor: %s\n", s.ID, s.Source, s.EventCount, s.Actor.Assessment)
	}
	fmt.Fprintln(w, "\ncaveats:")
	for _, caveat := range d.Caveats {
		fmt.Fprintf(w, "  - %s\n", caveat)
	}
}

func dash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
