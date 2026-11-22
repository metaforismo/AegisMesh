package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"github.com/metaforismo/aegismesh/internal/console/investigations"
	"github.com/metaforismo/aegismesh/internal/digest"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/recommend"
)

type digestCmd struct{ env *Env }

// NewDigestCmd constructs the on-demand local periodic summary command.
func NewDigestCmd(env *Env) Command { return &digestCmd{env: env} }
func (c *digestCmd) Name() string   { return "digest" }
func (c *digestCmd) Usage() string {
	return "digest --since 24h|7d [--data-dir DIR] [--format md|json] [--investigations-dir DIR] [--identity FILE ...] [--require-sealed]"
}
func (c *digestCmd) Help() string {
	return `Summarise retained local observations against the preceding equal window.

  digest --since 24h --data-dir ./data --format md

On demand only: no scheduler, delivery or egress. Reads at most 8192 verified
envelopes, failing closed on larger input. Recommendations use up to 4096
current-window local events and at most 20 proposals. Open investigations are
read without writes from --investigations-dir (the directory containing
investigations.json); default: DATA/console/tenants/default. Missing directories
produce null and an explicit availability limit, not a zero count.
--format defaults to md. --data-dir defaults to ./data.`
}
func (c *digestCmd) Run(ctx context.Context, args []string) error {
	var since, format, dir, state strictValueFlag
	var identities identityFilesFlag
	var sealed strictBoolFlag
	fs := newFlagSet("digest")
	fs.Var(&since, "since", "24h or 7d (required)")
	fs.Var(&format, "format", "md or json")
	fs.Var(&dir, "data-dir", "local evidence directory")
	fs.Var(&state, "investigations-dir", "operator-selected investigation snapshot directory")
	fs.Var(&identities, "identity", "native age/X25519 identity file (repeatable)")
	fs.Var(&sealed, "require-sealed", "require final segment seals")
	if err := parseIdentityFlags(fs, args); err != nil {
		return Usagef("%v", err)
	}
	duration, err := digest.Window(since.String())
	if err != nil || fs.NArg() != 0 {
		return Usagef("digest requires --since 24h|7d and flags only")
	}
	encoding := format.String()
	if len(format.values) == 0 {
		encoding = "md"
	}
	if encoding != "md" && encoding != "json" {
		return Usagef("--format must be md or json")
	}
	dataDir := dir.String()
	if len(dir.values) == 0 {
		dataDir = "./data"
	}
	if err := validateDataDir(dataDir); err != nil {
		return Usagef("%v", err)
	}
	stateDir := state.String()
	if len(state.values) == 0 {
		stateDir = filepath.Join(dataDir, "console", "tenants", "default")
	}
	if stateDir == "" {
		return Usagef("--investigations-dir must not be empty")
	}
	events, err := localEvidence(ctx, dataDir, identities, sealed.Value(), c.env.Err)
	if err != nil {
		return err
	}
	sort.Slice(events, func(i, j int) bool {
		if !events[i].Time.Equal(events[j].Time) {
			return events[i].Time.After(events[j].Time)
		}
		return events[i].ID < events[j].ID
	})
	now := time.Now().UTC()
	snapshot := evidenceindex.Snapshot{
		Events: []evidenceindex.Summary{},
		Index: evidenceindex.Stats{
			Events:   len(events),
			Capacity: evidenceindex.AnalysisLimit,
			History:  "unavailable",
		},
		Scanned: len(events),
		Limit:   evidenceindex.AnalysisLimit,
	}
	if len(events) > 0 {
		snapshot.Index.Oldest = events[len(events)-1].Time.UTC().Format(time.RFC3339Nano)
	}
	local := []event.Envelope{}
	excluded := 0
	for _, e := range events {
		summary, _, _ := evidenceindex.Project(e)
		snapshot.Events = append(snapshot.Events, summary)
		if !e.Time.Before(now.Add(-duration)) && e.Time.Before(now) {
			if len(local) < recommend.MaxEvidence {
				local = append(local, e)
			} else {
				excluded++
			}
		}
	}
	proposals, err := recommend.Generate(local, recommend.Options{Limit: 20})
	if err != nil {
		return err
	}
	open, err := investigations.ReadOpenCount(stateDir)
	if err != nil {
		return fmt.Errorf("digest investigation snapshot: %w", err)
	}
	report, err := digest.Build(digest.Input{
		Tenant:                 "local",
		Window:                 since.String(),
		AsOf:                   now,
		Bounds:                 snapshot,
		OpenInvestigations:     open,
		Recommendations:        len(proposals.Recommendations),
		RecommendationExcluded: excluded,
	})
	if err != nil {
		return err
	}
	body, err := digest.Render(report, encoding)
	if err != nil {
		return err
	}
	_, err = c.env.Out.Write(body)
	return err
}
