package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/metaforismo/aegismesh/internal/eventexport"
)

func (c *exportCmd) events(ctx context.Context, args []string) error {
	var dir, format, since, out strictValueFlag
	var identities identityFilesFlag
	var sealed strictBoolFlag
	fs := newFlagSet("export events")
	fs.Var(&dir, "data-dir", "local evidence directory (required)")
	fs.Var(&format, "format", "cef, syslog-rfc5424, otlp-json or ecs (required)")
	fs.Var(&since, "since", "inclusive RFC3339 lower bound")
	fs.Var(&out, "out", "new output file; omitted writes stdout")
	fs.Var(&identities, "identity", "native age/X25519 identity file (repeatable)")
	fs.Var(&sealed, "require-sealed", "require final segment seals")
	if err := parseIdentityFlags(fs, args); err != nil {
		return Usagef("%v", err)
	}
	if fs.NArg() != 0 || len(dir.values) != 1 || len(format.values) != 1 || !eventexport.ValidFormat(format.String()) {
		return Usagef("export events requires --data-dir and --format cef|syslog-rfc5424|otlp-json|ecs")
	}
	if err := validateDataDir(dir.String()); err != nil {
		return Usagef("%v", err)
	}
	if len(out.values) > 0 && out.String() == "" {
		return Usagef("--out must name a new file")
	}
	var cutoff time.Time
	if len(since.values) > 0 {
		var err error
		cutoff, err = time.Parse(time.RFC3339, since.String())
		if err != nil {
			return Usagef("--since must be RFC3339")
		}
	}
	events, err := localEvidence(ctx, dir.String(), identities, sealed.Value(), c.env.Err)
	if err != nil {
		return err
	}
	records := []eventexport.Record{}
	for _, e := range events {
		if !e.Time.Before(cutoff) {
			records = append(records, eventexport.Record{
				Envelope: e,
				NodeID:   "local",
			})
		}
	}
	body, err := eventexport.Render(records, format.String())
	if err != nil {
		return err
	}
	fmt.Fprintf(c.env.Err, "scanned %d event(s); selected %d\n", len(events), len(records))
	return writeLocalOutput(c.env.Out, out.String(), body)
}
