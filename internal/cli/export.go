package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/indicatorexport"
)

type exportCmd struct{ env *Env }

// NewExportCmd constructs local, verified indicator downloads to stdout.
func NewExportCmd(env *Env) Command { return &exportCmd{env: env} }

func (c *exportCmd) Name() string { return "export" }

func (c *exportCmd) Usage() string {
	return "export indicators --data-dir DIR --format stix|csv|txt [--since RFC3339] [--identity FILE ...] [--require-sealed]"
}

func (c *exportCmd) Help() string {
	return `Export proposed IP indicators from verified local evidence to stdout.

  export indicators --data-dir DIR --format stix [--since RFC3339]
  export indicators --data-dir DIR --format txt [--identity FILE ...] [--require-sealed]

Decoy contact is an observation, not an incident. Low confidence (15/100).
TXT is a PROPOSED blocklist for operator review, never applied by AegisMesh.
Non-IP source keys are skipped and counted on stderr. No network requests.
Every input event is verified before output. At most 8192 events are read,
including events older than --since; exports exceeding 2 MiB fail closed.
Open encrypted v3 segments expose checkpoint prefixes with stderr notices;
--require-sealed requires completeness. Exit codes: 0 success (possibly
incomplete), 1 read/output/size failure, 2 invalid arguments.`
}

func (c *exportCmd) Run(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "indicators" {
		return Usagef("choose export indicators")
	}
	var dataDir, format, since strictValueFlag
	var identities identityFilesFlag
	var requireSealed strictBoolFlag
	fs := newFlagSet("export indicators")
	fs.Var(&dataDir, "data-dir", "evidence directory (required)")
	fs.Var(&format, "format", "stix, csv or txt (required)")
	fs.Var(&since, "since", "inclusive RFC3339 lower time bound")
	fs.Var(&identities, "identity", "native age/X25519 identity file (repeatable)")
	fs.Var(&requireSealed, "require-sealed", "require final segment seals")
	if err := parseIdentityFlags(fs, args[1:]); err != nil {
		return Usagef("%v", err)
	}
	if fs.NArg() != 0 || len(dataDir.values) != 1 || len(format.values) != 1 {
		return Usagef("export indicators requires --data-dir and --format, with flags only")
	}
	if err := validateDataDir(dataDir.String()); err != nil {
		return Usagef("%v", err)
	}
	if format.String() != "stix" && format.String() != "csv" && format.String() != "txt" {
		return Usagef("--format must be stix, csv or txt")
	}
	var cutoff time.Time
	if len(since.values) > 0 {
		var err error
		cutoff, err = time.Parse(time.RFC3339, since.String())
		if err != nil {
			return Usagef("--since must be RFC3339")
		}
	}
	reader, err := identities.openReader(dataDir.String(), requireSealed.Value())
	if err != nil {
		return err
	}
	events := []evidenceindex.Summary{}
	read, corrupt := 0, 0
	instances := map[string]bool{}
	notices, err := reader.ForEachVerified(func(e event.Envelope) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		read++
		if read > indicatorexport.MaxEvents {
			return indicatorexport.ErrLimit
		}
		if e.Validate() != nil || e.VerifyIntegrity() != nil || !evidenceindex.ValidID(e.ID) || len(e.Instance) > 64 {
			return fmt.Errorf("indicator read failed closed: invalid envelope or integrity")
		}
		if !e.Time.Before(cutoff) {
			summary, _, _ := evidenceindex.Project(e)
			events = append(events, summary)
			instances[e.Instance] = true
		}
		return nil
	}, func(_ string, _ error) { corrupt++ })
	if err != nil {
		return err
	}
	if corrupt > 0 {
		return fmt.Errorf("indicator read failed closed: %d malformed JSON line(s)", corrupt)
	}
	// Local native instance labels define the deterministic identity namespace.
	// Hash the sorted set through the same rule-independent ordering every time.
	instanceNames := make([]string, 0, len(instances))
	for instance := range instances {
		instanceNames = append(instanceNames, instance)
	}
	identity := localExportIdentity(instanceNames)
	body, result, err := indicatorexport.Render(events, format.String(), identity)
	if err != nil {
		return err
	}
	reportOpenSegments(c.env.Err, notices)
	fmt.Fprintf(c.env.Err, "scanned %d event(s); selected %d; skipped non-IP source keys: %d; events: %d\n", read, len(events), result.SkippedSource, result.SkippedEvents)
	_, err = c.env.Out.Write(body)
	return err
}

func localExportIdentity(names []string) string {
	// Length-delimited names cannot collide through string concatenation.
	sort.Strings(names)
	hash := sha256.New()
	for _, name := range names {
		fmt.Fprintf(hash, "%d:%s", len(name), name)
	}
	return "local:" + hex.EncodeToString(hash.Sum(nil))
}
