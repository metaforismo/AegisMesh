package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/recommend"
	"github.com/metaforismo/aegismesh/internal/storage"
)

type recommendCmd struct {
	env *Env
}

func newRecommendCmd(env *Env) *recommendCmd { return &recommendCmd{env: env} }

func (c *recommendCmd) Name() string { return "recommend" }

func (c *recommendCmd) Usage() string {
	return "recommend --data-dir DIR [--limit N] [--rule RULE_ID] [--sensor ID] [--classification CLASS] [--json]"
}

func (c *recommendCmd) Help() string {
	return `Generate deterministic, dry-run operator recommendations from recorded evidence.

  recommend --data-dir DIR
  recommend --data-dir DIR --rule PI-001 --limit 10
  recommend --data-dir DIR --classification correlation_signal --json

Every evidence line is read and verified before output is written. Recommendations
are proposed review signals, not incidents and never perform enforcement, network
requests, process execution, credential changes, or other production mutation.
The native event observation is never copied into output; each recommendation
contains exact event IDs and verified observation payload hashes instead.`
}

func (c *recommendCmd) Run(_ context.Context, args []string) error {
	var dataDir strictValueFlag
	var limit strictValueFlag
	var ruleID strictValueFlag
	var sensorID strictValueFlag
	var classification strictValueFlag
	var jsonOut strictBoolFlag

	fs := newFlagSet(c.Name())
	fs.Var(&dataDir, "data-dir", "evidence directory (required)")
	fs.Var(&limit, "limit", "maximum recommendations (1..1000; default 20)")
	fs.Var(&ruleID, "rule", "filter by exact rule id")
	fs.Var(&sensorID, "sensor", "filter by exact sensor id")
	fs.Var(&classification, "classification", "filter by evidence class")
	fs.Var(&jsonOut, "json", "emit machine-readable JSON output")

	if err := fs.Parse(args); err != nil {
		return Usagef("%v", err)
	}
	if fs.NArg() > 0 {
		return Usagef("unexpected argument %q (recommend takes flags only)", fs.Arg(0))
	}
	if len(dataDir.values) != 1 {
		return Usagef("--data-dir is required")
	}
	if err := validateDataDir(dataDir.values[0]); err != nil {
		return Usagef("%v", err)
	}

	options := recommend.Options{Limit: recommend.DefaultLimit}
	if len(limit.values) == 1 {
		parsed, err := parseRecommendLimit(limit.values[0])
		if err != nil {
			return Usagef("%v", err)
		}
		options.Limit = parsed
	}
	if len(ruleID.values) == 1 {
		if err := validateExactFilter("--rule", ruleID.values[0]); err != nil {
			return Usagef("%v", err)
		}
		options.RuleID = ruleID.values[0]
	}
	if len(sensorID.values) == 1 {
		if err := validateExactFilter("--sensor", sensorID.values[0]); err != nil {
			return Usagef("%v", err)
		}
		options.SensorID = sensorID.values[0]
	}
	if len(classification.values) == 1 {
		if err := validateExactFilter("--classification", classification.values[0]); err != nil {
			return Usagef("%v", err)
		}
		options.Classification = classification.values[0]
	}
	if err := options.Validate(); err != nil {
		return Usagef("%v", err)
	}

	reader, err := storage.NewReader(dataDir.values[0])
	if err != nil {
		return err
	}
	events := make([]event.Envelope, 0, recommend.MaxEvidence)
	corrupt := 0
	err = reader.ForEach(func(e event.Envelope) error {
		if len(events) >= recommend.MaxEvidence {
			return fmt.Errorf("evidence read failed closed: more than %d events", recommend.MaxEvidence)
		}
		if err := recommend.ValidateEnvelope(e); err != nil {
			return fmt.Errorf("evidence read failed closed: invalid envelope")
		}
		events = append(events, e)
		return nil
	}, func(_ string, _ error) {
		corrupt++
	})
	if err != nil {
		return err
	}
	if corrupt > 0 {
		return fmt.Errorf("evidence read failed closed: %d malformed JSON line(s)", corrupt)
	}
	report, err := recommend.Generate(events, options)
	if err != nil {
		return fmt.Errorf("recommendation generation failed closed: %w", err)
	}

	var output bytes.Buffer
	if jsonOut.Value() {
		if err := writeJSON(&output, report); err != nil {
			return err
		}
	} else {
		writeRecommendationHuman(&output, report)
	}
	_, err = io.Copy(c.env.Out, &output)
	return err
}

func validateDataDir(value string) error {
	if value == "" || strings.TrimSpace(value) == "" {
		return fmt.Errorf("--data-dir must not be empty or whitespace")
	}
	if strings.TrimSpace(value) != value || strings.HasPrefix(value, "-") {
		return fmt.Errorf("--data-dir must not have leading/trailing whitespace or start with '-'")
	}
	return nil
}

func parseRecommendLimit(value string) (int, error) {
	if value == "" {
		return 0, fmt.Errorf("--limit must be an integer from 1 to %d", recommend.MaxLimit)
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("--limit must be an integer from 1 to %d", recommend.MaxLimit)
		}
	}
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || n < 1 || n > recommend.MaxLimit {
		return 0, fmt.Errorf("--limit must be from 1 to %d", recommend.MaxLimit)
	}
	return int(n), nil
}

func validateExactFilter(name, value string) error {
	if value == "" || strings.TrimSpace(value) != value || strings.Contains(value, ",") {
		return fmt.Errorf("%s must be one exact value without surrounding whitespace or commas", name)
	}
	return nil
}

type strictValueFlag struct {
	values []string
}

func (f *strictValueFlag) String() string {
	if len(f.values) == 0 {
		return ""
	}
	return f.values[len(f.values)-1]
}

func (f *strictValueFlag) Set(value string) error {
	if len(f.values) > 0 {
		return fmt.Errorf("flag given more than once")
	}
	f.values = append(f.values, value)
	return nil
}

type strictBoolFlag struct {
	seen  bool
	value bool
}

func (f *strictBoolFlag) String() string {
	if !f.seen {
		return "false"
	}
	return strconv.FormatBool(f.value)
}

func (f *strictBoolFlag) IsBoolFlag() bool { return true }

func (f *strictBoolFlag) Set(value string) error {
	if f.seen {
		return fmt.Errorf("flag given more than once")
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fmt.Errorf("must be true or false")
	}
	f.seen = true
	f.value = parsed
	return nil
}

func (f *strictBoolFlag) Value() bool { return f.value }

func writeRecommendationHuman(w io.Writer, report recommend.Report) {
	fmt.Fprintln(w, "DRY-RUN RECOMMENDATIONS")
	fmt.Fprintf(w, "mode: %s\n", report.Mode)
	fmt.Fprintf(w, "interpretation: %s\n", report.Interpretation)
	fmt.Fprintf(w, "kind: %s\n", report.Kind)
	fmt.Fprintf(w, "status: %s\n", report.Status)
	fmt.Fprintf(w, "recommendations: %d\n", len(report.Recommendations))
	for i, rec := range report.Recommendations {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "recommendation: %s\n", rec.ID)
		fmt.Fprintf(w, "  classification: %s\n", rec.Classification)
		fmt.Fprintf(w, "  mode: %s\n", rec.Mode)
		fmt.Fprintf(w, "  interpretation: %s\n", rec.Interpretation)
		fmt.Fprintf(w, "  kind: %s\n", rec.Kind)
		fmt.Fprintf(w, "  status: %s\n", rec.Status)
		fmt.Fprintf(w, "  sensor_id: %s\n", rec.SensorID)
		fmt.Fprintf(w, "  sensor_kind: %s\n", rec.SensorKind)
		fmt.Fprintf(w, "  rule_ids: %s\n", joinOrNone(rec.RuleIDs))
		fmt.Fprintf(w, "  summary: %s\n", rec.Summary)
		fmt.Fprintf(w, "  operator_review: %s\n", rec.OperatorReview)
		fmt.Fprintln(w, "  next_steps:")
		for _, step := range rec.NextSteps {
			fmt.Fprintf(w, "    - %s\n", step)
		}
		fmt.Fprintln(w, "  evidence:")
		for _, evidence := range rec.Evidence {
			fmt.Fprintf(w, "    - event_id: %s\n", evidence.EventID)
			fmt.Fprintf(w, "      payload_sha256: %s\n", evidence.PayloadSHA256)
			fmt.Fprintf(w, "      integrity_scope: %s\n", evidence.IntegrityScope)
			fmt.Fprintf(w, "      verification: %s\n", evidence.Verification)
		}
		if len(rec.Conflicts) > 0 {
			fmt.Fprintln(w, "  conflicts:")
			for _, conflict := range rec.Conflicts {
				fmt.Fprintf(w, "    - code: %s\n", conflict.Code)
				fmt.Fprintf(w, "      rule_ids: %s\n", joinOrNone(conflict.RuleIDs))
				fmt.Fprintf(w, "      resolution: %s\n", conflict.Resolution)
				fmt.Fprintf(w, "      note: %s\n", conflict.Note)
			}
		}
		if rec.SourceResolution != nil {
			fmt.Fprintf(w, "  source_resolution: resolved=%d unresolved=%d\n", rec.SourceResolution.Resolved, rec.SourceResolution.Unresolved)
		}
		fmt.Fprintln(w, "  false_positive_notes:")
		for _, note := range rec.FalsePositiveNotes {
			fmt.Fprintf(w, "    - %s\n", note)
		}
	}
	if len(report.Recommendations) == 0 {
		fmt.Fprintln(w, "no recommendations matched")
	}
}

func joinOrNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ",")
}
