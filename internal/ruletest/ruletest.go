// Package ruletest is the offline detection evaluator seam for rule test
// documents (capability 4d-2): it takes one validated rulesinput.Input and
// runs it through the existing DETECTION rule set. It owns no rule logic,
// no registry, and no configuration — every finding's meaning comes from
// internal/detect, and class metadata comes from internal/rulecatalog.
//
// SECURITY INVARIANTS:
//   - Pure and offline: in-process evaluation only; no network, no exec, no
//     environment access, no writes, no clocks, no randomness.
//   - Input is data: document content participates only in pattern matching.
//     It can never reach execution, path selection, or configuration, and it
//     is never echoed into results (summaries are static engine-authored
//     text, inherited from detect).
//   - No mutation: the provided input and the engine state are never
//     modified; a fresh immutable engine is built per call.
//   - Fail closed on the precondition only: a value that does not satisfy the
//     validated-input contract is rejected with a typed error. A valid input
//     that matches nothing is a successful result with zero findings.
package ruletest

import (
	"fmt"
	"unicode/utf8"

	"github.com/metaforismo/aegismesh/internal/detect"
	"github.com/metaforismo/aegismesh/internal/rulecatalog"
	"github.com/metaforismo/aegismesh/internal/rulesinput"
)

// Finding is one detection hit against a rule test document.
//
// Every field is copied from authoritative sources, never derived here:
// RuleID and Severity from the detect engine's own finding, Class from the
// rulecatalog entry for that ID, and Summary from the engine reason (which
// rulecatalog derives its summaries from, so the two cannot drift).
type Finding struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Class    string `json:"class"`
	Summary  string `json:"summary"`
}

// Result pairs safe provenance metadata (carried over verbatim from the
// validated input) with deterministic findings. Findings are ordered by the
// detection engine's canonical registration order (see detect.KnownRuleIDs);
// this seam preserves that order verbatim and never re-sorts or dedups.
type Result struct {
	Kind     rulesinput.SourceKind `json:"source_kind"`
	Name     string                `json:"name"`
	Bytes    int                   `json:"bytes"`
	Findings []Finding             `json:"findings"`
}

// Evaluate evaluates one validated rule-test input against the default
// DETECTION rule set (all six rules active, detect.DefaultMaxInputBytes).
//
// Mapping invariants (deliberate and documented):
//
//   - TotalBytes carries the full validated document size (in.Bytes), exactly
//     as production callers pass the original interaction size, so RES-001
//     fires honestly when a document exceeds the default detection bound even
//     though every byte of Text was scanned by the engine.
//   - rulesinput.MaxBytes (64 KiB) is within the engine's bounded-scan design,
//     so any accepted document is scannable in full: this seam never truncates.
//
// The error return enforces ONLY the precondition that in satisfies the
// validated-input contract (non-empty, valid UTF-8, within rulesinput.MaxBytes,
// internally consistent metadata). Source acquisition is not repeated here;
// callers are expected to pass an unmodified rulesinput.Load result.
func Evaluate(in rulesinput.Input) (Result, error) {
	if err := checkValidated(in); err != nil {
		return Result{}, err
	}
	engine := detect.New(detect.Options{})
	hits := engine.Evaluate(detect.Input{Text: in.Text, TotalBytes: in.Bytes})
	out := Result{
		Kind:     in.Kind,
		Name:     in.Name,
		Bytes:    in.Bytes,
		Findings: []Finding{},
	}
	for _, h := range hits {
		class := ""
		if entry, ok := rulecatalog.Lookup(string(h.RuleID)); ok {
			class = entry.Class
		} // else: unreachable while catalogs share one registry; keep zero rather than invent a class
		out.Findings = append(out.Findings, Finding{
			RuleID:   string(h.RuleID),
			Severity: string(h.Severity),
			Class:    class,
			Summary:  h.Reason,
		})
	}
	return out, nil
}

// checkValidated enforces the precondition on an already-loaded Input. It
// re-checks only the cheap content contract of the value itself — never the
// source acquisition, which this package deliberately does not repeat.
func checkValidated(in rulesinput.Input) error {
	if in.Text == "" {
		return fmt.Errorf("ruletest: %w", rulesinput.ErrEmptyInput)
	}
	if !utf8.ValidString(in.Text) {
		return fmt.Errorf("ruletest: %w", rulesinput.ErrInvalidUTF8)
	}
	if len(in.Text) > rulesinput.MaxBytes {
		return fmt.Errorf("ruletest: %w", rulesinput.ErrTooLarge)
	}
	if in.Bytes != len(in.Text) {
		return fmt.Errorf("ruletest: metadata inconsistent: Bytes is %d but Text is %d bytes", in.Bytes, len(in.Text))
	}
	return nil
}
