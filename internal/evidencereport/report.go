// Package evidencereport renders deterministic Markdown from redacted evidence.
// All variable text is inert quoted data, including operator notes and catalog prose.
package evidencereport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/metaforismo/aegismesh/internal/console/investigations"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/evidenceview"
	"github.com/metaforismo/aegismesh/internal/indicatorexport"
	"github.com/metaforismo/aegismesh/internal/recommend"
	"github.com/metaforismo/aegismesh/internal/rulecatalog"
)

// Input separates scope annotations from immutable evidence projections.
type Input struct {
	Tenant                 string
	Scope                  string
	Bounds                 evidenceindex.Snapshot
	Events                 []evidenceindex.Summary
	Investigation          *investigations.Investigation
	Recommendations        recommend.Report
	RecommendationMissing  int
	RecommendationExcluded int
}

// MarkdownText wraps one bounded, JSON-quoted line in a fixed code fence.
// JSON escapes newlines and HTML delimiters; the initial quote prevents any
// attacker-controlled fence from starting a line, even with backticks or tildes.
func MarkdownText(value string) string {
	bounded := strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, evidenceindex.Bound(value, 4000))
	body, _ := json.Marshal(bounded)
	return "\n```text\n" + string(body) + "\n```\n\n"
}

// Render emits an observation report, with fixed headings and capped detail.
func Render(input Input) ([]byte, error) {
	if len(input.Events) > evidenceindex.AnalysisLimit {
		return nil, indicatorexport.ErrLimit
	}
	var out bytes.Buffer
	out.WriteString("# AegisMesh observation report\n\nObservations are not incidents. This report makes no attribution or compromise verdict.\n\n## Scope\n")
	out.WriteString(MarkdownText(input.Scope))
	out.WriteString(MarkdownText("Tenant: " + input.Tenant))
	events := evidenceview.Chronological(input.Events)
	if len(events) > 0 {
		out.WriteString(MarkdownText("Selected interval: " + events[0].Time + " to " + events[len(events)-1].Time))
	}
	if input.Investigation != nil {
		out.WriteString(MarkdownText("Title: " + input.Investigation.Title))
		out.WriteString(MarkdownText("Status: " + input.Investigation.Status + "; priority: " + input.Investigation.Priority))
		fmt.Fprintf(&out, "Attached references: %d; resolved in sampled index: %d; unavailable: %d.\n\n", len(input.Investigation.EventIDs), len(input.Events), len(input.Investigation.EventIDs)-len(input.Events))
	}
	fmt.Fprintf(&out, "Selected events: %d. Index events: %d; scan limit: %d; scanned: %d; scan truncated: %t.\n", len(input.Events), input.Bounds.Index.Events, input.Bounds.Limit, input.Bounds.Scanned, input.Bounds.Truncated)
	out.WriteString(MarkdownText("Index history: " + input.Bounds.Index.History + "; oldest retained: " + input.Bounds.Index.Oldest))

	sources, rules := map[string]bool{}, map[string]bool{}
	for _, e := range input.Events {
		sources[e.Source] = true
		for _, id := range e.RuleIDs {
			rules[id] = true
		}
	}
	out.WriteString("## Sources\n")
	sortedSources := sortedKeys(sources)
	for _, source := range sortedSources[:min(len(sortedSources), evidenceview.SensorLimit)] {
		out.WriteString(MarkdownText(source))
	}
	fmt.Fprintf(&out, "Sources omitted from this section: %d.\n\n", max(0, len(sortedSources)-evidenceview.SensorLimit))

	out.WriteString("## Timeline\n\nChronological redacted display summaries; origins distinguish colliding event IDs.\n")
	for _, e := range events[:min(len(events), evidenceview.TimelineLimit)] {
		out.WriteString(MarkdownText(e.Time + " | " + evidenceview.EventKey(e) + " | " + e.Source + " | " + e.Sensor.ID + " | " + e.Sensor.Kind + " | " + e.Classification + " | " + strings.Join(e.RuleIDs, ", ") + " | " + e.Summary))
	}
	fmt.Fprintf(&out, "Timeline events omitted: %d.\n\n", max(0, len(events)-evidenceview.TimelineLimit))

	out.WriteString("## Rules and framework references\n\nEditorial relates-to mappings, not proof that a technique executed or a completeness claim.\n")
	for _, id := range sortedKeys(rules) {
		rule, ok := rulecatalog.Lookup(id)
		if !ok {
			continue
		}
		text := id + " | " + rule.Summary
		for _, mapping := range rule.Frameworks {
			text += " | " + mapping.Framework + " " + mapping.ID + " " + mapping.Name
		}
		out.WriteString(MarkdownText(text))
	}

	out.WriteString("## Automation observations\n\nAssessments describe retained evidence; they are never a verdict about the client.\n")
	sessions := evidenceview.Sessions(input.Tenant, input.Events)
	for _, session := range sessions[:min(len(sessions), evidenceview.TimelineLimit)] {
		out.WriteString(MarkdownText(session.Source + " | " + session.FirstSeen + " | " + session.LastSeen + " | " + session.Automation.Assessment))
		for _, evidence := range session.Automation.Evidence {
			out.WriteString(MarkdownText(evidence.Code + ": " + evidence.Detail))
		}
	}
	fmt.Fprintf(&out, "Assessment groups omitted: %d.\n\n", max(0, len(sessions)-evidenceview.TimelineLimit))

	out.WriteString("## Attached notes\n")
	if input.Investigation != nil {
		for _, note := range input.Investigation.Notes {
			out.WriteString(MarkdownText(note.Time + " | " + note.Author))
			out.WriteString(MarkdownText(note.Text))
		}
	}
	out.WriteString("## Proposed dry-run recommendations\n\nProposed for operator review. Not executed. No enforcement or asset changes are performed.\n")
	for _, proposal := range input.Recommendations.Recommendations {
		out.WriteString(MarkdownText(proposal.ID + " | " + proposal.Summary))
		out.WriteString(MarkdownText(proposal.OperatorReview))
		for _, step := range proposal.NextSteps {
			out.WriteString(MarkdownText(step))
		}
		for _, ref := range proposal.Evidence {
			out.WriteString(MarkdownText("Evidence: " + ref.EventID + " | SHA-256 observation payload: " + ref.PayloadSHA256))
		}
	}
	fmt.Fprintf(&out, "Recommendation inputs unavailable after snapshot: %d; excluded (forwarded or above 4096-event cap): %d. At most 20 proposals.\n\n", input.RecommendationMissing, input.RecommendationExcluded)
	out.WriteString("## Limits\n\nThe disposable index is bounded by count and bytes; only its newest 8192 events are scanned. Eviction, encryption, restart or forwarding can hide history. Session boundaries and IDs depend on the first retained event. Timeline and phase detail are capped at 200 events. Evidence is redacted before storage; this report contains projections, not raw credentials or prompts. Payload hashes establish consistency, not provenance or chain of custody. Source keys are observations, not actor identities; NAT, proxies, scanners and legitimate clients can share these behaviours. Recommendations use verified local evidence only; no cross-node recommendation generation.\n")
	if out.Len() > indicatorexport.MaxBytes {
		return nil, indicatorexport.ErrLimit
	}
	return out.Bytes(), nil
}

func sortedKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
