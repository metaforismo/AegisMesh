// Package digest derives deterministic, bounded summaries of retained observations.
package digest

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/evidencereport"
	"github.com/metaforismo/aegismesh/internal/evidenceview"
	"github.com/metaforismo/aegismesh/internal/rulecatalog"
)

// Input supplies a stable observation snapshot and independently computed local counts.
type Input struct {
	Tenant                 string
	Window                 string
	AsOf                   time.Time
	Bounds                 evidenceindex.Snapshot
	OpenInvestigations     *int
	Recommendations        int
	RecommendationExcluded int
	RecommendationMissing  int
}

// Report is a comparison of adjacent half-open windows, not incident attribution.
type Report struct {
	Window                string                         `json:"window"`
	AsOf                  string                         `json:"as_of"`
	Totals                evidenceindex.Totals           `json:"totals"`
	PreviousTotals        evidenceindex.Totals           `json:"previous_totals"`
	NewSources            int                            `json:"new_sources"`
	ReturningSources      int                            `json:"returning_sources"`
	AutomationSessions    int                            `json:"sessions_consistent_with_automation"`
	TopRules              []evidenceindex.RuleCount      `json:"top_rules"`
	NewTechniques         []rulecatalog.FrameworkMapping `json:"new_techniques"`
	HoneytokenHits        int                            `json:"honeytoken_hits"`
	AgentCanaryHits       int                            `json:"agent_canary_hits"`
	OpenInvestigations    *int                           `json:"open_investigations"`
	DryRunRecommendations int                            `json:"dry_run_recommendations"`
	Bounds                evidenceindex.Snapshot         `json:"bounds"`
	Limits                Limits                         `json:"limits"`
}

// Limits carries completeness and interpretation boundaries alongside the counts.
type Limits struct {
	Interpretation          string `json:"interpretation"`
	History                 string `json:"history"`
	ScanTruncated           bool   `json:"scan_truncated"`
	SourceComparison        string `json:"source_comparison"`
	InvestigationsAvailable bool   `json:"investigations_available"`
	RecommendationExcluded  int    `json:"recommendation_excluded"`
	RecommendationMissing   int    `json:"recommendation_missing"`
	RecommendationCap       int    `json:"recommendation_cap"`
}

// Window accepts precisely the periodic digest windows.
func Window(value string) (time.Duration, error) {
	switch value {
	case "24h":
		return 24 * time.Hour, nil
	case "7d":
		return 7 * 24 * time.Hour, nil
	}
	return 0, fmt.Errorf("digest window must be 24h or 7d")
}

// Build counts newest-sample evidence in [as_of-window,as_of), compared to its predecessor.
func Build(in Input) (Report, error) {
	if len(in.Bounds.Events) > evidenceindex.AnalysisLimit {
		return Report{}, evidenceindex.ErrQuery
	}
	duration, err := Window(in.Window)
	if err != nil {
		return Report{}, err
	}
	out := Report{
		Window:                in.Window,
		AsOf:                  in.AsOf.UTC().Format(time.RFC3339Nano),
		TopRules:              []evidenceindex.RuleCount{},
		NewTechniques:         []rulecatalog.FrameworkMapping{},
		OpenInvestigations:    in.OpenInvestigations,
		DryRunRecommendations: in.Recommendations,
		Bounds:                in.Bounds,
		Limits: Limits{
			Interpretation:          "Retained observations, not incidents, client attribution or technique execution; no scheduler or delivery.",
			History:                 in.Bounds.Index.History,
			ScanTruncated:           in.Bounds.Truncated,
			SourceComparison:        "New means absent from the preceding sampled window, not first-ever seen.",
			InvestigationsAvailable: in.OpenInvestigations != nil,
			RecommendationExcluded:  in.RecommendationExcluded,
			RecommendationMissing:   in.RecommendationMissing,
			RecommendationCap:       20,
		},
	}
	current, previous := []evidenceindex.Summary{}, []evidenceindex.Summary{}
	from := in.AsOf.Add(-duration)
	for _, e := range in.Bounds.Events {
		t := evidenceview.Time(e)
		if !t.Before(from) && t.Before(in.AsOf) {
			current = append(current, e)
		} else if !t.Before(from.Add(-duration)) && t.Before(from) {
			previous = append(previous, e)
		}
	}
	out.Totals = totals(current)
	out.PreviousTotals = totals(previous)
	oldSources := map[string]bool{}
	for _, e := range previous {
		if e.Source != "" {
			oldSources[e.Source] = true
		}
	}
	for _, s := range evidenceindex.Sources(current, from, in.AsOf) {
		if oldSources[s.Source] {
			out.ReturningSources++
		} else {
			out.NewSources++
		}
	}
	for _, s := range evidenceview.Sessions(in.Tenant, in.Bounds.Events) {
		if s.Automation.Assessment != "consistent_with_automation" {
			continue
		}
		for _, e := range s.Events {
			t := evidenceview.Time(e)
			if !t.Before(from) && t.Before(in.AsOf) {
				out.AutomationSessions++
				break
			}
		}
	}
	rules := map[string]int{}
	for _, e := range current {
		for _, id := range e.RuleIDs {
			rules[id]++
			if id == "HT-001" {
				out.HoneytokenHits++
			}
			if id == "AGT-001" {
				out.AgentCanaryHits++
			}
		}
	}
	for id, count := range rules {
		if rule, ok := rulecatalog.Lookup(id); ok {
			out.TopRules = append(out.TopRules, evidenceindex.RuleCount{
				RuleID:   id,
				Title:    rule.Summary,
				Events:   count,
				Severity: rule.Severity,
			})
		}
	}
	sort.Slice(out.TopRules, func(i, j int) bool {
		if out.TopRules[i].Events != out.TopRules[j].Events {
			return out.TopRules[i].Events > out.TopRules[j].Events
		}
		return out.TopRules[i].RuleID < out.TopRules[j].RuleID
	})
	if len(out.TopRules) > 10 {
		out.TopRules = out.TopRules[:10]
	}
	oldTech := techniques(previous)
	for key, mapping := range techniques(current) {
		if _, ok := oldTech[key]; !ok {
			out.NewTechniques = append(out.NewTechniques, mapping)
		}
	}
	sort.Slice(out.NewTechniques, func(i, j int) bool {
		a, b := out.NewTechniques[i], out.NewTechniques[j]
		if a.Framework != b.Framework {
			return a.Framework < b.Framework
		}
		return a.ID < b.ID
	})
	return out, nil
}

func totals(events []evidenceindex.Summary) evidenceindex.Totals {
	out := evidenceindex.Totals{}
	sources, sensors := map[string]bool{}, map[string]bool{}
	for _, e := range events {
		out.Events++
		switch e.Classification {
		case "interaction":
			out.Interaction++
		case "canary_invocation":
			out.CanaryInvocation++
		case "correlation_signal":
			out.CorrelationSignal++
		}
		if e.Source != "" {
			sources[e.Source] = true
		}
		sensors[e.Sensor.ID] = true
	}
	out.Sources = len(sources)
	out.SensorsActive = len(sensors)
	return out
}
func techniques(events []evidenceindex.Summary) map[string]rulecatalog.FrameworkMapping {
	out := map[string]rulecatalog.FrameworkMapping{}
	for _, e := range events {
		for _, id := range e.RuleIDs {
			if r, ok := rulecatalog.Lookup(id); ok {
				for _, m := range r.Frameworks {
					out[m.Framework+":"+m.ID] = m
				}
			}
		}
	}
	return out
}

// Render emits JSON or inert Markdown through the shared neutraliser.
func Render(report Report, format string) ([]byte, error) {
	if format == "json" {
		body, err := json.MarshalIndent(report, "", "  ")
		return append(body, '\n'), err
	}
	if format != "md" {
		return nil, fmt.Errorf("digest format must be md or json")
	}
	var out strings.Builder
	out.WriteString("# AegisMesh periodic observation digest\n\n")
	sections := []struct {
		name  string
		value any
	}{
		{"Window", map[string]string{"window": report.Window, "as_of": report.AsOf}},
		{"Totals and preceding window", map[string]any{"totals": report.Totals, "previous_totals": report.PreviousTotals, "new_sources": report.NewSources, "returning_sources": report.ReturningSources}},
		{"Automation observations", report.AutomationSessions},
		{"Top rules", report.TopRules},
		{"Newly observed technique relations", report.NewTechniques},
		{"Planted markers", map[string]int{"honeytoken_hits": report.HoneytokenHits, "agent_canary_hits": report.AgentCanaryHits}},
		{"Operator work", map[string]any{"open_investigations": report.OpenInvestigations, "dry_run_recommendations": report.DryRunRecommendations}},
		{"Limits", report.Limits},
		{"Snapshot bounds", report.Bounds},
	}
	for _, section := range sections {
		out.WriteString("## " + section.name + "\n\n")
		body, _ := json.Marshal(section.value)
		out.WriteString(evidencereport.MarkdownText(string(body)))
	}
	return []byte(out.String()), nil
}
