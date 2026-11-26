package evidenceview_test

import (
	"bytes"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/demoseed"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/evidenceview"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/rulecatalog"
)

// referenceCoverage is the pre-optimisation implementation of Coverage.
func referenceCoverage(events []evidenceindex.Summary, from, to time.Time) []evidenceview.Framework {
	parse := func(e evidenceindex.Summary) time.Time {
		t, _ := time.Parse(time.RFC3339Nano, e.Time)
		return t
	}
	out := []evidenceview.Framework{}
	for _, name := range []string{"mitre-attack", "mitre-atlas", "owasp-llm-2025"} {
		techniques := map[string]*evidenceview.Technique{}
		for _, rule := range rulecatalog.All() {
			for _, mapping := range rule.Frameworks {
				if mapping.Framework != name {
					continue
				}
				technique := techniques[mapping.ID]
				if technique == nil {
					technique = &evidenceview.Technique{ID: mapping.ID, Name: mapping.Name, RuleIDs: []string{}}
					techniques[mapping.ID] = technique
				}
				technique.RuleIDs = append(technique.RuleIDs, rule.ID)
			}
		}
		for _, e := range events {
			if parse(e).Before(from) || parse(e).After(to) {
				continue
			}
			for _, mapping := range evidenceview.Mappings(e.RuleIDs) {
				if mapping.Framework != name {
					continue
				}
				technique := techniques[mapping.ID]
				technique.ObservedEventCount++
				last, _ := time.Parse(time.RFC3339Nano, technique.LastSeen)
				if parse(e).After(last) || technique.LastSeen == "" {
					technique.LastSeen = e.Time
				}
			}
		}
		framework := evidenceview.Framework{Framework: name, Techniques: []evidenceview.Technique{}}
		for _, technique := range techniques {
			sort.Strings(technique.RuleIDs)
			framework.Techniques = append(framework.Techniques, *technique)
		}
		sort.Slice(framework.Techniques, func(i, j int) bool { return framework.Techniques[i].ID < framework.Techniques[j].ID })
		out = append(out, framework)
	}
	return out
}

func TestCoverageMatchesReferenceOnSeededHistory(t *testing.T) {
	cfg, err := demoseed.Config(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	cfg.Correlation.Enabled = &enabled
	anchor := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	index, _ := evidenceindex.New(50000, observe.NewRegistry())
	profile, _ := demoseed.Lookup(demoseed.Small)
	if _, err := demoseed.Generate(profile, cfg, anchor, func(e event.Envelope) error { index.Add(e); return nil }); err != nil {
		t.Fatal(err)
	}
	events := index.Analysis().Events
	// Unsorted and duplicate-time input must not change the result either.
	events = append(events, events[len(events)/2], evidenceindex.Summary{Time: "not a time", RuleIDs: []string{"HT-001"}})
	for _, window := range []time.Duration{time.Hour, 24 * time.Hour, 7 * 24 * time.Hour, 30 * 24 * time.Hour} {
		from, to := anchor.Add(-window), anchor
		got, _ := json.Marshal(evidenceview.Coverage(events, from, to))
		want, _ := json.Marshal(referenceCoverage(events, from, to))
		if !bytes.Equal(got, want) {
			t.Fatalf("window %s: coverage differs\n%s\n%s", window, got, want)
		}
	}
	got, _ := json.Marshal(evidenceview.Coverage(events, time.Time{}, anchor))
	want, _ := json.Marshal(referenceCoverage(events, time.Time{}, anchor))
	if !bytes.Equal(got, want) {
		t.Fatal("coverage from zero time differs")
	}
}
