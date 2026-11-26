package evidenceview

import (
	"sort"
	"time"

	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/rulecatalog"
)

// Technique lists editorial mappings and unique observed events, not completeness.
type Technique struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	RuleIDs            []string `json:"rule_ids"`
	ObservedEventCount int      `json:"observed_event_count"`
	LastSeen           string   `json:"last_seen"`
}

// Framework groups the catalog's mapped techniques, including unobserved ones.
type Framework struct {
	Framework  string      `json:"framework"`
	Techniques []Technique `json:"techniques"`
}

// Coverage counts an event once per technique, even if several rules map there.
func Coverage(events []evidenceindex.Summary, from, to time.Time) []Framework {
	// Each in-window event's time and mappings are derived once, not once per
	// framework; per-technique last-seen times are kept parsed.
	type observed struct {
		at       time.Time
		time     string
		mappings []rulecatalog.FrameworkMapping
	}
	window := make([]observed, 0, len(events))
	for _, e := range events {
		at := Time(e)
		if at.Before(from) || at.After(to) || len(e.RuleIDs) == 0 {
			continue
		}
		window = append(window, observed{at: at, time: e.Time, mappings: Mappings(e.RuleIDs)})
	}
	out := []Framework{}
	for _, name := range []string{"mitre-attack", "mitre-atlas", "owasp-llm-2025"} {
		techniques := map[string]*Technique{}
		for _, rule := range rulecatalog.All() {
			for _, mapping := range rule.Frameworks {
				if mapping.Framework != name {
					continue
				}
				technique := techniques[mapping.ID]
				if technique == nil {
					technique = &Technique{ID: mapping.ID, Name: mapping.Name, RuleIDs: []string{}}
					techniques[mapping.ID] = technique
				}
				technique.RuleIDs = append(technique.RuleIDs, rule.ID)
			}
		}
		lastSeen := map[string]time.Time{}
		for _, e := range window {
			for _, mapping := range e.mappings {
				if mapping.Framework != name {
					continue
				}
				technique := techniques[mapping.ID]
				technique.ObservedEventCount++
				if last, seen := lastSeen[mapping.ID]; !seen || e.at.After(last) {
					technique.LastSeen = e.time
					lastSeen[mapping.ID] = e.at
				}
			}
		}
		framework := Framework{Framework: name, Techniques: []Technique{}}
		for _, technique := range techniques {
			sort.Strings(technique.RuleIDs)
			framework.Techniques = append(framework.Techniques, *technique)
		}
		sort.Slice(framework.Techniques, func(i, j int) bool { return framework.Techniques[i].ID < framework.Techniques[j].ID })
		out = append(out, framework)
	}
	return out
}
