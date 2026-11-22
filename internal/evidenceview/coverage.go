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
		for _, e := range events {
			if Time(e).Before(from) || Time(e).After(to) {
				continue
			}
			for _, mapping := range Mappings(e.RuleIDs) {
				if mapping.Framework != name {
					continue
				}
				technique := techniques[mapping.ID]
				technique.ObservedEventCount++
				last, _ := time.Parse(time.RFC3339Nano, technique.LastSeen)
				if Time(e).After(last) || technique.LastSeen == "" {
					technique.LastSeen = e.Time
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
