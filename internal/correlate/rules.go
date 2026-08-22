package correlate

import (
	"sort"
	"strings"
)

// candidate is one rule's verdict for the current ring state.
type candidate struct {
	id      RuleID
	fire    bool
	contrib []Event // provenance: events that satisfied the predicate
}

// evaluate runs every rule in fixed order against the source's ring (which
// already contains the triggering event) and returns newly fired signals.
// Each rule fires at most once per window per source; a later event whose
// time passes lastFire+Window may re-arm it. Eviction forgets cooldowns —
// bounded memory is worth more than suppression continuity (documented).
func (e *Engine) evaluate(trigger Event, st *sourceState) []Signal {
	cands := []candidate{
		e.checkInjection(st),
		e.checkProtocolHopping(st),
		e.checkToolProbing(st),
		e.checkSustainedRecon(st),
	}
	var out []Signal
	for _, c := range cands { // fixed order => deterministic signal order
		if !c.fire {
			continue
		}
		if lf, seen := st.fired[c.id]; seen && trigger.Time.Before(lf.Add(e.opts.Window)) {
			continue // still cooling down
		}
		st.fired[c.id] = trigger.Time
		e.firedSignals++
		out = append(out, Signal{
			RuleID:         c.id,
			Time:           trigger.Time,
			SourceKey:      trigger.SourceKey,
			SourceEventIDs: eventIDs(c.contrib),
			Summary:        ruleSummaries[c.id],
		})
	}
	return out
}

func (e *Engine) checkInjection(st *sourceState) candidate {
	var contrib []Event
	for _, ev := range st.events {
		for _, fid := range ev.FindingIDs {
			if strings.HasPrefix(fid, "PI-") {
				contrib = append(contrib, ev)
				break // one entry per event
			}
		}
	}
	return candidate{RuleRepeatedInjection, len(contrib) >= e.opts.InjectionThreshold, capEvents(contrib)}
}

func (e *Engine) checkProtocolHopping(st *sourceState) candidate {
	seen := map[string]Event{}
	order := []string{}
	for _, ev := range st.events {
		if ev.SensorKind == "" {
			continue
		}
		if _, ok := seen[ev.SensorKind]; !ok {
			seen[ev.SensorKind] = ev
			order = append(order, ev.SensorKind)
		}
	}
	sort.Strings(order) // deterministic first-occurrence pick per kind
	var contrib []Event
	for _, k := range order {
		contrib = append(contrib, seen[k])
	}
	return candidate{RuleProtocolHopping, len(order) >= 3, contrib}
}

func (e *Engine) checkToolProbing(st *sourceState) candidate {
	seen := map[string]Event{}
	order := []string{}
	for _, ev := range st.events {
		if ev.ToolName == "" || ev.Classification != "canary_invocation" {
			continue
		}
		if _, ok := seen[ev.ToolName]; !ok {
			seen[ev.ToolName] = ev
			order = append(order, ev.ToolName)
		}
	}
	sort.Strings(order)
	var contrib []Event
	for _, k := range order {
		contrib = append(contrib, seen[k])
	}
	return candidate{RuleToolProbing, len(order) >= e.opts.ToolProbeThreshold, contrib}
}

func (e *Engine) checkSustainedRecon(st *sourceState) candidate {
	kinds := map[string]bool{}
	for _, ev := range st.events {
		if ev.SensorKind != "" {
			kinds[ev.SensorKind] = true
		}
	}
	ok := len(st.events) >= e.opts.ReconThreshold && len(kinds) >= 2
	return candidate{RuleSustainedRecon, ok, capEvents(st.events)}
}

func eventIDs(evs []Event) []string {
	ids := make([]string, 0, len(evs))
	for _, ev := range evs {
		ids = append(ids, ev.ID)
	}
	return ids
}

func capEvents(evs []Event) []Event {
	if len(evs) <= MaxPerSourceEvents {
		return evs
	}
	return evs[len(evs)-MaxPerSourceEvents:]
}
