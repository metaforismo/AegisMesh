package correlate

import (
	"sort"
	"strings"
	"time"
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
		e.checkCadence(trigger, st), e.checkAIEnumeration(trigger, st), e.checkStuffing(trigger, st), e.checkReplay(trigger, st),
	}
	var out []Signal
	for _, c := range cands { // fixed order => deterministic signal order
		if !c.fire || e.disabled.disabled(c.id) {
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

// New rules consider [trigger-window, trigger], excluding future events on
// out-of-order arrival without altering the historical rules' semantics.
func (e *Engine) past(trigger Event, st *sourceState) []Event {
	var events []Event
	cutoff := trigger.Time.Add(-e.opts.Window)
	for _, ev := range st.events {
		if !ev.Time.After(trigger.Time) && !ev.Time.Before(cutoff) {
			events = append(events, ev)
		}
	}
	return events
}
func (e *Engine) checkCadence(trigger Event, st *sourceState) candidate {
	events := e.past(trigger, st)
	sort.SliceStable(events, func(i, j int) bool { return events[i].Time.Before(events[j].Time) })
	n := e.opts.AutomationThreshold
	if len(events) < n {
		return candidate{id: RuleAutomationCadence}
	}
	events = events[len(events)-n:]
	gaps := make([]time.Duration, 0, n-1)
	for i := 1; i < len(events); i++ {
		gaps = append(gaps, events[i].Time.Sub(events[i-1].Time))
	}
	sorted := append([]time.Duration(nil), gaps...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	median := sorted[len(sorted)/2]
	if median < time.Second || median > 30*time.Second {
		return candidate{id: RuleAutomationCadence}
	}
	// At most one gap may differ from the median by more than 25%.
	outliers := 0
	for _, gap := range gaps {
		delta := gap - median
		if delta < 0 {
			delta = -delta
		}
		if delta > median/4 {
			outliers++
		}
	}
	return candidate{RuleAutomationCadence, outliers <= 1, events}
}
func (e *Engine) checkAIEnumeration(trigger Event, st *sourceState) candidate {
	seen := map[string]bool{}
	var events []Event
	for _, ev := range e.past(trigger, st) {
		if ev.AIFamily != "" && !seen[string(ev.AIFamily)] {
			seen[string(ev.AIFamily)] = true
			events = append(events, ev)
		}
	}
	return candidate{RuleAIEnumeration, len(seen) >= 2, events}
}
func (e *Engine) checkStuffing(trigger Event, st *sourceState) candidate {
	seen := map[string]bool{}
	var events []Event
	for _, ev := range e.past(trigger, st) {
		if ev.SensorKind != "http" && ev.SensorKind != "ssh" {
			continue
		}
		contributes := false
		for _, digest := range ev.AuthAttempts {
			if digest != "" && !seen[digest] {
				seen[digest] = true
				contributes = true
			}
		}
		if contributes {
			events = append(events, ev)
		}
	}
	return candidate{RuleCredentialStuffing, len(seen) >= e.opts.CredentialThreshold, events}
}
func (e *Engine) checkReplay(trigger Event, st *sourceState) candidate {
	hit := false
	for _, id := range trigger.FindingIDs {
		if id == "HT-001" {
			hit = true
		}
	}
	if !hit {
		return candidate{id: RuleCredentialReplay}
	}
	for _, ev := range e.past(trigger, st) {
		if ev.ID != trigger.ID && ev.SensorID != "" && ev.SensorID != trigger.SensorID && ev.Time.Before(trigger.Time) {
			return candidate{RuleCredentialReplay, true, []Event{ev, trigger}}
		}
	}
	return candidate{id: RuleCredentialReplay}
}
