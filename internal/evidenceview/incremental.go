package evidenceview

import (
	"sort"

	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

// MaxIncrementalChange bounds the number of added plus removed events an
// incremental update handles; larger changes recompute from scratch.
const MaxIncrementalChange = 1024

type eventRef struct{ node, id string }

func refOf(e evidenceindex.Summary) eventRef {
	if e.Node != nil {
		return eventRef{e.Node.ID, e.ID}
	}
	return eventRef{"", e.ID}
}

// sampleDiff aligns two newest-first index samples. It succeeds when next is
// previous with events inserted anywhere and events dropped from the oldest
// end only (what appends and evictions do to the bounded sample), and
// returns the source keys whose event sets changed.
func sampleDiff(previous, next []evidenceindex.Summary) (map[string]bool, bool) {
	affected := map[string]bool{}
	added := map[eventRef]bool{}
	i, j := 0, 0
	for i < len(next) {
		if j < len(previous) && refOf(next[i]) == refOf(previous[j]) {
			i, j = i+1, j+1
			continue
		}
		added[refOf(next[i])] = true
		affected[next[i].Source] = true
		i++
		if len(added) > MaxIncrementalChange {
			return nil, false
		}
	}
	if len(previous)-j+len(added) > MaxIncrementalChange {
		return nil, false
	}
	for _, e := range previous[j:] {
		// A dropped event that reappears among the additions means the walk
		// misaligned (a reorder, not an append): fall back.
		if added[refOf(e)] {
			return nil, false
		}
		affected[e.Source] = true
	}
	delete(affected, "")
	return affected, true
}

// UpdateSessions returns exactly Sessions(tenant, events), reusing the
// sessions of every source whose events did not change between previousEvents
// (from which previous was computed by Sessions or UpdateSessions) and events.
// Sessions of one source depend only on that source's events, so only the
// affected sources are regrouped and summarised; campaigns are then assigned
// over the full list as Sessions does. It falls back to Sessions when the
// samples do not align as an append/evict change, or the change is large.
func UpdateSessions(tenant string, previousEvents []evidenceindex.Summary, previous []Session, events []evidenceindex.Summary) []Session {
	if previous == nil {
		return Sessions(tenant, events)
	}
	affected, ok := sampleDiff(previousEvents, events)
	if !ok {
		return Sessions(tenant, events)
	}
	out := make([]Session, 0, len(previous)+len(affected))
	for _, session := range previous {
		if !affected[session.Source] {
			session.CampaignID = nil
			out = append(out, session)
		}
	}
	if len(affected) > 0 {
		subset := []evidenceindex.Summary{}
		for _, e := range events {
			if affected[e.Source] {
				subset = append(subset, e)
			}
		}
		groups := map[string][]evidenceindex.Summary{}
		for _, e := range Chronological(subset) {
			group := groups[e.Source]
			if len(group) > 0 && Time(e).Sub(Time(group[len(group)-1])) > IdleGap {
				out = append(out, summarize(tenant, group))
				group = nil
			}
			groups[e.Source] = append(group, e)
		}
		for _, group := range groups {
			out = append(out, summarize(tenant, group))
		}
	}
	sortSessions(out)
	assignCampaigns(tenant, out)
	return out
}

func sortSessions(out []Session) {
	sort.Slice(out, func(i, j int) bool {
		a, b := Time(out[i].Events[len(out[i].Events)-1]), Time(out[j].Events[len(out[j].Events)-1])
		if !a.Equal(b) {
			return a.After(b)
		}
		return out[i].ID < out[j].ID
	})
}
