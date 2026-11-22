package evidenceindex

import "github.com/metaforismo/aegismesh/internal/event"

// AnalysisLimit caps derived console analysis independently of index capacity.
const AnalysisLimit = 8192

// Snapshot is a consistent newest-first summary sample and its index bounds.
// It carries no raw observations or credentials.
type Snapshot struct {
	Events    []Summary `json:"-"`
	Index     Stats     `json:"index"`
	Scanned   int       `json:"scanned_events"`
	Limit     int       `json:"scan_limit"`
	Truncated bool      `json:"scan_truncated"`
}

// Analysis snapshots the newest retained summaries under one read lock.
func (index *Index) Analysis() Snapshot {
	index.mu.RLock()
	defer index.mu.RUnlock()

	out := Snapshot{
		Events: []Summary{},
		Index: Stats{
			Events: index.items.Len(), Capacity: index.capacity, History: index.history,
		},
		Limit: AnalysisLimit,
	}
	if first := index.items.Front(); first != nil {
		out.Index.Oldest = first.Value.(*entry).summary.Time
	}
	for element := index.items.Back(); element != nil && len(out.Events) < AnalysisLimit; element = element.Prev() {
		out.Events = append(out.Events, index.resolved(element.Value.(*entry).summary))
	}
	out.Scanned = len(out.Events)
	out.Truncated = out.Index.Events > out.Scanned
	return out
}

// LocalEvidence returns at most 4096 requested local envelopes under one lock,
// with a count of references evicted since the summary snapshot. It performs no
// related-event traversal, and never resolves a local ID against a fleet origin.
func (index *Index) LocalEvidence(ids []string) ([]event.Envelope, int, error) {
	if len(ids) > 4096 {
		return nil, 0, ErrQuery
	}
	index.mu.RLock()
	defer index.mu.RUnlock()

	envelopes := make([]event.Envelope, 0, len(ids))
	missing := 0
	for _, id := range ids {
		element := index.ids[id]
		if element == nil {
			missing++
			continue
		}
		envelopes = append(envelopes, clone(element.Value.(*entry).envelope))
	}
	return envelopes, missing, nil
}
