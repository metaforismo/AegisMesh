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

	generation uint64
}

// Generation identifies the retained state this snapshot was taken from, or is
// zero when the snapshot must not be memoised: with a live node-name resolver,
// names can change without an index change.
func (s Snapshot) Generation() uint64 { return s.generation }

// Analysis snapshots the newest retained summaries under one read lock. The
// result is an independent copy the caller may modify.
func (index *Index) Analysis() Snapshot {
	index.mu.RLock()
	defer index.mu.RUnlock()
	return index.analysisLocked()
}

// SharedAnalysis returns the same sample as Analysis, built at most once per
// generation and shared by every caller until the next change. Its Events,
// their slices and nodes must be treated as read-only; every summary's slices
// are clipped to their length, so an append by a caller reallocates instead of
// writing into shared storage. With a live node-name resolver installed it is
// not memoised and returns a fresh copy (generation zero).
func (index *Index) SharedAnalysis() Snapshot {
	index.mu.RLock()
	if cached := index.analysis; cached != nil {
		out := *cached
		index.mu.RUnlock()
		return out
	}
	out := index.analysisLocked()
	resolver := index.nodeName != nil
	index.mu.RUnlock()
	if resolver {
		return out
	}
	index.mu.Lock()
	if index.generation == out.generation && index.analysis == nil {
		index.analysis = &out
	}
	index.mu.Unlock()
	return out
}

// analysisLocked builds a fresh sample; callers hold mu for reading.
func (index *Index) analysisLocked() Snapshot {
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
	out.Events = make([]Summary, 0, min(index.items.Len(), AnalysisLimit))
	for element := index.items.Back(); element != nil && len(out.Events) < AnalysisLimit; element = element.Prev() {
		summary := index.resolved(element.Value.(*entry).summary)
		summary.RuleIDs = summary.RuleIDs[:len(summary.RuleIDs):len(summary.RuleIDs)]
		summary.TokenIDs = summary.TokenIDs[:len(summary.TokenIDs):len(summary.TokenIDs)]
		out.Events = append(out.Events, summary)
	}
	out.Scanned = len(out.Events)
	out.Truncated = out.Index.Events > out.Scanned
	if index.nodeName == nil {
		out.generation = index.generation
	}
	return out
}

// LocalEvidence returns at most 4096 requested local envelopes under one lock,
// with a count of references evicted since the summary snapshot. It performs no
// related-event traversal, and never resolves a local ID against a fleet origin.
func (index *Index) LocalEvidence(ids []string) ([]event.Envelope, int, error) {
	envelopes, missing, _, err := index.LocalEvidenceAt(ids)
	return envelopes, missing, err
}

// LocalEvidenceAt is LocalEvidence plus the generation it was read at.
func (index *Index) LocalEvidenceAt(ids []string) ([]event.Envelope, int, uint64, error) {
	if len(ids) > 4096 {
		return nil, 0, 0, ErrQuery
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
	return envelopes, missing, index.generation, nil
}

// ExportEvidence returns origin-qualified copies with no related-event traversal.
// Missing references fail the entire download rather than silently reducing scope.
func (index *Index) ExportEvidence(selected []Summary) ([]event.OriginEnvelope, error) {
	if len(selected) > AnalysisLimit {
		return nil, ErrQuery
	}
	index.mu.RLock()
	defer index.mu.RUnlock()
	out := make([]event.OriginEnvelope, 0, len(selected))
	bytes := 0
	for _, summary := range selected {
		item := index.ids[originKey(summary.ID, origin(summary))]
		if item == nil {
			return nil, ErrQuery
		}
		stored := item.Value.(*entry)
		bytes += len(stored.envelope.Observation) + 1024
		if bytes > 2<<20 {
			return nil, ErrQuery
		}
		out = append(out, event.OriginEnvelope{Envelope: clone(stored.envelope), NodeID: origin(summary)})
	}
	return out, nil
}
