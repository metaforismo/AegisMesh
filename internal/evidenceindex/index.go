package evidenceindex

import (
	"container/list"
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
)

// MaxBytes bounds retained envelope bytes plus a conservative projection allowance.
const MaxBytes = 64 << 20

// MaxStreams bounds concurrent live observation subscriptions.
const MaxStreams = 16

type entry struct {
	summary  Summary
	envelope event.Envelope
	findings []Finding
	related  []string
	ordinal  uint64
	bytes    int
}

// Index owns chronological projections with count, byte, and subscriber bounds.
type Index struct {
	nodeName        func(string) string
	mu              sync.RWMutex
	capacity, bytes int
	items           *list.List
	ids             map[string]*list.Element
	next            uint64
	history         string
	key             [32]byte
	subscribers     map[chan Summary]struct{}
	size            observe.Gauge
}

// Stats reports current index capacity, occupancy, and historical coverage.
type Stats struct {
	// Events counts retained projections.
	Events int `json:"events"`
	// Capacity is the configured entry bound.
	Capacity int `json:"capacity"`
	// Oldest is the oldest retained timestamp, or empty when no evidence exists.
	Oldest string `json:"oldest"`
	// History reports complete, truncated, or unavailable historical coverage.
	History string `json:"history"`
}

// New creates a bounded disposable index and a process-local cursor signing key.
func New(capacity int, meter observe.Meter) (*Index, error) {
	if capacity < 1 || capacity > 500000 {
		return nil, errors.New("index: capacity outside 1..500000")
	}

	index := &Index{
		capacity:    capacity,
		items:       list.New(),
		ids:         map[string]*list.Element{},
		history:     "complete",
		subscribers: map[chan Summary]struct{}{},
		size:        meter.Gauge("aegismesh_console_index_events", "Indexed console envelopes"),
	}

	if _, err := rand.Read(index.key[:]); err != nil {
		return nil, err
	}

	return index, nil
}

func clone(envelope event.Envelope) event.Envelope {
	envelope.Observation = append(json.RawMessage(nil), envelope.Observation...)
	envelope.Redaction.Rules = append([]string(nil), envelope.Redaction.Rules...)
	return envelope
}

func copySummary(summary Summary) Summary {
	summary.RuleIDs = append([]string{}, summary.RuleIDs...)
	if summary.Node != nil {
		node := *summary.Node
		summary.Node = &node
	}
	return summary
}

// Add must be called only after the authoritative append succeeds.
func (index *Index) Add(envelope event.Envelope) {
	index.add(envelope, "")
}

// SetNodeNames installs the trusted read-time registry name resolver before serving.
func (index *Index) SetNodeNames(resolve func(string) string) {
	index.nodeName = resolve
}

// AddForwarded indexes a successfully appended envelope with authenticated origin metadata.
func (index *Index) AddForwarded(envelope event.Envelope, node string) {
	if !ValidID(node) {
		return
	}
	index.add(envelope, node)
}

func originKey(id, node string) string {
	if node == "" || node == "local" {
		return id
	}
	return node + ":" + id
}

func origin(summary Summary) string {
	if summary.Node != nil {
		return summary.Node.ID
	}
	return ""
}

func (index *Index) resolved(summary Summary) Summary {
	summary = copySummary(summary)
	if summary.Node != nil && index.nodeName != nil {
		summary.Node.Name = index.nodeName(summary.Node.ID)
	}
	return summary
}

func (index *Index) add(envelope event.Envelope, node string) {
	body, err := json.Marshal(envelope)
	if err != nil || len(body) > event.MaxStoredEnvelopeBytes || !ValidID(envelope.ID) {
		return
	}

	summary, findings, related := Project(envelope)
	if node != "" {
		summary.Node = &Node{ID: node}
	}
	key := originKey(envelope.ID, node)
	item := entry{
		summary:  summary,
		envelope: clone(envelope),
		findings: findings,
		related:  related,
		bytes:    len(body) + 4096,
	}

	index.mu.Lock()
	defer index.mu.Unlock()

	if index.ids[key] != nil {
		return
	}

	index.next++
	item.ordinal = index.next
	// Native timestamps can precede an intervening correlation append.
	// Keep query order chronological; ordinal disambiguates equal timestamps.
	previous := index.items.Back()
	for previous != nil && previous.Value.(entry).envelope.Time.After(envelope.Time) {
		previous = previous.Prev()
	}

	if previous == nil {
		index.ids[key] = index.items.PushFront(item)
	} else {
		index.ids[key] = index.items.InsertAfter(item, previous)
	}

	index.bytes += item.bytes
	for index.items.Len() > index.capacity || index.bytes > MaxBytes {
		element := index.items.Front()
		old := element.Value.(entry)
		delete(index.ids, originKey(old.summary.ID, origin(old.summary)))
		index.items.Remove(element)
		index.bytes -= old.bytes
		if index.history != "unavailable" {
			index.history = "truncated"
		}
	}

	index.size.Set(float64(index.items.Len()))
	for subscriber := range index.subscribers {
		select {
		case subscriber <- index.resolved(summary):
		default:
			delete(index.subscribers, subscriber)
			close(subscriber)
		}
	}
}

// SetHistory records whether authoritative backfill is complete, truncated, or unavailable.
func (index *Index) SetHistory(history string) {
	index.mu.Lock()
	defer index.mu.Unlock()

	index.history = history
}

// Stats returns current occupancy and historical coverage without exposing index storage.
func (index *Index) Stats() Stats {
	index.mu.RLock()
	defer index.mu.RUnlock()

	stats := Stats{
		Events:   index.items.Len(),
		Capacity: index.capacity,
		History:  index.history,
	}

	if element := index.items.Front(); element != nil {
		stats.Oldest = element.Value.(entry).summary.Time
	}

	return stats
}

// Page contains newest-first summaries and an opaque continuation cursor.
type Page struct {
	// Events contains newest-first matching summaries.
	Events []Summary `json:"events"`
	// NextCursor is an opaque authenticated continuation token, or empty at the end.
	NextCursor string `json:"next_cursor"`
	// TotalMatched counts all retained observations matching the filters.
	TotalMatched int `json:"total_matched"`
}

// Query returns a bounded page matching validated filters and a signed continuation cursor.
func (index *Index) Query(filter Filter) (Page, error) {
	page := Page{Events: []Summary{}}
	if filter.Limit < 1 || filter.Limit > 200 {
		return page, ErrQuery
	}

	before, err := index.decodeCursor(filter)
	if err != nil {
		return page, err
	}

	index.mu.RLock()
	defer index.mu.RUnlock()

	var last entry
	for element := index.items.Back(); element != nil; element = element.Prev() {
		item := element.Value.(entry)
		if !filter.matches(item.summary) {
			continue
		}
		page.TotalMatched++
		if filter.Cursor != "" &&
			(item.envelope.Time.After(before.Time) ||
				item.envelope.Time.Equal(before.Time) &&
					item.ordinal >= before.Before) {
			continue
		}
		if len(page.Events) < filter.Limit {
			page.Events = append(page.Events, index.resolved(item.summary))
			last = item
		} else if page.NextCursor == "" {
			page.NextCursor = index.encodeCursor(last.envelope.Time, last.ordinal, filter)
		}
	}

	return page, nil
}

// Get returns copies of an indexed observation, findings, and related observations.
func (index *Index) Get(id string) (Summary, event.Envelope, []Finding, []Summary, bool) {
	return index.GetNode(id, "")
}

// GetNode looks up a scoped event ID; unscoped lookup prefers local and refuses ambiguous remote IDs.
func (index *Index) GetNode(id, node string) (Summary, event.Envelope, []Finding, []Summary, bool) {
	index.mu.RLock()
	defer index.mu.RUnlock()
	element := index.ids[originKey(id, node)]
	if element == nil && node == "" {
		for candidate := index.items.Back(); candidate != nil; candidate = candidate.Prev() {
			if candidate.Value.(entry).summary.ID == id {
				if element != nil {
					return Summary{}, event.Envelope{}, nil, nil, false
				}
				element = candidate
			}
		}
	}
	if element == nil {
		return Summary{}, event.Envelope{}, nil, nil, false
	}

	item := element.Value.(entry)
	related := []Summary{}
	for element := index.items.Back(); element != nil && len(related) < 200; element = element.Prev() {
		other := element.Value.(entry)
		if origin(other.summary) != origin(item.summary) {
			continue
		}
		match := false
		if item.summary.Classification == event.ClassificationCorrelationSignal {
			for _, id := range item.related {
				match = match || id == other.summary.ID
			}
		} else if other.summary.Classification == event.ClassificationCorrelationSignal {
			for _, id := range other.related {
				match = match || id == item.summary.ID
			}
		}
		if match {
			related = append(related, index.resolved(other.summary))
		}
	}

	return index.resolved(item.summary), clone(item.envelope), append([]Finding{}, item.findings...), related, true
}

// Summaries returns independent copies of all retained summaries, newest first.
func (index *Index) Summaries() []Summary {
	index.mu.RLock()
	defer index.mu.RUnlock()

	summaries := make([]Summary, 0, index.items.Len())
	for element := index.items.Back(); element != nil; element = element.Prev() {
		summaries = append(summaries, index.resolved(element.Value.(entry).summary))
	}

	return summaries
}

// Envelopes is bounded to the recommendation engine's evidence budget.
func (index *Index) Envelopes(max int) []event.Envelope {
	index.mu.RLock()
	defer index.mu.RUnlock()

	envelopes := []event.Envelope{}
	for element := index.items.Back(); element != nil && len(envelopes) < max; element = element.Prev() {
		item := element.Value.(entry)
		if item.summary.Node == nil {
			envelopes = append(envelopes, clone(item.envelope))
		}
	}

	return envelopes
}

// Subscribe registers a bounded live feed; a slow subscriber is closed rather than blocking append.
func (index *Index) Subscribe() (<-chan Summary, func(), bool) {
	index.mu.Lock()
	defer index.mu.Unlock()

	if len(index.subscribers) >= MaxStreams {
		return nil, nil, false
	}

	subscriber := make(chan Summary, 32)
	index.subscribers[subscriber] = struct{}{}
	return subscriber, func() {
		index.mu.Lock()
		defer index.mu.Unlock()
		if _, ok := index.subscribers[subscriber]; ok {
			delete(index.subscribers, subscriber)
			close(subscriber)
		}
	}, true
}
