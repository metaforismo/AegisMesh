package evidenceindex

import (
	"container/list"
	"crypto/rand"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
)

// MaxBytes bounds retained envelope bytes plus a conservative projection allowance.
const MaxBytes = 64 << 20

// MaxStreams bounds concurrent live observation subscriptions.
const MaxStreams = 16

type entry struct {
	summary    Summary
	envelope   event.Envelope
	findings   []Finding
	related    []string
	ordinal    uint64
	search     string
	selections []selection
	bytes      int
}

// Index owns chronological projections with count, byte, and subscriber bounds.
type Index struct {
	nodeName        func(string) string
	mu              sync.RWMutex
	capacity, bytes int
	items           *list.List
	ids             map[string]*list.Element
	next            uint64
	ordinals        map[uint64]*list.Element
	selectors       [selectorCount]map[string]*list.List
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

	index.ordinals = make(map[uint64]*list.Element)
	for i := range index.selectors {
		index.selectors[i] = make(map[string]*list.List)
	}

	if _, err := rand.Read(index.key[:]); err != nil {
		return nil, err
	}

	return index, nil
}

func clone(envelope event.Envelope) event.Envelope {
	envelope.AuthAttempts = nil // live distinctness metadata never belongs in an index
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
	item := &entry{
		summary:  summary,
		search:   searchText(summary),
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
	for previous != nil && previous.Value.(*entry).envelope.Time.After(envelope.Time) {
		previous = previous.Prev()
	}

	if previous == nil {
		index.ids[key] = index.items.PushFront(item)
	} else {
		index.ids[key] = index.items.InsertAfter(item, previous)
	}

	index.ordinals[item.ordinal] = index.ids[key]
	index.selectEntry(item)

	index.bytes += item.bytes
	for index.items.Len() > index.capacity || index.bytes > MaxBytes {
		element := index.items.Front()
		old := element.Value.(*entry)
		delete(index.ids, originKey(old.summary.ID, origin(old.summary)))
		delete(index.ordinals, old.ordinal)
		index.unselectEntry(old)
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
		stats.Oldest = element.Value.(*entry).summary.Time
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

	candidates := index.candidates(filter)
	if candidates == nil {
		return page, nil
	}
	all := filter.selectsAll()
	if all {
		page.TotalMatched = candidates.Len()
	}
	element := candidates.Back()
	// The cursor's ordinal is process-local and authenticated. A retained anchor
	// allows deep unfiltered pages to start directly at their predecessor.
	if all && filter.Cursor != "" {
		if anchor := index.ordinals[before.Before]; anchor != nil && anchor.Value.(*entry).envelope.Time.Equal(before.Time) {
			element = anchor.Prev()
		}
	}
	needle := strings.ToLower(filter.Q)
	// The validated limit is at most 200. Gather immutable references first so
	// selective filters allocate exactly the returned page, with no growth copies.
	var selected [200]*entry
	count := 0
	var last *entry
	for ; element != nil; element = element.Prev() {
		item := element.Value.(*entry)
		if !filter.Since.IsZero() && item.envelope.Time.Before(filter.Since) {
			break
		}
		if !filter.Until.IsZero() && item.envelope.Time.After(filter.Until) {
			continue
		}
		if !all {
			if !filter.matchesAt(item.summary, item.envelope.Time, item.search, needle) {
				continue
			}
			page.TotalMatched++
		}
		if filter.Cursor != "" && (item.envelope.Time.After(before.Time) || item.envelope.Time.Equal(before.Time) && item.ordinal >= before.Before) {
			continue
		}
		if count < filter.Limit {
			selected[count] = item
			count++
			last = item
		} else if page.NextCursor == "" {
			page.NextCursor = index.encodeCursor(last.envelope.Time, last.ordinal, filter)
			if all {
				break
			}
		}
	}

	if count > 0 {
		page.Events = make([]Summary, count)
		for i, item := range selected[:count] {
			page.Events[i] = index.resolved(item.summary)
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
			if candidate.Value.(*entry).summary.ID == id {
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

	item := element.Value.(*entry)
	matches := []*entry{}
	if item.summary.Classification == event.ClassificationCorrelationSignal {
		seen := map[string]bool{}
		for _, id := range item.related {
			if other := index.ids[originKey(id, origin(item.summary))]; other != nil && !seen[id] {
				matches = append(matches, other.Value.(*entry))
				seen[id] = true
			}
		}
	} else if signals := index.selectors[byClassification][event.ClassificationCorrelationSignal]; signals != nil {
		for element := signals.Back(); element != nil; element = element.Prev() {
			other := element.Value.(*entry)
			if origin(other.summary) != origin(item.summary) {
				continue
			}
			for _, id := range other.related {
				if id == item.summary.ID {
					matches = append(matches, other)
					break
				}
			}
			if len(matches) == 200 {
				break
			}
		}
	}
	sort.Slice(matches, func(i, j int) bool { return newer(matches[i], matches[j]) })
	related := make([]Summary, 0, min(len(matches), 200))
	for _, other := range matches[:min(len(matches), 200)] {
		related = append(related, index.resolved(other.summary))
	}

	return index.resolved(item.summary), clone(item.envelope), append([]Finding{}, item.findings...), related, true
}

// Summaries returns independent copies of all retained summaries, newest first.
func (index *Index) Summaries() []Summary {
	index.mu.RLock()
	defer index.mu.RUnlock()

	summaries := make([]Summary, 0, index.items.Len())
	for element := index.items.Back(); element != nil; element = element.Prev() {
		summaries = append(summaries, index.resolved(element.Value.(*entry).summary))
	}

	return summaries
}

// Envelopes is bounded to the recommendation engine's evidence budget.
func (index *Index) Envelopes(max int) []event.Envelope {
	index.mu.RLock()
	defer index.mu.RUnlock()

	envelopes := []event.Envelope{}
	for element := index.items.Back(); element != nil && len(envelopes) < max; element = element.Prev() {
		item := element.Value.(*entry)
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
