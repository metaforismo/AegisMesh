package evidenceindex

import (
	"container/list"
	"time"
)

const (
	byNode = iota
	byClassification
	bySensor
	byKind
	bySource
	byRule
	selectorCount
)

type selection struct {
	field   int
	key     string
	element *list.Element
}

func newer(a, b *entry) bool {
	return a.envelope.Time.After(b.envelope.Time) || a.envelope.Time.Equal(b.envelope.Time) && a.ordinal > b.ordinal
}

// Secondary lists share immutable entries with the chronological list. All
// links are maintained under mu, removed on eviction, and bounded by retained
// entries (at most five scalar keys and 64 projected rule IDs per entry).
func (index *Index) selectEntry(item *entry) {
	node := origin(item.summary)
	if node == "" {
		node = "local"
	}
	keys := [...]string{node, item.summary.Classification, item.summary.Sensor.ID, item.summary.Sensor.Kind, item.summary.Source}
	item.selections = make([]selection, 0, len(keys)+len(item.summary.RuleIDs))
	add := func(field int, key string) {
		if key == "" {
			return
		}
		items := index.selectors[field][key]
		if items == nil {
			items = list.New()
			index.selectors[field][key] = items
		}
		previous := items.Back()
		for previous != nil && newer(previous.Value.(*entry), item) {
			previous = previous.Prev()
		}
		var link *list.Element
		if previous == nil {
			link = items.PushFront(item)
		} else {
			link = items.InsertAfter(item, previous)
		}
		item.selections = append(item.selections, selection{field, key, link})
	}
	for field, key := range keys {
		add(field, key)
	}
	for _, rule := range item.summary.RuleIDs {
		add(byRule, rule)
	}
}

func (index *Index) unselectEntry(item *entry) {
	for _, link := range item.selections {
		items := index.selectors[link.field][link.key]
		items.Remove(link.element)
		if items.Len() == 0 {
			delete(index.selectors[link.field], link.key)
		}
	}
}

func (index *Index) candidates(filter Filter) *list.List {
	node := filter.Node
	keys := [...]string{node, filter.Classification, filter.Sensor, filter.Kind, filter.Source, filter.Rule}
	items := index.items
	for field, key := range keys {
		if key == "" {
			continue
		}
		selected := index.selectors[field][key]
		if selected == nil {
			return nil
		}
		if selected.Len() < items.Len() {
			items = selected
		}
	}
	return items
}

// snapshot holds the read lock only while collecting immutable references.
// Window boundaries use native timestamps; aggregation and sorting run unlocked.
func (index *Index) snapshot(from, to time.Time, source string) []*entry {
	index.mu.RLock()
	defer index.mu.RUnlock()
	items := index.items
	if source != "" {
		items = index.selectors[bySource][source]
	}
	if items == nil {
		return nil
	}
	capacity := min(items.Len(), 256)
	// Full-window snapshots know their exact size without a counting pass.
	if first, last := items.Front(), items.Back(); first != nil && !first.Value.(*entry).envelope.Time.Before(from) && last.Value.(*entry).envelope.Time.Before(to) {
		capacity = items.Len()
	}
	out := make([]*entry, 0, capacity)
	for element := items.Back(); element != nil; element = element.Prev() {
		item := element.Value.(*entry)
		if item.envelope.Time.Before(from) {
			break
		}
		if !item.envelope.Time.Before(to) {
			continue
		}
		out = append(out, item)
	}
	return out
}
