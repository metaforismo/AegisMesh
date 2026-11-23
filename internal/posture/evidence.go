package posture

import "github.com/metaforismo/aegismesh/internal/evidenceindex"

// FromSnapshot counts local observations per sensor and honeytoken hits in one
// analysis snapshot. Forwarded fleet events are excluded: their sensor IDs
// belong to other nodes' configurations.
func FromSnapshot(snapshot evidenceindex.Snapshot) Evidence {
	e := Evidence{
		Available: true, Scanned: len(snapshot.Events), Limit: snapshot.Limit, Truncated: snapshot.Truncated,
		SensorEvents: map[string]int{}, TokenHits: map[string]int{},
	}
	for _, event := range snapshot.Events {
		if event.Node != nil {
			continue
		}
		e.SensorEvents[event.Sensor.ID]++
		for _, id := range event.TokenIDs {
			e.TokenHits[id]++
		}
	}
	return e
}

// Unavailable reports evidence that could not be read, with a reason that must
// not contain secrets or paths supplied by untrusted input.
func Unavailable(reason string) Evidence {
	return Evidence{Reason: reason, SensorEvents: map[string]int{}, TokenHits: map[string]int{}}
}
