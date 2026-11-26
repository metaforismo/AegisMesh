package demoseed

import (
	"encoding/json"

	"github.com/metaforismo/aegismesh/internal/event"
)

// Marked reports whether an envelope's observation carries the top-level
// "synthetic": true marker this package writes. The marker is a display label
// for seeded demo history, not an authenticity or trust signal.
func Marked(envelope event.Envelope) bool {
	var probe struct {
		Synthetic bool `json:"synthetic"`
	}
	return json.Unmarshal(envelope.Observation, &probe) == nil && probe.Synthetic
}
