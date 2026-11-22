package evidenceindex

import "time"

// GapBucket counts adjacent retained events with an exclusive upper millisecond bound.
// A nil bound is positive infinity.
type GapBucket struct {
	LessThanMS *int `json:"lt_ms"`
	Count      int  `json:"count"`
}

// InterArrival computes a fixed histogram over all retained source events, including signals.
func (index *Index) InterArrival(source string) []GapBucket {
	bounds := []int{100, 1000, 10000, 60000, 300000, 1800000}
	out := make([]GapBucket, len(bounds)+1)
	for i := range bounds {
		out[i].LessThanMS = &bounds[i]
	}
	index.mu.RLock()
	defer index.mu.RUnlock()
	items := index.selectors[bySource][source]
	if items == nil {
		return out
	}
	var previous time.Time
	first := true
	for e := items.Front(); e != nil; e = e.Next() {
		timestamp := e.Value.(*entry).envelope.Time
		if !first {
			gap := timestamp.Sub(previous)
			bucket := len(bounds)
			for i, bound := range bounds {
				if gap < time.Duration(bound)*time.Millisecond {
					bucket = i
					break
				}
			}
			out[bucket].Count++
		}
		first = false
		previous = timestamp
	}
	return out
}
