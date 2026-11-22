package correlate

import (
	"testing"
	"time"
)

func TestCadenceMedianBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name string
		gaps []time.Duration
		fire bool
	}{
		{"fast irregular", []time.Duration{0, 10, 20, 100, 900, 2000, 5000}, true},
		{"all simultaneous", []time.Duration{0, 0, 0, 0, 0, 0, 0}, true},
		{"below second", []time.Duration{999, 999, 999, 999, 999, 999, 999}, true},
		{"exact second", []time.Duration{1000, 1000, 1000, 1000, 1000, 1000, 1000}, true},
		{"second irregular", []time.Duration{0, 0, 1000, 1000, 1000, 1000, 3000}, false},
		{"thirty seconds", []time.Duration{30000, 30000, 30000, 30000, 30000, 30000, 30000}, true},
		{"above thirty", []time.Duration{30001, 30001, 30001, 30001, 30001, 30001, 30001}, false},
		{"one outlier", []time.Duration{1000, 1000, 1000, 1000, 1000, 1000, 2000}, true},
		{"25 percent inclusive", []time.Duration{750, 750, 1000, 1000, 1000, 1250, 1250}, true},
		{"two outliers", []time.Duration{749, 1000, 1000, 1000, 1000, 1000, 1251}, false},
		{"insufficient", []time.Duration{100, 100, 100}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := New(Options{})
			st := &sourceState{}
			now := time.Unix(1000, 0)
			st.events = append(st.events, Event{Time: now})
			for _, gap := range tc.gaps {
				now = now.Add(gap * time.Millisecond)
				st.events = append(st.events, Event{Time: now})
			}
			if got := e.checkCadence(Event{Time: now}, st).fire; got != tc.fire {
				t.Fatalf("fire=%v, want %v", got, tc.fire)
			}
		})
	}
}
