package evidenceindex

import (
	"fmt"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
)

func TestSensorBucketBoundariesAndCap(t *testing.T) {
	for _, window := range []string{"1h", "24h", "7d"} {
		t.Run(window, func(t *testing.T) {
			index, err := New(1000, observe.NewRegistry())
			if err != nil {
				t.Fatal(err)
			}
			now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
			duration, count, _ := Window(window)
			for i, kind := range []string{"interaction", "canary_invocation", "correlation_signal"} {
				observation := envelope(t, &event.Sequencer{}, kind, `{}`)
				observation.Time = now.Add(-duration).Add(time.Duration(i) * duration / time.Duration(count))
				index.Add(observation)
			}
			overview, err := index.Overview(window, now)
			if err != nil {
				t.Fatal(err)
			}
			if len(overview.BySensor) != 1 || len(overview.BySensor[0].Buckets) != count {
				t.Fatal("wrong bucket series")
			}
			for i, main := range overview.Buckets {
				if main != overview.BySensor[0].Buckets[i] {
					t.Fatalf("misaligned bucket %d", i)
				}
			}
			for i := range 100 {
				observation := envelope(t, &event.Sequencer{}, "interaction", `{}`)
				observation.Sensor.ID = fmt.Sprintf("sensor-%d", i)
				observation.Time = now.Add(-time.Second)
				index.Add(observation)
			}
			overview, err = index.Overview(window, now)
			if err != nil || len(overview.BySensor) != 64 {
				t.Fatalf("sensor cap: %d %v", len(overview.BySensor), err)
			}
		})
	}
}
