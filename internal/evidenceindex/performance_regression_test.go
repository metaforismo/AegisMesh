package evidenceindex

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
)

func TestPerformanceOverviewContract(t *testing.T) {
	index, err := New(200, observe.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 15, 12, 0, 0, 123456789, time.UTC)
	index.SetNodeNames(func(id string) string { return "synthetic-" + id[:2] })
	n := 0
	for _, duration := range []time.Duration{time.Hour, 24 * time.Hour, 7 * 24 * time.Hour} {
		for _, offset := range []time.Duration{-2*duration - time.Nanosecond, -2 * duration, -duration - time.Nanosecond, -duration, -time.Nanosecond, 0, time.Nanosecond} {
			for _, class := range []string{"interaction", "canary_invocation", "correlation_signal"} {
				body := `{"remote_host":"203.0.113.7","method":"GET","path":"/synthetic","response":{"status":403},"detection":{"action":"tag","findings":[{"rule_id":"PI-001","confidence":"high"}]}}`
				if class == "correlation_signal" {
					body = `{"source_key":"203.0.113.7","rule_id":"COR-001","summary":"Synthetic signal"}`
				}
				e := event.Envelope{Schema: event.SchemaV1, ID: fmt.Sprintf("%032x", n), Time: now.Add(offset), Seq: uint64(n), Sensor: event.SensorRef{ID: fmt.Sprintf("sensor-%d", n%3), Kind: "http"}, Classification: class, Observation: json.RawMessage(body)}
				if n%2 == 0 {
					index.Add(e)
				} else {
					index.AddForwarded(e, strings.Repeat("ab", 16))
				}
				n++
			}
		}
	}
	// Include late arrivals, equal timestamps and changes to a sensor's stored kind.
	e := event.Envelope{ID: strings.Repeat("f", 32), Time: now.Add(-time.Minute), Sensor: event.SensorRef{ID: "sensor-0", Kind: "mcp"}, Classification: "interaction", Observation: json.RawMessage(`{"remote_host":"203.0.113.8","method":"tools/list"}`)}
	index.Add(e)
	result := map[string]any{}
	for _, window := range []string{"1h", "24h", "7d"} {
		overview, err := index.Overview(window, now)
		if err != nil {
			t.Fatal(err)
		}
		result[window] = overview
		result[window+"-nodes"] = index.ByNode(window, now)
	}
	result["sources"] = index.Sources(time.Time{}, now)
	result["source"] = index.Source("203.0.113.7", time.Time{}, now)
	body, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')
	const path = "testdata/performance_overview.golden.json"
	if os.Getenv("AEGISMESH_UPDATE_PERF_GOLDEN") == "1" {
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != string(want) {
		t.Fatal("overview/source JSON changed from the pre-optimization golden")
	}
}

func TestPerformanceQueryPagesAgainstRetainedSnapshot(t *testing.T) {
	index, err := New(37, observe.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	for n := 0; n < 150; n++ {
		e := event.Envelope{ID: fmt.Sprintf("%032x", n), Time: base.Add(time.Duration(n%53) * time.Second), Sensor: event.SensorRef{ID: fmt.Sprintf("sensor-%d", n%4), Kind: "http"}, Classification: []string{"interaction", "canary_invocation", "correlation_signal"}[n%3], Observation: json.RawMessage(fmt.Sprintf(`{"remote_host":"203.0.113.%d","method":"GET","path":"/SYNTHETIC","detection":{"findings":[{"rule_id":"PI-001"}]}}`, n%7))}
		if n%2 == 0 {
			index.Add(e)
		} else {
			index.AddForwarded(e, fmt.Sprintf("%032x", n%3+1))
		}
	}
	filters := []Filter{{}, {Node: "local"}, {Node: fmt.Sprintf("%032x", 2)}, {Node: strings.Repeat("f", 32)}, {Classification: "correlation_signal"}, {Sensor: "sensor-1"}, {Kind: "http"}, {Source: "203.0.113.3"}, {Source: "absent"}, {Rule: "PI-001"}, {Severity: "high"}, {Q: "SyNtHeTiC"}, {Since: base.Add(40 * time.Second)}, {Until: base.Add(45 * time.Second)}, {Sensor: "sensor-1", Source: "203.0.113.3", Q: "synthetic"}}
	summaries := index.Summaries()
	for _, filter := range filters {
		t.Run(fmt.Sprintf("%+v", filter), func(t *testing.T) {
			want := []Summary{}
			for _, s := range summaries {
				if filter.Matches(s) {
					want = append(want, s)
				}
			}
			filter.Limit = 3
			got := []Summary{}
			for pageNumber := 0; pageNumber < 20; pageNumber++ {
				page, err := index.Query(filter)
				if err != nil {
					t.Fatal(err)
				}
				if page.TotalMatched != len(want) {
					t.Fatalf("total=%d want=%d", page.TotalMatched, len(want))
				}
				got = append(got, page.Events...)
				if page.NextCursor == "" {
					break
				}
				filter.Cursor = page.NextCursor
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("pages differ: got=%v want=%v", got, want)
			}
		})
	}
	// Mutating returned slices must not change later search or aggregation.
	page, _ := index.Query(Filter{Rule: "PI-001", Limit: 1})
	if len(page.Events) != 1 {
		t.Fatal("missing detection")
	}
	page.Events[0].RuleIDs[0] = "mutated"
	again, _ := index.Query(Filter{Rule: "PI-001", Q: "PI-001", Limit: 1})
	if len(again.Events) != 1 || again.Events[0].RuleIDs[0] != "PI-001" {
		t.Fatal("query result aliases retained data")
	}
	sources := index.Sources(time.Time{}, base.Add(time.Hour))
	sources[0].Sensors[0] = "mutated"
	if index.Sources(time.Time{}, base.Add(time.Hour))[0].Sensors[0] == "mutated" {
		t.Fatal("source result aliases retained data")
	}
}

func TestSecondarySelectorsEvictKeysAndCursorAnchors(t *testing.T) {
	index, err := New(31, observe.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	var oldCursor string
	for i := 0; i < 500; i++ {
		e := event.Envelope{ID: fmt.Sprintf("%032x", i), Time: now.Add(time.Duration(i) * time.Second), Sensor: event.SensorRef{ID: fmt.Sprintf("sensor-%d", i), Kind: "http"}, Classification: "interaction", Observation: json.RawMessage(fmt.Sprintf(`{"remote_host":"synthetic-%d","detection":{"findings":[{"rule_id":"PI-001"}]}}`, i))}
		index.AddForwarded(e, fmt.Sprintf("%032x", i))
		if i == 30 {
			p, err := index.Query(Filter{Limit: 10})
			if err != nil {
				t.Fatal(err)
			}
			oldCursor = p.NextCursor
		}
	}
	retained := index.Stats().Events
	if retained != 31 || len(index.ordinals) != retained || len(index.ids) != retained {
		t.Fatal("retention/anchor bounds")
	}
	for field, values := range index.selectors {
		if len(values) > retained {
			t.Fatalf("field %d retained stale keys", field)
		}
		links := 0
		for _, items := range values {
			if items.Len() == 0 {
				t.Fatal("empty selector retained")
			}
			for e := items.Front(); e != nil; e = e.Next() {
				item := e.Value.(*entry)
				if index.ordinals[item.ordinal] == nil {
					t.Fatal("selector references evicted entry")
				}
				links++
			}
		}
		if links != retained {
			t.Fatalf("field %d links=%d retained=%d", field, links, retained)
		}
	}
	p, err := index.Query(Filter{Limit: 10, Cursor: oldCursor})
	if err != nil || len(p.Events) != 0 || p.TotalMatched != retained {
		t.Fatalf("evicted cursor anchor: %+v %v", p, err)
	}
	// An entry older than the retained horizon is immediately evicted from every list.
	e := event.Envelope{ID: strings.Repeat("e", 32), Time: now.Add(-time.Hour), Sensor: event.SensorRef{ID: "late", Kind: "tcp"}, Classification: "interaction", Observation: json.RawMessage(`{"remote_host":"late"}`)}
	index.Add(e)
	for _, f := range []Filter{{Sensor: "late"}, {Kind: "tcp"}, {Source: "late"}} {
		f.Limit = 10
		p, err := index.Query(f)
		if err != nil || p.TotalMatched != 0 {
			t.Fatalf("late eviction leaked: %+v %v", p, err)
		}
	}
}

func TestConcurrentWindowSnapshotsDoNotAliasEntries(t *testing.T) {
	index, err := New(64, observe.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 500; i++ {
			e := event.Envelope{ID: fmt.Sprintf("%032x", i), Time: base.Add(time.Duration(i) * time.Millisecond), Sensor: event.SensorRef{ID: "synthetic", Kind: "http"}, Classification: "interaction", Observation: json.RawMessage(`{"remote_host":"203.0.113.7","detection":{"findings":[{"rule_id":"PI-001"}]}}`)}
			index.AddForwarded(e, strings.Repeat("a", 32))
		}
	}()
	for range 50 {
		overview, err := index.Overview("24h", base.Add(time.Hour))
		if err != nil {
			t.Error(err)
		}
		if len(overview.TopSources) > 0 {
			overview.TopSources[0].Sensors[0] = "mutated"
		}
		page, err := index.Query(Filter{Limit: 10})
		if err != nil {
			t.Error(err)
		}
		for _, summary := range page.Events {
			summary.Node.Name = "mutated"
			summary.RuleIDs[0] = "mutated"
		}
	}
	<-done
	overview, err := index.Overview("24h", base.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if overview.Totals.Events != 64 || len(overview.TopRules) != 1 || overview.TopRules[0].RuleID != "PI-001" || overview.TopSources[0].Sensors[0] != "synthetic" {
		t.Fatal("mutations leaked into retained projections")
	}
}
