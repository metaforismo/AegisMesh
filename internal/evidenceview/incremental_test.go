package evidenceview

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

// sampleModel mimics the index: chronological order with insertion order
// breaking ties, eviction of the oldest beyond capacity, and a newest-first
// sample of at most limit summaries.
type sampleModel struct {
	all      []evidenceindex.Summary
	capacity int
	limit    int
}

func (m *sampleModel) add(e evidenceindex.Summary) {
	at := Time(e)
	position := len(m.all)
	for position > 0 && Time(m.all[position-1]).After(at) {
		position--
	}
	m.all = append(m.all, evidenceindex.Summary{})
	copy(m.all[position+1:], m.all[position:])
	m.all[position] = e
	if len(m.all) > m.capacity {
		m.all = m.all[len(m.all)-m.capacity:]
	}
}

func (m *sampleModel) sample() []evidenceindex.Summary {
	out := []evidenceindex.Summary{}
	for i := len(m.all) - 1; i >= 0 && len(out) < m.limit; i-- {
		out = append(out, m.all[i])
	}
	return out
}

var scripts = [][]string{
	{"GET /api/tags → 200", "GET /v1/models → 200", "POST /v1/chat/completions → 200", "GET /.env → 404"},
	{"GET /admin → 403", "GET /wp-login.php → 404", "GET /.git/config → 404", "POST /login → 401"},
	{"GET / → 200", "GET /robots.txt → 404", "GET /v1/models → 200", "GET /metrics → 404"},
}

// scripted emits each source's next step of a fixed script, so sessions of
// different sources share step sequences and campaigns form; steps reset
// after an idle gap so new sessions start at the script's first step.
type scripted struct{ next map[string]int }

func (g *scripted) summary(r *rand.Rand, n int, clock time.Time) evidenceindex.Summary {
	number := r.IntN(12)
	source := fmt.Sprintf("198.51.100.%d", number)
	if r.IntN(25) == 0 {
		source = "" // unknown peers are never grouped
	}
	e := evidenceindex.Summary{
		ID: fmt.Sprintf("%032x", n), Time: clock.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
		Source: source, Classification: "interaction", RuleIDs: []string{},
		Sensor: event.SensorRef{ID: "web", Kind: "http"}, HTTPStatus: 0,
	}
	switch r.IntN(8) {
	case 0:
		e.Sensor = event.SensorRef{ID: "corr", Kind: "http"}
		e.Classification = event.ClassificationCorrelationSignal
		e.RuleIDs = []string{"COR-008"}
	case 1:
		e.Sensor = event.SensorRef{ID: "mcp", Kind: "mcp"}
		e.Summary = "tools/call list_files"
	default:
		script := scripts[number%len(scripts)]
		e.Summary = script[g.next[source]%len(script)]
		g.next[source]++
		fmt.Sscanf(e.Summary[len(e.Summary)-3:], "%d", &e.HTTPStatus)
		e.ClientFamily = []string{"openai_python", "curl"}[number%2]
	}
	if r.IntN(5) == 0 {
		e.RuleIDs = append(e.RuleIDs, "HT-001")
		e.Severity = "critical"
	}
	if r.IntN(9) == 0 {
		e.Node = &evidenceindex.Node{ID: "00000000000000000000000000000abc"}
	}
	return e
}

// TestUpdateSessionsMatchesFullRecompute appends random batches (with
// out-of-order times, idle gaps, eviction and sample truncation) and compares
// the incremental result with a full Sessions/Campaigns recompute at every step.
func TestUpdateSessionsMatchesFullRecompute(t *testing.T) {
	for seed := range uint64(6) {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			r := rand.New(rand.NewPCG(seed, 99))
			model := &sampleModel{capacity: 150 + r.IntN(400), limit: 100 + r.IntN(300)}
			clock := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
			var previousEvents []evidenceindex.Summary
			var previous []Session
			incremental, n, withCampaigns := 0, 0, 0
			generator := &scripted{next: map[string]int{}}
			for step := range 120 {
				for range 1 + r.IntN(12) {
					n++
					clock = clock.Add(time.Duration(r.IntN(90_000)) * time.Millisecond)
					if r.IntN(25) == 0 {
						clock = clock.Add(IdleGap + time.Minute) // idle gap splits sessions
						generator.next = map[string]int{}
					}
					at := clock
					if r.IntN(6) == 0 {
						at = clock.Add(-time.Duration(r.IntN(600)) * time.Second) // native time precedes
					}
					model.add(generator.summary(r, n, at))
				}
				events := model.sample()
				if _, ok := sampleDiff(previousEvents, events); ok && previous != nil {
					incremental++
				}
				got := UpdateSessions("tenant-a", previousEvents, previous, events)
				want := Sessions("tenant-a", events)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("step %d: incremental sessions differ from full recompute", step)
				}
				gotJSON, _ := json.Marshal(got)
				wantJSON, _ := json.Marshal(want)
				if string(gotJSON) != string(wantJSON) {
					t.Fatalf("step %d: JSON differs", step)
				}
				campaigns := Campaigns("tenant-a", want)
				if !reflect.DeepEqual(Campaigns("tenant-a", got), campaigns) {
					t.Fatalf("step %d: campaigns differ", step)
				}
				if len(campaigns.Campaigns) > 0 {
					withCampaigns++
				}
				previousEvents, previous = events, got
			}
			if incremental < 100 || withCampaigns < 40 {
				t.Fatalf("incremental path %d/120, steps with campaigns %d/120: the equivalence check is too weak", incremental, withCampaigns)
			}
		})
	}
}

func TestSampleDiffFallsBack(t *testing.T) {
	mk := func(ids ...int) []evidenceindex.Summary {
		out := []evidenceindex.Summary{}
		for _, id := range ids {
			out = append(out, evidenceindex.Summary{ID: fmt.Sprint(id), Source: fmt.Sprint("s", id%3)})
		}
		return out
	}
	tests := []struct {
		name     string
		previous []int
		next     []int
		ok       bool
		affected []string
	}{
		{"append at newest end", []int{3, 2, 1}, []int{5, 4, 3, 2, 1}, true, []string{"s1", "s2"}},
		{"insert in the middle", []int{3, 2, 1}, []int{3, 4, 2, 1}, true, []string{"s1"}},
		{"tail eviction", []int{3, 2, 1}, []int{4, 3, 2}, true, []string{"s1"}},
		{"identical", []int{3, 2, 1}, []int{3, 2, 1}, true, []string{}},
		{"middle removal", []int{3, 2, 1}, []int{3, 1}, false, nil},
		{"reorder", []int{3, 2, 1}, []int{2, 3, 1}, false, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			affected, ok := sampleDiff(mk(test.previous...), mk(test.next...))
			if ok != test.ok {
				t.Fatalf("ok = %v", ok)
			}
			if ok {
				got := []string{}
				for source := range affected {
					got = append(got, source)
				}
				sort.Strings(got)
				if !reflect.DeepEqual(got, test.affected) {
					t.Fatalf("affected = %v; want %v", got, test.affected)
				}
			}
		})
	}
	large := make([]int, MaxIncrementalChange+1)
	for i := range large {
		large[i] = i + 10
	}
	if _, ok := sampleDiff(mk(1), mk(append(large, 1)...)); ok {
		t.Fatal("oversized change handled incrementally")
	}
}
