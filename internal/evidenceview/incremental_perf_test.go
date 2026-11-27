//go:build perf

package evidenceview_test

import (
	"fmt"
	"os"
	goruntime "runtime"
	"sort"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/demoseed"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/evidenceview"
	"github.com/metaforismo/aegismesh/internal/observe"
)

// TestPerfIncrementalSessions measures, on the seeded large profile, the cost
// of sessions plus campaigns after one append: full recompute versus
// UpdateSessions. Run: go test -tags perf -run TestPerfIncrementalSessions -v ./internal/evidenceview
func TestPerfIncrementalSessions(t *testing.T) {
	cfg, err := demoseed.Config(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	cfg.Correlation.Enabled = &enabled
	name := os.Getenv("AEGISMESH_PERF_PROFILE")
	if name == "" {
		name = demoseed.Large
	}
	profile, err := demoseed.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	index, err := evidenceindex.New(50000, observe.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := demoseed.Generate(profile, cfg, time.Now(), func(e event.Envelope) error { index.Add(e); return nil }); err != nil {
		t.Fatal(err)
	}
	recent, _ := index.EnvelopesAt(500)
	previous := index.SharedAnalysis()
	sessions := evidenceview.Sessions("local", previous.Events)
	t.Logf("retained %d, sample %d, sessions %d, campaigns %d", previous.Index.Events, len(previous.Events), len(sessions),
		len(evidenceview.Campaigns("local", sessions).Campaigns))

	measure := func(fn func()) (time.Duration, uint64, uint64) {
		var before, after goruntime.MemStats
		goruntime.GC()
		goruntime.ReadMemStats(&before)
		start := time.Now()
		fn()
		elapsed := time.Since(start)
		goruntime.ReadMemStats(&after)
		return elapsed, after.TotalAlloc - before.TotalAlloc, after.Mallocs - before.Mallocs
	}
	type row struct {
		d             time.Duration
		bytes, allocs uint64
	}
	var full, incremental, sessionsOnly, campaignsOnly []row
	const rounds = 60
	for i := range rounds {
		e := recent[i%len(recent)]
		e.ID = fmt.Sprintf("%032x", 0xabc00000+i)
		e.Time = time.Now().UTC()
		index.Add(e)
		snapshot := index.SharedAnalysis()
		var want []evidenceview.Session
		d, b, a := measure(func() {
			want = evidenceview.Sessions("local", snapshot.Events)
			evidenceview.Campaigns("local", want)
		})
		full = append(full, row{d, b, a})
		var got []evidenceview.Session
		d, b, a = measure(func() {
			got = evidenceview.UpdateSessions("local", previous.Events, sessions, snapshot.Events)
			evidenceview.Campaigns("local", got)
		})
		incremental = append(incremental, row{d, b, a})
		d, b, a = measure(func() { evidenceview.UpdateSessions("local", previous.Events, sessions, snapshot.Events) })
		sessionsOnly = append(sessionsOnly, row{d, b, a})
		d, b, a = measure(func() { evidenceview.Campaigns("local", got) })
		campaignsOnly = append(campaignsOnly, row{d, b, a})
		if len(got) != len(want) {
			t.Fatal("incremental result differs")
		}
		previous, sessions = snapshot, got
	}
	report := func(label string, rows []row) {
		sort.Slice(rows, func(i, j int) bool { return rows[i].d < rows[j].d })
		p50, p95 := rows[len(rows)/2], rows[len(rows)*95/100]
		var bytes, allocs uint64
		for _, r := range rows {
			bytes += r.bytes
			allocs += r.allocs
		}
		t.Logf("%-42s p50 %8.3f ms  p95 %8.3f ms  %10d B/op  %7d allocs/op", label,
			float64(p50.d.Microseconds())/1000, float64(p95.d.Microseconds())/1000, bytes/uint64(len(rows)), allocs/uint64(len(rows)))
	}
	report("full Sessions+Campaigns after append", full)
	report("UpdateSessions+Campaigns after append", incremental)
	report("UpdateSessions only", sessionsOnly)
	report("Campaigns only (over updated sessions)", campaignsOnly)
}
