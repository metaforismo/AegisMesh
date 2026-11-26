//go:build perf

// Seeded console performance harness. Not part of `make test`; run with
// `make perf` (see docs/performance/2026-11-26). Results are local synthetic
// latency samples through the in-process handler stack, not capacity.
package console

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/demoseed"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/storage"
)

const perfToken = "synthetic-perf-admin"

type perfRow struct {
	name        string
	n           int
	p50, p95    time.Duration
	max         time.Duration
	bytesPerOp  uint64
	allocsPerOp uint64
	respBytes   int
}

type perfReport struct {
	mu   sync.Mutex
	rows []string
}

func (r *perfReport) add(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows = append(r.rows, fmt.Sprintf(format, args...))
}

func (r *perfReport) write(t *testing.T) {
	out := strings.Join(r.rows, "\n") + "\n"
	t.Log("\n" + out)
	if path := os.Getenv("AEGISMESH_PERF_OUT"); path != "" {
		if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func perfProfile(t *testing.T) demoseed.Profile {
	name := os.Getenv("AEGISMESH_PERF_PROFILE")
	if name == "" {
		name = demoseed.Large
	}
	profile, err := demoseed.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func perfConfig(t *testing.T) *config.Config {
	cfg, err := demoseed.Config(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	cfg.Correlation.Enabled = &enabled
	cfg.Console = config.Console{
		Enabled: true, Listen: "127.0.0.1:0", SessionTTLSeconds: 3600, IndexMaxEvents: 50000,
		SettingsEditing: config.SettingsEditingConsole,
		Operators:       []config.Operator{{Name: "perf-admin", Role: "admin", TokenSHA256: auth.Digest(perfToken)}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func heapInUse() uint64 {
	var stats goruntime.MemStats
	for range 3 {
		goruntime.GC()
	}
	goruntime.ReadMemStats(&stats)
	return stats.HeapAlloc
}

// TestPerfSeededConsole measures seeded backfill, index memory, every console
// GET the UI issues, and SSE fan-out. It reports; it asserts only correctness.
func TestPerfSeededConsole(t *testing.T) {
	profile := perfProfile(t)
	cfg := perfConfig(t)
	report := &perfReport{}
	defer report.write(t)
	report.add("profile=%s go=%s GOMAXPROCS=%d GOOS/GOARCH=%s/%s", profile.Name, goruntime.Version(), goruntime.GOMAXPROCS(0), goruntime.GOOS, goruntime.GOARCH)

	// Seed through real storage, then time the runtime's backfill loop.
	store, err := storage.New(storage.Options{Dir: cfg.Runtime.DataDir, MaxFileBytes: cfg.Storage.MaxFileBytes, MaxEventBytes: cfg.Storage.MaxEventBytes, MaxEvents: cfg.Storage.Retention.MaxEvents, MaxAgeDays: cfg.Storage.Retention.MaxAgeDays})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	seeded, err := demoseed.Generate(profile, cfg, time.Now(), func(e event.Envelope) error { return store.Append(context.Background(), e) })
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	report.add("seed: %d events + %d signals, %d sources; generate+append %s", seeded.Events, seeded.Signals, seeded.Sources, time.Since(start).Round(time.Millisecond))

	before := heapInUse()
	index, err := evidenceindex.New(cfg.Console.IndexMaxEvents, observe.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	reader, err := storage.NewReader(cfg.Runtime.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	read := 0
	if err := reader.ForEach(func(e event.Envelope) error {
		if e.Validate() != nil || e.VerifyIntegrity() != nil || !evidenceindex.ValidID(e.ID) {
			t.Fatalf("corrupt seeded envelope %s", e.ID)
		}
		read++
		index.Add(e)
		return nil
	}, func(_ string, err error) { t.Fatal(err) }); err != nil {
		t.Fatal(err)
	}
	backfill := time.Since(start)
	stats := index.Stats()
	after := heapInUse()
	report.add("backfill (storage read + validate + verify + index add, as runtime buildConsole): %d envelopes in %s; retained %d (history %s)", read, backfill.Round(time.Millisecond), stats.Events, stats.History)
	report.add("index heap: %.1f MiB live heap after GC for %d retained entries (%.0f B/entry; includes index structures)", float64(after-before)/(1<<20), stats.Events, float64(after-before)/float64(max(stats.Events, 1)))

	decoys, markers := DecoyCatalog(cfg)
	facts := PostureFacts(cfg)
	s, err := New(Options{
		Posture: &facts, Decoys: decoys, Honeytokens: markers, Config: cfg.Console,
		StateDir: filepath.Join(t.TempDir(), "console"), Index: index, Runtime: absentRuntime{}, Meter: observe.NewRegistry(),
		TenantIndexes: map[string]*evidenceindex.Index{},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(context.Background()) }()

	get := func(path string) (int, []byte) {
		r := httptest.NewRequest("GET", "http://"+s.Addr()+path, nil)
		r.Header.Set("Authorization", "Bearer "+perfToken)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w.Code, w.Body.Bytes()
	}
	decodeInto := func(path string, value any) {
		code, body := get(path)
		if code != 200 {
			t.Fatalf("%s: %d %s", path, code, body)
		}
		if err := json.Unmarshal(body, value); err != nil {
			t.Fatal(err)
		}
	}
	var page struct {
		Events []struct {
			ID string `json:"id"`
		} `json:"events"`
		NextCursor string `json:"next_cursor"`
	}
	decodeInto("/api/v1/events?limit=50", &page)
	var sessions struct {
		Sessions []struct {
			ID string `json:"id"`
		} `json:"sessions"`
	}
	decodeInto("/api/v1/sessions?window=7d&limit=50", &sessions)
	var campaigns struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
		Total int `json:"total_campaigns"`
	}
	decodeInto("/api/v1/campaigns", &campaigns)
	if len(page.Events) == 0 || page.NextCursor == "" || len(sessions.Sessions) == 0 || len(campaigns.Items) == 0 {
		t.Fatalf("seeded console is missing data: events=%d sessions=%d campaigns=%d", len(page.Events), len(sessions.Sessions), len(campaigns.Items))
	}
	report.add("analysis sample: sessions(7d page)=%d campaigns=%d", len(sessions.Sessions), campaigns.Total)

	endpoints := []struct{ name, path string }{
		{"overview 1h", "/api/v1/overview?window=1h"},
		{"overview 24h", "/api/v1/overview?window=24h"},
		{"overview 7d", "/api/v1/overview?window=7d"},
		{"events limit=50", "/api/v1/events?limit=50"},
		{"events page 2 (cursor)", "/api/v1/events?limit=50&cursor=" + page.NextCursor},
		{"events classification=canary_invocation", "/api/v1/events?limit=50&classification=canary_invocation"},
		{"events sensor=demo-ssh", "/api/v1/events?limit=50&sensor=demo-ssh"},
		{"events q=env", "/api/v1/events?limit=50&q=env"},
		{"event detail", "/api/v1/events/" + page.Events[0].ID},
		{"sessions 24h", "/api/v1/sessions?window=24h&limit=50"},
		{"sessions 7d", "/api/v1/sessions?window=7d&limit=50"},
		{"session detail", "/api/v1/sessions/" + sessions.Sessions[0].ID},
		{"campaigns", "/api/v1/campaigns"},
		{"campaign detail", "/api/v1/campaigns/" + campaigns.Items[0].ID},
		{"coverage 7d", "/api/v1/coverage?window=7d"},
		{"posture", "/api/v1/posture"},
		{"digest 24h", "/api/v1/digest?window=24h"},
		{"digest 7d", "/api/v1/digest?window=7d"},
		{"sources 24h", "/api/v1/sources?window=24h"},
		{"decoys 24h", "/api/v1/decoys?window=24h"},
		{"honeytokens 24h", "/api/v1/honeytokens?window=24h"},
		{"recommendations", "/api/v1/recommendations"},
		{"settings", "/api/v1/admin/settings"},
		{"system", "/api/v1/system"},
		{"me", "/api/v1/me"},
	}
	report.add("")
	report.add("| Endpoint | n | p50 | p95 | max | B/op | allocs/op | response bytes |")
	report.add("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
	for _, endpoint := range endpoints {
		row := measure(t, endpoint.name, func() (int, []byte) { return get(endpoint.path) }, nil)
		report.add("| %s | %d | %s | %s | %s | %d | %d | %d |", row.name, row.n, ms(row.p50), ms(row.p95), ms(row.max), row.bytesPerOp, row.allocsPerOp, row.respBytes)
	}
	served := heapInUse()
	report.add("live heap after serving every endpoint once warm: %.1f MiB above the pre-index baseline (index %.1f MiB + server state and any memoised analysis %.1f MiB)",
		float64(served-before)/(1<<20), float64(after-before)/(1<<20), (float64(served)-float64(after))/(1<<20))
	// Cold analysis: one append between requests invalidates any per-generation reuse.
	extra := 0
	appendOne := func() {
		e := benchEnvelope(extra)
		extra++
		index.Add(e)
	}
	for _, endpoint := range []struct{ name, path string }{
		{"sessions 24h, append before each", "/api/v1/sessions?window=24h&limit=50"},
		{"campaigns, append before each", "/api/v1/campaigns"},
		{"overview 24h, append before each", "/api/v1/overview?window=24h"},
		{"posture, append before each", "/api/v1/posture"},
	} {
		row := measure(t, endpoint.name, func() (int, []byte) { return get(endpoint.path) }, appendOne)
		report.add("| %s | %d | %s | %s | %s | %d | %d | %d |", row.name, row.n, ms(row.p50), ms(row.p95), ms(row.max), row.bytesPerOp, row.allocsPerOp, row.respBytes)
	}

	report.add("")
	report.add("| SSE subscribers | events | delivery p50 | delivery p95 | max | append p50 | append p95 |")
	report.add("| ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
	for _, subscribers := range []int{1, 4, 16} {
		report.add("%s", sseFanout(t, s, index, subscribers))
	}
}

func ms(d time.Duration) string { return fmt.Sprintf("%.3f ms", float64(d)/float64(time.Millisecond)) }

// benchEnvelope is a fresh, valid synthetic observation newer than the seed.
func benchEnvelope(n int) event.Envelope {
	observation := json.RawMessage(fmt.Sprintf(`{"method":"GET","path":"/perf","remote_host":"192.0.2.250","response":{"status":404},"synthetic":true,"n":%d}`, n))
	return event.Envelope{
		Schema: event.SchemaV1, ID: fmt.Sprintf("%032x", 0xfeed0000+n), Time: time.Now().UTC(), Seq: uint64(n + 1),
		Instance: "synthetic-perf", Sensor: event.SensorRef{ID: "demo-http", Kind: "http", Listen: "127.0.0.1:0"},
		Classification: event.ClassificationInteraction,
		Integrity:      event.Integrity{PayloadSHA256: event.SHA256Hex(observation), Algorithm: "sha256"},
		Observation:    observation,
	}
}

// measure runs one request repeatedly within a time budget and reports the
// latency distribution plus average heap allocation per request (including
// the recorder). setup, when set, runs untimed before each request.
func measure(t *testing.T, name string, request func() (int, []byte), setup func()) perfRow {
	for range 3 {
		if setup != nil {
			setup()
		}
		if code, body := request(); code != 200 {
			t.Fatalf("%s: %d %s", name, code, body)
		}
	}
	const maxRuns, minRuns, budget = 300, 30, 4 * time.Second
	durations := make([]time.Duration, 0, maxRuns)
	var before, after goruntime.MemStats
	goruntime.GC()
	goruntime.ReadMemStats(&before)
	started := time.Now()
	size := 0
	var setupAlloc, setupMallocs uint64
	for len(durations) < maxRuns && (len(durations) < minRuns || time.Since(started) < budget) {
		if setup != nil {
			var a, b goruntime.MemStats
			goruntime.ReadMemStats(&a)
			setup()
			goruntime.ReadMemStats(&b)
			setupAlloc += b.TotalAlloc - a.TotalAlloc
			setupMallocs += b.Mallocs - a.Mallocs
		}
		begin := time.Now()
		code, body := request()
		durations = append(durations, time.Since(begin))
		if code != 200 {
			t.Fatalf("%s: %d", name, code)
		}
		size = len(body)
	}
	goruntime.ReadMemStats(&after)
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	n := uint64(len(durations))
	return perfRow{
		name: name, n: len(durations), p50: percentile(durations, 50), p95: percentile(durations, 95), max: durations[len(durations)-1],
		bytesPerOp: (after.TotalAlloc - before.TotalAlloc - setupAlloc) / n, allocsPerOp: (after.Mallocs - before.Mallocs - setupMallocs) / n,
		respBytes: size,
	}
}

// percentile uses the nearest-rank method on sorted samples.
func percentile(sorted []time.Duration, p int) time.Duration {
	rank := (p*len(sorted) + 99) / 100
	return sorted[max(rank, 1)-1]
}

type sseWriter struct {
	header http.Header
	ready  chan struct{}
	once   sync.Once
	mu     sync.Mutex
	seen   map[string]time.Time
}

func (w *sseWriter) Header() http.Header              { return w.header }
func (w *sseWriter) WriteHeader(int)                  {}
func (w *sseWriter) SetWriteDeadline(time.Time) error { return nil }
func (w *sseWriter) Flush()                           { w.once.Do(func() { close(w.ready) }) }
func (w *sseWriter) Write(p []byte) (int, error) {
	now := time.Now()
	if i := bytes.Index(p, []byte(`"id":"`)); i >= 0 && len(p) >= i+6+32 {
		w.mu.Lock()
		w.seen[string(p[i+6:i+6+32])] = now
		w.mu.Unlock()
	}
	return len(p), nil
}

// sseFanout appends paced events and measures append-to-write latency per subscriber.
func sseFanout(t *testing.T, s *Server, index *evidenceindex.Index, subscribers int) string {
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	writers := make([]*sseWriter, subscribers)
	for i := range writers {
		w := &sseWriter{header: http.Header{}, ready: make(chan struct{}), seen: map[string]time.Time{}}
		writers[i] = w
		r := httptest.NewRequest("GET", "http://"+s.Addr()+"/api/v1/events/stream", nil).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer "+perfToken)
		wg.Add(1)
		go func() { defer wg.Done(); s.ServeHTTP(w, r) }()
		select {
		case <-w.ready:
		case <-time.After(5 * time.Second):
			t.Fatal("stream not ready")
		}
	}
	const events = 200
	added := make(map[string]time.Time, events)
	appends := make([]time.Duration, 0, events)
	base := 0x5e000000 + subscribers*events
	for n := range events {
		e := benchEnvelope(base + n)
		begin := time.Now()
		index.Add(e)
		appends = append(appends, time.Since(begin))
		added[e.ID] = begin
		time.Sleep(2 * time.Millisecond)
	}
	deadline := time.Now().Add(5 * time.Second)
	latencies := make([]time.Duration, 0, events*subscribers)
	for _, w := range writers {
		for {
			w.mu.Lock()
			count := len(w.seen)
			w.mu.Unlock()
			if count >= events || time.Now().After(deadline) {
				break
			}
			time.Sleep(time.Millisecond)
		}
		w.mu.Lock()
		if len(w.seen) != events {
			t.Fatalf("subscriber received %d of %d events", len(w.seen), events)
		}
		for id, at := range w.seen {
			latencies = append(latencies, at.Sub(added[id]))
		}
		w.mu.Unlock()
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	sort.Slice(appends, func(i, j int) bool { return appends[i] < appends[j] })
	return fmt.Sprintf("| %d | %d | %s | %s | %s | %s | %s |", subscribers, events, ms(percentile(latencies, 50)), ms(percentile(latencies, 95)), ms(latencies[len(latencies)-1]), ms(percentile(appends, 50)), ms(percentile(appends, 95)))
}
