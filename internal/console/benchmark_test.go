package console

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/testutil/benchfixture"
)

func benchmarkServer(b *testing.B, tenants int) (*Server, []*evidenceindex.Index) {
	b.Helper()
	indexes := benchfixture.Indexes(b, tenants)
	opts := Options{Config: config.Console{Enabled: true, Listen: "127.0.0.1:0", SessionTTLSeconds: 3600, IndexMaxEvents: 50000}, StateDir: filepath.Join(b.TempDir(), "console"), Index: indexes[0], Runtime: absentRuntime{}, Meter: observe.NewRegistry(), TenantIndexes: map[string]*evidenceindex.Index{}}
	for i, index := range indexes {
		name := fmt.Sprintf("tenant-%d", i)
		opts.Config.Tenants = append(opts.Config.Tenants, name)
		opts.TenantIndexes[name] = index
		opts.Config.Operators = append(opts.Config.Operators, config.Operator{Name: name, Role: "viewer", Tenants: []string{name}, TokenSHA256: auth.Digest("synthetic-" + name)})
	}
	opts.Config.LocalTenant = opts.Config.Tenants[0]
	s, err := New(opts)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		if err := s.Close(context.Background()); err != nil {
			b.Fatal(err)
		}
	})
	return s, indexes
}

func BenchmarkConsoleRequest(b *testing.B) {
	for _, tenants := range []int{1, 8} {
		b.Run(fmt.Sprintf("tenants=%d", tenants), func(b *testing.B) {
			s, _ := benchmarkServer(b, tenants)
			cookies := make([]*http.Cookie, tenants)
			for i := range cookies {
				r := httptest.NewRequest("POST", "http://"+s.Addr()+"/api/v1/session", strings.NewReader(fmt.Sprintf(`{"token":"synthetic-tenant-%d"}`, i)))
				r.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				s.ServeHTTP(w, r)
				if w.Code != 200 {
					b.Fatalf("login: %d %s", w.Code, w.Body.String())
				}
				cookies[i] = w.Result().Cookies()[0]
			}
			for _, path := range []string{"/events?limit=50", "/overview", "/session"} {
				for _, method := range []string{"Cookie", "Bearer"} {
					b.Run(strings.Split(path, "?")[0][1:]+"/"+method, func(b *testing.B) {
						requests := make([]*http.Request, tenants)
						for i := range requests {
							r := httptest.NewRequest("GET", "http://"+s.Addr()+"/api/v1"+path, nil)
							if method == "Cookie" {
								r.AddCookie(cookies[i])
							} else {
								r.Header.Set("Authorization", fmt.Sprintf("Bearer synthetic-tenant-%d", i))
							}
							requests[i] = r
						}
						b.ReportAllocs()
						b.ResetTimer()
						for i := 0; i < b.N; i++ {
							w := httptest.NewRecorder()
							s.ServeHTTP(w, requests[i%tenants])
							if w.Code != 200 {
								b.Fatalf("request: %d %s", w.Code, w.Body.String())
							}
						}
					})
				}
			}
		})
	}
}

// streamBenchWriter exercises the real stream handler without socket/client cost.
// A blocked writer models a slow client; cleanup always releases and joins it.
type streamBenchWriter struct {
	header http.Header
	ready  chan struct{}
	once   sync.Once
	writes atomic.Int64
	block  <-chan struct{}
}

func (w *streamBenchWriter) Header() http.Header              { return w.header }
func (w *streamBenchWriter) WriteHeader(int)                  {}
func (w *streamBenchWriter) SetWriteDeadline(time.Time) error { return nil }
func (w *streamBenchWriter) Flush()                           { w.once.Do(func() { close(w.ready) }) }
func (w *streamBenchWriter) Write(p []byte) (int, error) {
	if w.block != nil {
		<-w.block
	}
	w.writes.Add(1)
	return len(p), nil
}

func BenchmarkSSEFanout(b *testing.B) {
	for _, tc := range []struct {
		name  string
		count int
		slow  bool
	}{{"One", 1, false}, {"Sixteen", 16, false}, {"Slow", 16, true}} {
		b.Run(tc.name, func(b *testing.B) {
			s, indexes := benchmarkServer(b, 1)
			ctx, cancel := context.WithCancel(context.Background())
			var wg sync.WaitGroup
			release := make(chan struct{})
			defer func() { cancel(); close(release); wg.Wait() }()
			writers := make([]*streamBenchWriter, tc.count)
			for i := range writers {
				w := &streamBenchWriter{header: http.Header{}, ready: make(chan struct{})}
				if tc.slow && i == 0 {
					w.block = release
				}
				writers[i] = w
				r := httptest.NewRequest("GET", "http://"+s.Addr()+"/api/v1/events/stream", nil).WithContext(ctx)
				r.Header.Set("Authorization", "Bearer synthetic-tenant-0")
				wg.Add(1)
				go func() { defer wg.Done(); s.ServeHTTP(w, r) }()
				select {
				case <-w.ready:
				case <-time.After(5 * time.Second):
					b.Fatal("stream not ready")
				}
			}

			// At least 64 events are needed to overflow the slow subscription's 32 slots.
			// Each benchmark operation is a 100-event, 1000/s paced batch.
			e := benchfixture.Envelope(50000)
			ids := make([]string, 65536)
			for i := range ids {
				ids[i] = fmt.Sprintf("%032x", 50000+i)
			}
			b.ReportAllocs()
			b.ResetTimer()
			var active time.Duration
			pacedStart := time.Now()
			for i := 0; i < b.N; i++ {
				for j := 0; j < 100; j++ {
					n := i*100 + j
					// Absolute deadlines catch up after scheduler jitter instead of silently
					// discarding ticker slots and lowering the offered event rate.
					if delay := time.Until(pacedStart.Add(time.Duration(n+1) * time.Millisecond)); delay > 0 {
						time.Sleep(delay)
					}
					e.ID = ids[n%len(ids)]
					e.Time = benchfixture.Now.Add(time.Duration(n) * time.Millisecond)
					start := time.Now()
					indexes[0].Add(e)
					active += time.Since(start)
				}
			}
			// Wait for healthy readers so allocations include encoding and writes, not just enqueue.
			target := int64(b.N * 100)
			deadline := time.Now().Add(time.Second)
			for i, w := range writers {
				if tc.slow && i == 0 {
					continue
				}
				for w.writes.Load() < target && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if w.writes.Load() != target {
					b.Fatal("healthy subscriber lost events")
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(active.Nanoseconds())/float64(b.N*100), "append-ns/event")
			b.ReportMetric(100, "events/op")
			b.ReportMetric(float64(b.N*100)/time.Since(pacedStart).Seconds(), "events/s")
		})
	}
}
