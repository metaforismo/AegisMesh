package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
)

// recMeter records plain-counter increments so tests can assert outcomes
// deterministically.
type recMeter struct {
	mu   sync.Mutex
	vals map[string]float64
}

func newRecMeter() *recMeter { return &recMeter{vals: map[string]float64{}} }

func (m *recMeter) add(name string, v float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.vals[name] += v
}

func (m *recMeter) get(name string) float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.vals[name]
}

func (m *recMeter) Counter(name, _ string) observe.Counter { return recCounter{m, name} }
func (m *recMeter) Gauge(string, string) observe.Gauge     { return nopGauge{} }
func (m *recMeter) CounterVec(string, string, int) observe.LabeledCounter {
	return nopLabeled{}
}
func (m *recMeter) WritePrometheus() string { return "" }

type recCounter struct {
	m    *recMeter
	name string
}

func (c recCounter) Inc()          { c.m.add(c.name, 1) }
func (c recCounter) Add(d float64) { c.m.add(c.name, d) }

type nopGauge struct{}

func (nopGauge) Set(float64) {}
func (nopGauge) Add(float64) {}

type nopLabeled struct{}

func (nopLabeled) Inc(string) {}

const testSecret = "synthetic-hmac-key-for-tests"

func testEnvelope(n int) event.Envelope {
	seq := &event.Sequencer{}
	env, err := event.New(seq, "it", event.SensorRef{ID: "http-decoy", Kind: "http", Listen: "127.0.0.1:8081"},
		event.ClassificationInteraction, json.RawMessage(`{"n":`+strconv.Itoa(n)+`}`), nil)
	if err != nil {
		panic(err)
	}
	return env
}

type sinkOpts func(*Config)

func newTestSink(t *testing.T, srvURL string, opts ...sinkOpts) (*Sink, *recMeter) {
	t.Helper()
	u, err := url.Parse(srvURL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Endpoint:          u,
		Secret:            []byte(testSecret),
		QueueSize:         64,
		BatchSize:         4,
		FlushInterval:     60 * time.Millisecond,
		Timeout:           time.Second,
		MaxRetries:        2,
		ShutdownFlush:     time.Second,
		AllowLoopbackHTTP: true,
	}
	for _, o := range opts {
		o(&cfg)
	}
	m := newRecMeter()
	s, err := New(cfg, m, slog.New(slog.NewTextHandler(&testWriter{}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s, m
}

type testWriter struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (w *testWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *testWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func waitFor(t *testing.T, d time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestOfferConcurrentWithClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	exited := make(chan struct{})
	close(exited)
	meter := newRecMeter()
	s := &Sink{
		cfg:        Config{ShutdownFlush: time.Second},
		ctx:        ctx,
		cancel:     cancel,
		ch:         make(chan event.Envelope, 1024),
		exited:     exited,
		doneSignal: make(chan struct{}),
		c: counters{
			droppedQueueFull: recCounter{meter, "queue_full"},
		},
	}

	start := make(chan struct{})
	var producers sync.WaitGroup
	for i := 0; i < 8; i++ {
		producers.Add(1)
		go func() {
			defer producers.Done()
			<-start
			for j := 0; j < 200; j++ {
				s.Offer(testEnvelope(j))
			}
		}()
	}
	close(start)
	s.Close()
	producers.Wait()
	if s.Offer(testEnvelope(999)) {
		t.Fatal("Offer after Close = true, want false")
	}
}

// collectEventsServer verifies signature headers and records accepted bodies.
func collectEventsServer(t *testing.T, hits chan<- int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = readFull(r, body)
		sig := r.Header.Get("X-AegisMesh-Signature")
		mac := hmac.New(sha256.New, []byte(testSecret))
		mac.Write(body)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(sig), []byte(want)) {
			t.Errorf("bad or missing signature: %q", sig)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("X-AegisMesh-Timestamp") == "" || r.Header.Get("X-AegisMesh-Batch-ID") == "" {
			t.Error("missing timestamp or batch id headers")
		}
		var payload struct {
			Events []struct {
				ID string `json:"id"`
			} `json:"events"`
		}
		if err := json.Unmarshal(body, &payload); err != nil || len(payload.Events) == 0 {
			t.Errorf("unparseable body: %v (%d bytes)", err, len(body))
		}
		hits <- len(payload.Events)
		w.WriteHeader(http.StatusNoContent)
	}))
}

func readFull(r *http.Request, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Body.Read(buf[total:])
		total += n
		if err != nil {
			return total, nil // EOF is fine
		}
	}
	return total, nil
}

func TestSuccessfulSignedDelivery(t *testing.T) {
	hits := make(chan int, 16)
	srv := collectEventsServer(t, hits)
	defer srv.Close()

	s, m := newTestSink(t, srv.URL)
	const want = 6
	for i := 0; i < want; i++ {
		if !s.Offer(testEnvelope(i)) {
			t.Fatalf("offer %d rejected unexpectedly", i)
		}
	}
	waitFor(t, 3*time.Second, func() bool { return m.get("aegismesh_webhook_delivered_events_total") == want },
		"delivered count")
	got := 0
	for len(hits) > 0 {
		got += <-hits
	}
	if got != want {
		t.Fatalf("server accepted %d events, want %d", got, want)
	}
	s.Close()
}

func TestRetryThenSuccess(t *testing.T) {
	var mu sync.Mutex
	failures := 2
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if failures > 0 {
			failures--
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	s, m := newTestSink(t, srv.URL)
	for i := 0; i < 4; i++ {
		s.Offer(testEnvelope(i))
	}
	waitFor(t, 4*time.Second, func() bool { return m.get("aegismesh_webhook_delivered_events_total") == 4 },
		"delivery after retries")
	if got := m.get("aegismesh_webhook_retry_attempts_total"); got != 2 {
		t.Fatalf("retry attempts = %v, want 2", got)
	}
	s.Close()
}

func TestExhaustedRetriesThenRecovery(t *testing.T) {
	var mu sync.Mutex
	firstBatch := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if firstBatch {
			w.WriteHeader(http.StatusBadGateway) // every retry of batch one fails
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	s, m := newTestSink(t, srv.URL, func(c *Config) { c.BatchSize = 2; c.MaxRetries = 1 })
	s.Offer(testEnvelope(1))
	s.Offer(testEnvelope(2))
	waitFor(t, 4*time.Second, func() bool { return m.get("aegismesh_webhook_failed_batches_total") == 1 },
		"first batch to fail permanently")

	// Sink stays healthy: the next batch goes through.
	mu.Lock()
	firstBatch = false
	mu.Unlock()
	s.Offer(testEnvelope(3))
	s.Offer(testEnvelope(4))
	waitFor(t, 4*time.Second, func() bool { return m.get("aegismesh_webhook_delivered_events_total") == 2 },
		"recovery delivery")

	if got := m.get("aegismesh_webhook_dropped_failed_total"); got != 2 {
		t.Fatalf("dropped_failed = %v, want 2", got)
	}
	s.Close()
}

func TestAttemptTimeoutIsBounded(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	s, m := newTestSink(t, srv.URL, func(c *Config) {
		c.Timeout = 200 * time.Millisecond
		c.MaxRetries = 1
	})
	start := time.Now()
	s.Offer(testEnvelope(1))
	waitFor(t, 5*time.Second, func() bool { return m.get("aegismesh_webhook_failed_batches_total") >= 1 },
		"failed batches after timeouts")
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("retry cycle exceeded its bound: %v", elapsed)
	}
	s.forceStop() // unblock handler waiters deterministically
	s.Close()
}

func TestRedirectsAreNeverFollowed(t *testing.T) {
	hopHits := 0
	var hopMu sync.Mutex
	hop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hopMu.Lock()
		hopHits++
		hopMu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer hop.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, hop.URL, http.StatusFound)
	}))
	defer srv.Close()

	s, m := newTestSink(t, srv.URL, func(c *Config) { c.MaxRetries = 0 })
	s.Offer(testEnvelope(1))
	waitFor(t, 3*time.Second, func() bool { return m.get("aegismesh_webhook_failed_batches_total") == 1 },
		"redirect treated as failure")
	hopMu.Lock()
	defer hopMu.Unlock()
	if hopHits != 0 {
		t.Fatalf("redirect was followed %d times", hopHits)
	}
	s.Close()
}

func TestConstructionRefusesUnsafeDestinations(t *testing.T) {
	cases := map[string]struct {
		raw      string
		loopback bool
		private  bool
	}{
		"metadata literal":       {"http://169.254.169.254/latest/meta-data", false, false},
		"metadata https":         {"https://169.254.169.254/x", false, false},
		"cleartext public":       {"http://collector.example.com/events", false, false},
		"private without opt-in": {"https://10.1.2.3/events", false, false},
		"loopback cleartext":     {"http://127.0.0.1:9/events", false, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			u, _ := url.Parse(tc.raw)
			if _, err := New(Config{
				Endpoint: u, QueueSize: 8, BatchSize: 1,
				AllowLoopbackHTTP: tc.loopback, AllowPrivate: tc.private,
			}, newRecMeter(), nil); err == nil {
				t.Fatal("construction must refuse unsafe destinations")
			}
		})
	}
}

func TestBackpressureDropsWithoutBlocking(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	block := func() { <-release }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		block()
		r.Body.Close()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	defer once.Do(func() { close(release) })

	// BatchSize small enough that the worker starts a POST immediately and
	// parks on the blocked handler, leaving the queue to overflow.
	s, m := newTestSink(t, srv.URL, func(c *Config) { c.QueueSize = 2; c.BatchSize = 4 })
	begin := time.Now()
	droppedByOffer := 0
	for i := 0; i < 50; i++ {
		if !s.Offer(testEnvelope(i)) {
			droppedByOffer++
		}
	}
	if burst := time.Since(begin); burst > time.Second {
		t.Fatalf("Offer blocked under backpressure for %v", burst)
	}
	if droppedByOffer == 0 {
		t.Fatal("expected queue-full drops during burst")
	}
	waitFor(t, 2*time.Second, func() bool {
		return m.get("aegismesh_webhook_dropped_queue_full_total") == float64(droppedByOffer)
	}, "drop accounting")
	s.forceStop()
	s.Close()
}

func TestShutdownIsBoundedAndCountsAbandoned(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		r.Body.Close()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	defer close(release)

	s, m := newTestSink(t, srv.URL, func(c *Config) {
		c.QueueSize = 32
		c.BatchSize = 64 // never auto-flushes by size within this test
		c.ShutdownFlush = 250 * time.Millisecond
	})
	for i := 0; i < 10; i++ {
		s.Offer(testEnvelope(i))
	}
	begin := time.Now()
	s.Close()
	if elapsed := time.Since(begin); elapsed > 4*time.Second {
		t.Fatalf("Close exceeded its bound: %v", elapsed)
	}
	if got := m.get("aegismesh_webhook_dropped_shutdown_total"); got < 1 {
		t.Fatalf("abandoned events not accounted: %v", got)
	}
}

func TestErrorsNeverContainSecretMaterial(t *testing.T) {
	var tw testWriter
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	cfg := Config{
		Endpoint: u, Secret: []byte("SUPERSECRETVALUE42"), QueueSize: 8, BatchSize: 2,
		FlushInterval: 40 * time.Millisecond, Timeout: time.Second, MaxRetries: 0,
		ShutdownFlush: time.Second, AllowLoopbackHTTP: true,
	}
	s, err := New(cfg, newRecMeter(), slog.New(slog.NewTextHandler(&tw, nil)))
	if err != nil {
		t.Fatal(err)
	}
	s.Offer(testEnvelope(1))
	s.Offer(testEnvelope(2))
	waitFor(t, 3*time.Second, func() bool { return strings.Contains(tw.String(), "webhook batch failed") },
		"failure log line")
	s.Close()
	if strings.Contains(tw.String(), "SUPERSECRETVALUE42") {
		t.Fatal("logs leaked the HMAC key material")
	}
}
