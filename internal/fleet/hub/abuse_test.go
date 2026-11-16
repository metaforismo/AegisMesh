package hub

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
	"github.com/metaforismo/aegismesh/internal/observe"
)

type abuseFixture struct {
	h            *Hub
	dir          string
	seconds      atomic.Int64
	keys         []ed25519.PrivateKey
	meter        *observe.Registry
	closeHandled bool
}

func newAbuseFixture(t *testing.T, nodes int) *abuseFixture {
	t.Helper()
	f := &abuseFixture{dir: filepath.Join(t.TempDir(), "hub"), meter: observe.NewRegistry()}
	f.seconds.Store(1800000000)
	var err error
	f.h, err = New(Options{StateDir: f.dir, Now: f.now, Meter: f.meter})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if f.closeHandled {
			return
		}
		if err := f.h.Close(); err != nil {
			t.Error(err)
		}
	})
	f.h.mu.Lock()
	defer f.h.mu.Unlock()
	for i := 0; i < nodes; i++ {
		seed := make([]byte, ed25519.SeedSize)
		seed[0], seed[1] = byte(i), byte(i>>8)
		key := ed25519.NewKeyFromSeed(seed)
		f.keys = append(f.keys, key)
		public := key.Public().(ed25519.PublicKey)
		id := protocol.ID(public)
		f.h.state.Nodes[id] = registration{PublicKey: hex.EncodeToString(public), IntervalSeconds: 10,
			Node: protocol.Node{ID: id, Name: "test-node", Status: "online", EnrolledAt: f.now().UTC().Format(time.RFC3339Nano),
				PublicKeyFingerprint: protocol.Digest(public), Sensors: []protocol.Sensor{}}}
	}
	if err := f.h.save(); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *abuseFixture) now() time.Time { return time.Unix(f.seconds.Load(), 0) }

func (f *abuseFixture) heartbeatRequest(t *testing.T, index int) *http.Request {
	t.Helper()
	body, err := json.Marshal(protocol.Heartbeat{Name: "test-node", Sensors: []protocol.Sensor{}, StorageHealthy: true})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", protocol.HeartbeatPath, bytes.NewReader(body))
	r.RemoteAddr = fmt.Sprintf("192.0.2.%d:1234", index+1)
	r.Header.Set("Content-Type", "application/json")
	if err := protocol.Sign(r, body, f.keys[index], f.now()); err != nil {
		t.Fatal(err)
	}
	return r
}

func (f *abuseFixture) heartbeat(t *testing.T, index int) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, f.heartbeatRequest(t, index))
	return w
}

func (f *abuseFixture) registry(t *testing.T) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(f.dir, "tenants", "default", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestRejectionBurstBoundedAudit(t *testing.T) {
	f := newAbuseFixture(t, 1)
	for i := 0; i < 100; i++ {
		r := httptest.NewRequest("POST", protocol.HeartbeatPath, bytes.NewReader([]byte(`{}`)))
		r.Header.Set("Content-Type", "application/json")
		f.h.ServeHTTP(httptest.NewRecorder(), r)
	}
	if w := f.heartbeat(t, 0); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	// The burst must not have triggered an audit fsync per request.
	body, err := os.ReadFile(filepath.Join(f.dir, "tenants", "default", "audit", "audit.jsonl"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if count := bytes.Count(body, []byte("\n")); count > 5 {
		t.Fatalf("100 invalid requests wrote %d audit records, want <=5", count)
	}
	f.seconds.Add(60)
	f.h.maintain()
	records, _, err := f.h.audit.Read(^uint64(0), 200, "", "")
	if err != nil || len(records) != 6 {
		t.Fatalf("audit = %+v, %v; want five samples and one summary", records, err)
	}
	summaries := 0
	for _, record := range records {
		if record.Action == "fleet.node.rejected.summary" {
			summaries++
			if record.Target != "95" || record.Outcome != "suppressed" {
				t.Fatalf("summary = %+v", record)
			}
		}
	}
	if summaries != 1 {
		t.Fatalf("summaries = %d", summaries)
	}
	if !strings.Contains(f.meter.WritePrometheus(), `aegismesh_fleet_hub_requests_total{label="unauthenticated"} 100`) {
		t.Fatal(f.meter.WritePrometheus())
	}
}

func TestRogueHeartbeatSpacing(t *testing.T) {
	f := newAbuseFixture(t, 2)
	for second := 0; second < 31; second++ {
		for attempt := 0; attempt < 5; attempt++ {
			w := f.heartbeat(t, 0)
			want := 429
			if second%10 == 0 && attempt == 0 {
				want = 200
			}
			if w.Code != want {
				t.Fatalf("second %d attempt %d: %d %s; want %d", second, attempt, w.Code, w.Body.String(), want)
			}
		}
		if second%10 == 0 {
			if w := f.heartbeat(t, 1); w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
		}
		f.seconds.Add(1)
	}
}

func TestHeartbeatDoesNotSynchronouslyRewriteRegistry(t *testing.T) {
	f := newAbuseFixture(t, 2)
	before := f.registry(t)
	for i := range f.keys {
		if w := f.heartbeat(t, i); w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if !bytes.Equal(before, f.registry(t)) {
		t.Fatal("heartbeats synchronously rewrote registry")
	}
}

func TestRemoteLimiterBoundsAndExpiry(t *testing.T) {
	f := newAbuseFixture(t, 0)
	for i := 0; i < maxRemotes+100; i++ {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = fmt.Sprintf("198.18.%d.%d:1234", i/256, i%256)
		w := httptest.NewRecorder()
		f.h.ServeHTTP(w, r)
		want := 404
		if i >= maxRemotes {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("remote %d: %d, want %d", i, w.Code, want)
		}
		if w.Code == 429 && w.Header().Get("Retry-After") != "60" {
			t.Fatal(w.Header())
		}
	}
	f.h.limits.mu.Lock()
	count := len(f.h.limits.remotes)
	f.h.limits.mu.Unlock()
	if count != maxRemotes {
		t.Fatalf("remote table = %d", count)
	}
	f.seconds.Add(60)
	f.h.maintain()
	if !f.h.allowRemote("203.0.113.1:4567") {
		t.Fatal("expired table did not recover")
	}
}

func TestRemoteLimiterIgnoresPortsAndForwardingHeaders(t *testing.T) {
	f := newAbuseFixture(t, 0)
	for i := 0; i <= remoteRequestsPerMinute; i++ {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "192.0.2.1:" + strconv.Itoa(1000+i)
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("198.18.%d.%d", i/256, i%256))
		w := httptest.NewRecorder()
		f.h.ServeHTTP(w, r)
		want := 404
		if i == remoteRequestsPerMinute {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("attempt %d = %d", i, w.Code)
		}
	}
	if !strings.Contains(f.meter.WritePrometheus(), `aegismesh_fleet_hub_requests_total{label="rate_limited"} 1`) {
		t.Fatal(f.meter.WritePrometheus())
	}
}

func TestPerNodeNonceCapacityIsolation(t *testing.T) {
	f := newAbuseFixture(t, 2)
	id := protocol.ID(f.keys[0].Public().(ed25519.PublicKey))
	f.h.mu.Lock()
	for i := 0; i < MaxNoncesPerNode; i++ {
		err := f.h.remember(protocol.Authentication{NodeID: id, Nonce: fmt.Sprintf("%032x", i), Time: f.now()})
		if err != nil {
			t.Fatal(err)
		}
	}
	f.h.mu.Unlock()
	before := f.registry(t)
	if w := f.heartbeat(t, 0); w.Code != 503 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := f.heartbeat(t, 1); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if !bytes.Equal(before, f.registry(t)) {
		t.Fatal("capacity rejection wrote registry")
	}
	f.seconds.Add(121)
	if w := f.heartbeat(t, 0); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	f.h.mu.Lock()
	count := len(f.h.replay[id])
	f.h.mu.Unlock()
	if count != 1 {
		t.Fatalf("pruned node nonces = %d", count)
	}
}

func TestRevokedAndThrottledNodesDoNotMutateReplayOrDisk(t *testing.T) {
	f := newAbuseFixture(t, 2)
	if w := f.heartbeat(t, 0); w.Code != 200 {
		t.Fatal(w.Code)
	}
	id := protocol.ID(f.keys[1].Public().(ed25519.PublicKey))
	if _, err := f.h.Revoke(id); err != nil {
		t.Fatal(err)
	}
	before := f.registry(t)
	for range 100 {
		if w := f.heartbeat(t, 0); w.Code != 429 || w.Header().Get("Retry-After") != "10" {
			t.Fatal(w.Code, w.Header(), w.Body.String())
		}
		if w := f.heartbeat(t, 1); w.Code != 403 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	f.h.mu.Lock()
	count, dirty := len(f.h.state.Nonces), f.h.dirty
	f.h.mu.Unlock()
	if count != 1 || dirty || !bytes.Equal(before, f.registry(t)) {
		t.Fatalf("rejections mutated state: nonces %d dirty %v", count, dirty)
	}
}

func TestFlushCoalescingAndDurableChanges(t *testing.T) {
	f := newAbuseFixture(t, 2)
	before := f.registry(t)
	for i := range f.keys {
		if w := f.heartbeat(t, i); w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	f.seconds.Add(4)
	f.h.maintain()
	if !bytes.Equal(before, f.registry(t)) {
		t.Fatal("flushed before interval")
	}
	f.seconds.Add(1)
	f.h.maintain()
	after := f.registry(t)
	if bytes.Equal(before, after) {
		t.Fatal("did not flush at interval")
	}
	var saved snapshot
	if err := decodeState(after, &saved); err != nil || len(saved.Nonces) != 2 {
		t.Fatal(err, len(saved.Nonces))
	}
	for _, record := range saved.Nodes {
		if record.Node.LastSeenAt == "" || !record.Node.StorageHealthy {
			t.Fatal(record.Node)
		}
	}
	// No IO when clean, even when another flush is due.
	f.seconds.Add(5)
	f.h.maintain()
	if !bytes.Equal(after, f.registry(t)) {
		t.Fatal("clean flush changed snapshot")
	}
	// Revocation remains synchronously durable and the soft flush cannot undo it.
	id := protocol.ID(f.keys[0].Public().(ed25519.PublicKey))
	if _, err := f.h.Revoke(id); err != nil {
		t.Fatal(err)
	}
	if err := decodeState(f.registry(t), &saved); err != nil || saved.Nodes[id].Node.Status != "revoked" {
		t.Fatal(err)
	}
	f.seconds.Add(5)
	f.h.maintain()
	if err := decodeState(f.registry(t), &saved); err != nil || saved.Nodes[id].Node.Status != "revoked" {
		t.Fatal(err)
	}
}

func TestBackgroundFlushUsesInjectedClock(t *testing.T) {
	f := newAbuseFixture(t, 1)
	before := f.registry(t)
	if w := f.heartbeat(t, 0); w.Code != 200 {
		t.Fatal(w.Code)
	}
	f.seconds.Add(int64(FlushInterval / time.Second))
	deadline := time.Now().Add(3 * time.Second)
	for bytes.Equal(before, f.registry(t)) {
		if time.Now().After(deadline) {
			t.Fatal("background worker did not flush")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestConcurrentInvalidBurstAndLegitimateHeartbeat(t *testing.T) {
	f := newAbuseFixture(t, 1)
	server := httptest.NewServer(f.h)
	defer server.Close()
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				response, err := server.Client().Post(server.URL+protocol.HeartbeatPath, "application/json", strings.NewReader(`{}`))
				if err != nil {
					t.Error(err)
					return
				}
				_, _ = io.Copy(io.Discard, response.Body)
				response.Body.Close()
				if response.StatusCode != 401 {
					t.Errorf("invalid request = %d", response.StatusCode)
					return
				}
			}
		}()
	}
	body, err := json.Marshal(protocol.Heartbeat{Name: "test-node", Sensors: []protocol.Sensor{}, StorageHealthy: true})
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequest("POST", server.URL+protocol.HeartbeatPath, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	if err := protocol.Sign(r, body, f.keys[0], f.now()); err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	wg.Wait()
	if response.StatusCode != 200 {
		t.Fatalf("legitimate heartbeat = %d", response.StatusCode)
	}
	f.seconds.Add(60)
	f.h.maintain()
	records, _, err := f.h.audit.Read(^uint64(0), 200, "", "")
	if err != nil || len(records) != 6 {
		t.Fatalf("audit = %d, %v", len(records), err)
	}
}

// crash stops the worker and closes handles without the orderly soft-state flush.
// Reopen the actual last on-disk snapshot, rather than constructing fake state.
func (f *abuseFixture) crash(t *testing.T) {
	t.Helper()
	close(f.h.stop)
	<-f.h.done
	if err := f.h.audit.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.h.root.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.h, err = New(Options{StateDir: f.dir, Now: f.now, Meter: f.meter})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCrashRestoresFlushedStateAndDocumentsReplayGap(t *testing.T) {
	f := newAbuseFixture(t, 1)
	id := protocol.ID(f.keys[0].Public().(ed25519.PublicKey))
	request := f.heartbeatRequest(t, 0)
	captured := request.Header.Clone()
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, request)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	f.crash(t)
	node, err := f.h.Node(id)
	if err != nil || node.LastSeenAt != "" || node.Status != "offline" {
		t.Fatal(node, err)
	}
	replay := func(want int) {
		t.Helper()
		r := f.heartbeatRequest(t, 0)
		r.Header = captured.Clone()
		w := httptest.NewRecorder()
		f.h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("captured request = %d %s, want %d", w.Code, w.Body.String(), want)
		}
	}
	// Honest residual gap: the unflushed nonce can be accepted again after a crash.
	replay(200)
	replay(401)
	f.seconds.Add(5)
	f.h.maintain()
	f.crash(t)
	node, err = f.h.Node(id)
	if err != nil || node.LastSeenAt != time.Unix(1800000000, 0).UTC().Format(time.RFC3339Nano) {
		t.Fatal(node, err)
	}
	replay(401) // A flushed nonce survives an abrupt restart.
	f.seconds.Add(116)
	replay(401) // Even a lost nonce is unusable beyond signed time + 120 seconds.
	if w := f.heartbeat(t, 0); w.Code != 200 {
		t.Fatal(w.Code)
	}
	node, err = f.h.Node(id)
	if err != nil || node.LastSeenAt != f.now().UTC().Format(time.RFC3339Nano) {
		t.Fatal(node, err)
	}
}

func TestOrderlyCloseFlushesSoftState(t *testing.T) {
	f := newAbuseFixture(t, 1)
	if w := f.heartbeat(t, 0); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if err := f.h.Close(); err != nil {
		t.Fatal(err)
	}
	var saved snapshot
	if err := decodeState(f.registry(t), &saved); err != nil || len(saved.Nonces) != 1 {
		t.Fatal(err)
	}
	for _, record := range saved.Nodes {
		if record.Node.LastSeenAt == "" {
			t.Fatal("shutdown lost last heartbeat")
		}
	}
}

func TestEnrollmentRetryCannotBypassWriteThrottle(t *testing.T) {
	f := newAbuseFixture(t, 1)
	before := f.registry(t)
	submit := func(interval int) int {
		t.Helper()
		input := protocol.Enrollment{PublicKey: hex.EncodeToString(f.keys[0].Public().(ed25519.PublicKey)),
			Name: "test-node", IntervalSeconds: interval}
		body, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", protocol.EnrollPath, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if err := protocol.Sign(r, body, f.keys[0], f.now()); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		f.h.ServeHTTP(w, r)
		return w.Code
	}
	if code := submit(10); code != 200 {
		t.Fatal(code)
	}
	for range 100 {
		if code := submit(11); code != 429 {
			t.Fatal(code)
		}
	}
	if !bytes.Equal(before, f.registry(t)) {
		t.Fatal("retry forced a disk write")
	}
	f.seconds.Add(10)
	if code := submit(11); code != 200 {
		t.Fatal(code)
	}
	var saved snapshot
	if err := decodeState(f.registry(t), &saved); err != nil {
		t.Fatal(err)
	}
	for _, record := range saved.Nodes {
		if record.IntervalSeconds != 11 {
			t.Fatal("interval change was not durable")
		}
	}
}

func TestStatelessRejectionsDoNotAcquireRegistryMutex(t *testing.T) {
	f := newAbuseFixture(t, 1)
	for _, mode := range []string{"method", "path", "content_type", "headers", "body_cap", "clock_skew", "signature"} {
		t.Run(mode, func(t *testing.T) {
			input := protocol.Enrollment{PublicKey: hex.EncodeToString(f.keys[0].Public().(ed25519.PublicKey)),
				Name: "test-node", IntervalSeconds: 10}
			body, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("POST", protocol.EnrollPath, bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			if err := protocol.Sign(r, body, f.keys[0], f.now()); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "method":
				r.Method = "GET"
			case "path":
				r.URL.Path = "/unknown"
			case "content_type":
				r.Header.Del("Content-Type")
			case "headers":
				r.Header.Del("X-AegisMesh-Signature")
			case "body_cap":
				r.ContentLength = protocol.MaxBodyBytes + 1
			case "clock_skew":
				if err := protocol.Sign(r, body, f.keys[0], f.now().Add(-121*time.Second)); err != nil {
					t.Fatal(err)
				}
			case "signature":
				r.Header.Set("X-AegisMesh-Signature", strings.Repeat("0", 128))
			}
			done := make(chan struct{})
			f.h.mu.Lock()
			go func() {
				defer close(done)
				f.h.ServeHTTP(httptest.NewRecorder(), r)
			}()
			blocked := false
			select {
			case <-done:
			case <-time.After(time.Second):
				blocked = true
			}
			f.h.mu.Unlock()
			<-done
			if blocked {
				t.Fatal("stateless rejection waited for hub mutex")
			}
		})
	}
}

func TestBackgroundWriteFailureLatchesUnavailable(t *testing.T) {
	f := newAbuseFixture(t, 1)
	if w := f.heartbeat(t, 0); w.Code != 200 {
		t.Fatal(w.Code)
	}
	// A real stale temporary file forces the production atomic writer to refuse IO.
	if err := os.WriteFile(filepath.Join(f.dir, "tenants", "default", "registry.json.tmp"), []byte("synthetic stale temp"), 0600); err != nil {
		t.Fatal(err)
	}
	f.seconds.Add(5)
	f.h.maintain()
	if _, err := f.h.Node(protocol.ID(f.keys[0].Public().(ed25519.PublicKey))); Code(err) != "unavailable" {
		t.Fatalf("failed flush did not latch unavailable: %v", err)
	}
	if w := f.heartbeat(t, 0); w.Code != 503 {
		t.Fatal(w.Code)
	}
	if err := f.h.Close(); Code(err) != "unavailable" {
		t.Fatalf("close lost flush failure: %v", err)
	}
	// This deliberate close failure was asserted above; cleanup need not close again.
	f.closeHandled = true
}

func TestLegacyReplayWindowWaitsForExpiry(t *testing.T) {
	f := newAbuseFixture(t, 1)
	if err := f.h.Close(); err != nil {
		t.Fatal(err)
	}
	var saved snapshot
	if err := decodeState(f.registry(t), &saved); err != nil {
		t.Fatal(err)
	}
	id := protocol.ID(f.keys[0].Public().(ed25519.PublicKey))
	for i := 0; i < MaxNoncesPerNode+1; i++ {
		saved.Nonces[id+":"+fmt.Sprintf("%032x", i)] = f.now().Add(protocol.Window).Unix()
	}
	body, err := encodeState(saved)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "tenants", "default", "registry.json"), body, 0600); err != nil {
		t.Fatal(err)
	}
	if h, err := New(Options{StateDir: f.dir, Now: f.now}); Code(err) != "corrupt_state" {
		if h != nil {
			h.Close()
		}
		t.Fatalf("oversized live replay window accepted: %v", err)
	}
	f.seconds.Add(121)
	f.h, err = New(Options{StateDir: f.dir, Now: f.now, Meter: f.meter})
	if err != nil {
		t.Fatal(err)
	}
	if w := f.heartbeat(t, 0); w.Code != 200 {
		t.Fatal(w.Code)
	}
	f.h.mu.Lock()
	count := len(f.h.state.Nonces)
	f.h.mu.Unlock()
	if count != 1 {
		t.Fatalf("expired legacy entries retained: %d", count)
	}
}
