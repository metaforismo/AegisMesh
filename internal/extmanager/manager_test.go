package extmanager

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/ext"
	"github.com/metaforismo/aegismesh/internal/observe"
)

// fakeMeter records CounterVec increments so tests can assert delivery
// outcomes deterministically without parsing Prometheus text.
type fakeMeter struct {
	mu    sync.Mutex
	count map[string]map[string]uint64 // vec name -> label -> count
}

func newFakeMeter() *fakeMeter { return &fakeMeter{count: map[string]map[string]uint64{}} }

func (f *fakeMeter) inc(vec, label string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.count[vec] == nil {
		f.count[vec] = map[string]uint64{}
	}
	f.count[vec][label]++
}

func (f *fakeMeter) get(vec, label string) uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.count[vec][label]
}

func (f *fakeMeter) Counter(string, string) observe.Counter { return nopCounter{} }
func (f *fakeMeter) Gauge(string, string) observe.Gauge     { return nopGauge{} }
func (f *fakeMeter) CounterVec(name, _ string, _ int) observe.LabeledCounter {
	return labeledVec{f: f, name: name}
}
func (f *fakeMeter) WritePrometheus() string { return "" }

type nopCounter struct{}

func (nopCounter) Inc()        {}
func (nopCounter) Add(float64) {}

type nopGauge struct{}

func (nopGauge) Set(float64) {}
func (nopGauge) Add(float64) {}

type labeledVec struct {
	f    *fakeMeter
	name string
}

func (v labeledVec) Inc(label string) { v.f.inc(v.name, label) }

// buildFixture compiles a synthetic extension source and returns a manifest
// wired to run it.
func buildFixture(t *testing.T, name string, callTimeoutMS int) *ext.Manifest {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping go build in -short mode")
	}
	srcDir := filepath.Join("testdata", "observer-"+name)
	dir := t.TempDir()
	exePath := filepath.Join(dir, "ext")
	cmd := exec.Command("go", "build", "-o", exePath, ".") //nolint:gosec // fixed test fixture path
	cmd.Dir = srcDir
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", name, err, b)
	}
	bin, err := os.ReadFile(exePath)
	if err != nil {
		t.Fatal(err)
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(bin))
	m := &ext.Manifest{
		Dir:         dir,
		APIVersion:  "ext.aegismesh.io/v1alpha1",
		Name:        "obs-" + name,
		Version:     "1.0.0",
		Description: "synthetic test extension",
		Permissions: []string{"observe"},
		Transport: ext.Transport{
			Kind:               "subprocess-ndjson",
			Command:            []string{exePath},
			HandshakeTimeoutMS: 5000,
			CallTimeoutMS:      callTimeoutMS,
			MaxOutputBytes:     1 << 20,
		},
		Digest: ext.Digest{Algorithm: "sha256", Value: sum},
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("fixture manifest invalid: %v", err)
	}
	return m
}

func testEnvelope(n int) event.Envelope {
	seq := &event.Sequencer{}
	env, err := event.New(seq, "it", event.SensorRef{ID: "http-decoy", Kind: "http", Listen: "127.0.0.1:8081"},
		event.ClassificationInteraction, json.RawMessage(fmt.Sprintf(`{"n":%d}`, n)), nil)
	if err != nil {
		panic(err)
	}
	return env
}

// waitFor polls until cond passes or the deadline expires; extension delivery
// is asynchronous by design.
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

const deliveredVec = "aegismesh_extension_delivered_total"
const droppedVec = "aegismesh_extension_dropped_total"
const revokedVec = "aegismesh_extension_revoked_total"

func TestDeliveredObservationsAreCounted(t *testing.T) {
	fm := newFakeMeter()
	mgr := New([]*ext.Manifest{buildFixture(t, "acker", 2000)}, fm, nil, 16, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := mgr.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	for i := 0; i < 3; i++ {
		mgr.Deliver(testEnvelope(i))
	}
	waitFor(t, 3*time.Second, func() bool { return fm.get(deliveredVec, "obs-acker") == 3 }, "3 deliveries")
}

func TestSlowExtensionRevokesAndDeliveryStaysBounded(t *testing.T) {
	fm := newFakeMeter()
	mgr := New([]*ext.Manifest{buildFixture(t, "slow", 100)}, fm, nil, 16, 500*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := mgr.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	mgr.Deliver(testEnvelope(1))
	waitFor(t, 3*time.Second, func() bool { return fm.get(revokedVec, "obs-slow") == 1 }, "revocation")

	// Post-revocation deliveries drop instead of blocking or erroring.
	for i := 2; i < 12; i++ {
		mgr.Deliver(testEnvelope(i))
	}
	waitFor(t, 2*time.Second, func() bool { return fm.get(droppedVec, "obs-slow") >= 10 }, "post-revocation drops")

	// Bounded shutdown even though the extension would sleep 2s per call.
	stopStart := time.Now()
	mgr.Stop()
	if elapsed := time.Since(stopStart); elapsed > 4*time.Second {
		t.Fatalf("Stop exceeded its bound: %v", elapsed)
	}
}

func TestErrorFrameExtensionRevokes(t *testing.T) {
	fm := newFakeMeter()
	mgr := New([]*ext.Manifest{buildFixture(t, "failer", 2000)}, fm, nil, 16, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := mgr.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	mgr.Deliver(testEnvelope(1))
	waitFor(t, 3*time.Second, func() bool { return fm.get(revokedVec, "obs-failer") == 1 }, "revocation on error frame")
}

func TestCrashingExtensionRevokes(t *testing.T) {
	fm := newFakeMeter()
	mgr := New([]*ext.Manifest{buildFixture(t, "crasher", 2000)}, fm, nil, 16, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := mgr.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	mgr.Deliver(testEnvelope(1))
	waitFor(t, 3*time.Second, func() bool { return fm.get(revokedVec, "obs-crasher") == 1 }, "revocation on crash")
}

func TestBackpressureDropsWithoutBlocking(t *testing.T) {
	fm := newFakeMeter()
	// Queue of 2 against an acker that answers instantly still overflows when
	// 300 envelopes arrive faster than the dispatcher drains them.
	mgr := New([]*ext.Manifest{buildFixture(t, "acker", 2000)}, fm, nil, 2, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := mgr.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	begin := time.Now()
	for i := 0; i < 300; i++ {
		mgr.Deliver(testEnvelope(i))
	}
	if burst := time.Since(begin); burst > time.Second {
		t.Fatalf("Deliver blocked under backpressure for %v", burst)
	}
	waitFor(t, 3*time.Second, func() bool {
		d := fm.get(droppedVec, "obs-acker")
		del := fm.get(deliveredVec, "obs-acker")
		return d > 0 && d+del == 300
	}, "drop+deliver accounting to equal 300")
}

func TestDeliverConcurrentWithStop(t *testing.T) {
	mgr := New([]*ext.Manifest{buildFixture(t, "acker", 2000)}, newFakeMeter(), nil, 8, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := mgr.Start(ctx); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var producers sync.WaitGroup
	for i := 0; i < 8; i++ {
		producers.Add(1)
		go func() {
			defer producers.Done()
			<-start
			for j := 0; j < 200; j++ {
				mgr.Deliver(testEnvelope(j))
			}
		}()
	}
	close(start)
	mgr.Stop()
	producers.Wait()
	mgr.Deliver(testEnvelope(999))
}

func TestStartFailureTearsDownAndStopIsIdempotent(t *testing.T) {
	fm := newFakeMeter()
	good := buildFixture(t, "acker", 2000)
	bad := buildFixture(t, "acker", 2000)
	bad.Name = "obs-missing"
	bad.Transport.Command = []string{"./definitely-not-here"}

	mgr := New([]*ext.Manifest{good, bad}, fm, nil, 16, time.Second)
	err := mgr.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "obs-missing") {
		t.Fatalf("expected start failure naming the broken extension, got: %v", err)
	}
	mgr.Stop() // must be safe after failed start
	mgr.Stop() // and idempotent
}
