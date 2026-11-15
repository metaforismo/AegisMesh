package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
	"github.com/metaforismo/aegismesh/internal/observe"
)

func queuedFixture(t testing.TB) event.Envelope {
	t.Helper()
	envelope, err := event.New(&event.Sequencer{}, "synthetic", event.SensorRef{ID: "web", Kind: "http"},
		event.ClassificationInteraction, json.RawMessage(`{"method":"GET","path":"/"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func testForwarder() *forwarder {
	return &forwarder{items: make([]queuedEvidence, QueueEvents),
		status:   protocol.Forwarding{Enabled: true},
		outcomes: observe.NewRegistry().CounterVec("forward_test", "outcomes", 3)}
}

func TestQueueBoundsAndConcurrentStatus(t *testing.T) {
	a := &Agent{forward: testForwarder()}
	envelope := queuedFixture(t)
	var workers sync.WaitGroup
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 2000 {
				a.Enqueue(envelope)
				_ = a.Status()
			}
		}()
	}
	workers.Wait()
	status := a.Status().Forwarding
	if status.QueuedEvents != QueueEvents || status.DroppedTotal != 8000-QueueEvents || status.QueuedBytes > QueueBytes {
		t.Fatalf("queue accounting: %+v", status)
	}
}

func BenchmarkAgentEnqueue(b *testing.B) {
	envelope := queuedFixture(b)
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		a := &Agent{}
		if enabled {
			name = "enabled"
			a.forward = testForwarder()
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				a.Enqueue(envelope)
			}
		})
	}
}

func TestHostileAcknowledgementCountsCannotOverflow(t *testing.T) {
	for _, valid := range []bool{false, true} {
		t.Run(fmt.Sprint(valid), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				accepted, invalid, duplicates := int(^uint(0)>>1), int(^uint(0)>>1), 3
				if valid {
					accepted, invalid, duplicates = 1, 0, 0
				}
				_ = json.NewEncoder(w).Encode(protocol.EvidenceAck{NodeID: r.Header.Get("X-AegisMesh-Node"),
					Accepted: accepted, Invalid: invalid, Duplicates: duplicates})
			}))
			defer server.Close()
			a, err := New(Options{HubURL: server.URL, StateDir: filepath.Join(t.TempDir(), "agent"), Name: "test-node", ForwardEvidence: true,
				Interval: 10 * time.Second, Snapshot: func() protocol.Heartbeat { return protocol.Heartbeat{} }})
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			a.status.Enrolled = true
			a.Enqueue(queuedFixture(t))
			err = a.ForwardStep(context.Background())
			if (err == nil) != valid {
				t.Fatalf("ack validation: %v", err)
			}
			status := a.Status().Forwarding
			if !valid && (status.QueuedEvents != 1 || status.ForwardedTotal != 0) {
				t.Fatalf("hostile counts mutated queue: %+v", status)
			}
		})
	}
}
