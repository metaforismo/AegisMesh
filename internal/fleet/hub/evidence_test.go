package hub_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/fleet/agent"
	"github.com/metaforismo/aegismesh/internal/fleet/hub"
	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/storage"
)

func evidenceHarness(t *testing.T) (*harness, *evidenceindex.Index, string) {
	t.Helper()
	index, err := evidenceindex.New(10000, observe.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{dir: filepath.Join(t.TempDir(), "hub"), clock: &testClock{}}
	h.clock.seconds.Store(time.Now().Unix())
	dir := filepath.Join(h.dir, "evidence")
	h.hub, err = hub.New(hub.Options{StateDir: h.dir, Now: h.clock.now, Evidence: &hub.EvidenceOptions{
		Dir: dir, Store: storage.Options{MaxEvents: 10000}, OnAppend: func(id string, e event.Envelope) { index.AddForwarded(e, id) },
	}})
	if err != nil {
		t.Fatal(err)
	}
	h.server = httptest.NewServer(h.hub)
	index.SetNodeNames(func(id string) string { node, _ := h.hub.Node(id); return node.Name })
	t.Cleanup(func() {
		h.server.Close()
		if err := h.hub.Close(); err != nil {
			t.Error(err)
		}
	})
	return h, index, dir
}

func nativeEvidence(t testing.TB, n int) event.Envelope {
	t.Helper()
	envelope, err := event.New(&event.Sequencer{}, "synthetic", event.SensorRef{ID: "web", Kind: "http"},
		event.ClassificationInteraction, json.RawMessage(fmt.Sprintf(`{"method":"GET","path":"/%d"}`, n)), nil)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func batchOf(t *testing.T, stream string, first uint64, envelopes ...event.Envelope) []byte {
	t.Helper()
	batch := protocol.EvidenceBatch{StreamID: stream, First: first, Last: first + uint64(len(envelopes)) - 1}
	for _, envelope := range envelopes {
		batch.Events = append(batch.Events, encoded(t, envelope))
	}
	return encoded(t, batch)
}

func enrollEvidenceKey(t *testing.T, h *harness) ed25519.PrivateKey {
	t.Helper()
	key := makeKey(t)
	send(t, h.request(t, protocol.EnrollPath, encoded(t, enrollment(key, h.mint(t, 0).Token)), key), 200)
	return key
}

func readAck(t *testing.T, h *harness, body []byte, key ed25519.PrivateKey) protocol.EvidenceAck {
	t.Helper()
	response, err := http.DefaultClient.Do(h.request(t, protocol.EvidencePath, body, key))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var ack protocol.EvidenceAck
	if err := json.NewDecoder(response.Body).Decode(&ack); err != nil || response.StatusCode != 200 {
		t.Fatalf("ack: %+v %v status %d", ack, err, response.StatusCode)
	}
	return ack
}

func TestEvidenceIngestionHostileInputs(t *testing.T) {
	for _, mode := range []string{"valid", "hash", "oversize_event", "malformed", "signature", "replay", "revoked", "duplicate", "quota"} {
		t.Run(mode, func(t *testing.T) {
			h, index, dir := evidenceHarness(t)
			key := enrollEvidenceKey(t, h)
			id := protocol.ID(key.Public().(ed25519.PublicKey))
			envelope := nativeEvidence(t, 1)
			stream := strings.Repeat("a", 32)
			switch mode {
			case "hash":
				envelope.Integrity.PayloadSHA256 = strings.Repeat("0", 64)
			case "oversize_event":
				envelope.Observation = json.RawMessage(`{"x":"` + strings.Repeat("x", event.MaxStoredEnvelopeBytes) + `"}`)
				envelope.Integrity.PayloadSHA256 = event.SHA256Hex(envelope.Observation)
			}
			body := batchOf(t, stream, 1, envelope)
			request := h.request(t, protocol.EvidencePath, body, key)
			switch mode {
			case "malformed":
				send(t, h.request(t, protocol.EvidencePath, []byte(`{"events":[]}`), key), 400)
				return
			case "signature":
				request.Header.Set("X-AegisMesh-Signature", strings.Repeat("0", 128))
				send(t, request, 401)
				return
			case "revoked":
				if _, err := h.hub.Revoke(id); err != nil {
					t.Fatal(err)
				}
				send(t, request, 403)
				return
			case "replay":
				headers := request.Header.Clone()
				send(t, request, 200)
				repeated := h.request(t, protocol.EvidencePath, body, key)
				repeated.Header = headers
				send(t, repeated, 401)
				return
			}
			ack := readAck(t, h, body, key)
			if mode == "hash" || mode == "oversize_event" {
				if ack.Invalid != 1 || index.Stats().Events != 0 {
					t.Fatalf("invalid evidence accepted: %+v", ack)
				}
				return
			}
			if ack.Accepted != 1 {
				t.Fatalf("not appended: %+v", ack)
			}
			if mode == "duplicate" {
				h.clock.seconds.Add(5)
				ack = readAck(t, h, body, key)
				if ack.Duplicates != 1 || ack.Accepted != 0 {
					t.Fatalf("duplicate: %+v", ack)
				}
			}
			if mode == "quota" {
				send(t, h.request(t, protocol.EvidencePath, body, key), 429)
				other := enrollEvidenceKey(t, h)
				ack = readAck(t, h, body, other)
				if ack.Accepted != 1 {
					t.Fatal("one node starved another")
				}
				return
			}
			summaries := index.Summaries()
			if len(summaries) != 1 || summaries[0].Node == nil || summaries[0].Node.ID != id || summaries[0].Node.Name != "test-node" {
				t.Fatalf("attribution: %+v", summaries)
			}
			reader, err := storage.NewReader(filepath.Join(dir, id))
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			err = reader.ForEach(func(stored event.Envelope) error {
				count++
				if !bytes.Equal(stored.Observation, envelope.Observation) {
					t.Fatal("native payload changed")
				}
				return stored.VerifyIntegrity()
			}, func(_ string, err error) { t.Fatal(err) })
			if err != nil || count != 1 {
				t.Fatalf("inspect-compatible read: %d %v", count, err)
			}
		})
	}
}

func TestAgentQueueRecoveryOverflowAndGaps(t *testing.T) {
	h, index, _ := evidenceHarness(t)
	reporter, err := agent.New(agent.Options{HubURL: h.server.URL, StateDir: filepath.Join(t.TempDir(), "agent"),
		Name: "test-node", Token: h.mint(t, 0).Token, Interval: 10 * time.Second, Now: h.clock.now, Snapshot: heartbeat,
		ForwardEvidence: true})
	if err != nil {
		t.Fatal(err)
	}
	defer reporter.Close()
	if err := reporter.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A real unavailable listener leaves every queued item pending.
	h.server.CloseClientConnections()
	offline := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	offline.Close()
	// Closing the hub listener preserves its registry for recovery on the same authority.
	oldListener := h.server.Listener.Addr().String()
	h.server.Close()
	for i := 0; i < agent.QueueEvents+3; i++ {
		reporter.Enqueue(nativeEvidence(t, i))
	}
	if err := reporter.ForwardStep(context.Background()); err == nil {
		t.Fatal("offline delivery unexpectedly succeeded")
	}
	if status := reporter.Status().Forwarding; status.DroppedTotal != 3 || status.QueuedEvents != agent.QueueEvents {
		t.Fatalf("overflow: %+v", status)
	}
	listener, err := net.Listen("tcp", oldListener)
	if err != nil {
		t.Fatal(err)
	}
	recovered := httptest.NewUnstartedServer(h.hub)
	recovered.Listener = listener
	recovered.Start()
	h.server = recovered
	for reporter.Status().Forwarding.QueuedEvents > 0 {
		h.clock.seconds.Add(5)
		if err := reporter.ForwardStep(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	node, err := h.hub.Node(reporter.Status().NodeID)
	if err != nil || node.Forwarding == nil || node.Forwarding.GapsTotal != 3 {
		t.Fatalf("gaps: %+v %v", node.Forwarding, err)
	}
	summaries := index.Summaries()
	if len(summaries) != agent.QueueEvents {
		t.Fatalf("recovery count: %d", len(summaries))
	}
	// The oldest surviving envelope was /3, and all later envelopes retained order.
	for i, summary := range summaries {
		want := fmt.Sprintf("GET /%d", agent.QueueEvents+2-i)
		if summary.Summary != want {
			t.Fatalf("order[%d]: %s want %s", i, summary.Summary, want)
		}
	}
	h.clock.seconds.Add(10)
	if err := reporter.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	node, _ = h.hub.Node(reporter.Status().NodeID)
	if node.Forwarding.DroppedTotal != 3 || node.Forwarding.ForwardedTotal != agent.QueueEvents {
		t.Fatalf("heartbeat counters: %+v", node.Forwarding)
	}
}

func TestEvidenceByteQuotaIsolationAndRetention(t *testing.T) {
	h, _, dir := evidenceHarness(t)
	// Keep all quota requests within one fixed-minute window.
	h.clock.seconds.Store(h.clock.now().Unix()/60*60 + 1)
	key := enrollEvidenceKey(t, h)
	other := enrollEvidenceKey(t, h)
	stream := strings.Repeat("b", 32)
	for batchNumber := 0; batchNumber < 6; batchNumber++ {
		events := make([]event.Envelope, 12)
		for i := range events {
			events[i] = nativeEvidence(t, batchNumber*12+i)
			events[i].Observation = json.RawMessage(`{"padding":"` + strings.Repeat("x", 250<<10) + `"}`)
			events[i].Integrity.PayloadSHA256 = event.SHA256Hex(events[i].Observation)
		}
		body := batchOf(t, stream, uint64(batchNumber*12+1), events...)
		if batchNumber == 5 {
			send(t, h.request(t, protocol.EvidencePath, body, key), 429)
		} else {
			ack := readAck(t, h, body, key)
			if ack.Accepted != 12 {
				t.Fatalf("quota fixture: %+v", ack)
			}
		}
		h.clock.seconds.Add(5)
	}
	ack := readAck(t, h, batchOf(t, stream, 1, nativeEvidence(t, 0)), other)
	if ack.Accepted != 1 {
		t.Fatal("byte exhaustion starved other identity")
	}
	id := protocol.ID(key.Public().(ed25519.PublicKey))
	files, err := os.ReadDir(filepath.Join(dir, id))
	if err != nil {
		t.Fatal(err)
	}
	var bytes int64
	for _, file := range files {
		info, err := file.Info()
		if err != nil {
			t.Fatal(err)
		}
		bytes += info.Size()
	}
	if bytes > hub.NodeEvidenceBytes {
		t.Fatalf("retention exceeded per-node byte cap: %d", bytes)
	}
}

func TestEvidenceDisabledDoesNotBlockHeartbeat(t *testing.T) {
	h := newHarness(t)
	reporter, err := agent.New(agent.Options{HubURL: h.server.URL, StateDir: filepath.Join(t.TempDir(), "agent"),
		Name: "test-node", Token: h.mint(t, 0).Token, Interval: 10 * time.Second, Now: h.clock.now, Snapshot: heartbeat,
		ForwardEvidence: true})
	if err != nil {
		t.Fatal(err)
	}
	defer reporter.Close()
	if err := reporter.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	reporter.Enqueue(nativeEvidence(t, 1))
	if err := reporter.ForwardStep(context.Background()); err == nil {
		t.Fatal("disabled hub accepted evidence")
	}
	status := reporter.Status().Forwarding
	if status.LastError != "evidence_disabled" || status.QueuedEvents != 1 {
		t.Fatalf("disabled state: %+v", status)
	}
	h.clock.seconds.Add(10)
	if err := reporter.Step(context.Background()); err != nil {
		t.Fatal("forwarding refusal blocked heartbeat", err)
	}
}
