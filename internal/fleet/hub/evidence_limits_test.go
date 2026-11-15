package hub

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
	"github.com/metaforismo/aegismesh/internal/storage"
)

func TestAggregateReservationsAreAtomicAndBounded(t *testing.T) {
	receiver := &evidenceReceiver{}
	var admitted atomic.Int64
	var workers sync.WaitGroup
	for range 64 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if receiver.reserve(NodeEvidenceBytes) {
				admitted.Add(1)
			}
		}()
	}
	workers.Wait()
	if receiver.total.Load() != TotalEvidenceBytes || admitted.Load() != TotalEvidenceBytes/NodeEvidenceBytes {
		t.Fatalf("reservation cap: total=%d admitted=%d", receiver.total.Load(), admitted.Load())
	}
}

func TestConfiguredSmallSegmentCapCountsUnfittableEvents(t *testing.T) {
	var seconds atomic.Int64
	seconds.Store(time.Now().Unix())
	now := func() time.Time { return time.Unix(seconds.Load(), 0) }
	dir := t.TempDir()
	h, err := New(Options{StateDir: filepath.Join(dir, "hub"), Now: now, Evidence: &EvidenceOptions{
		Dir: filepath.Join(dir, "copies"), Store: storage.Options{MaxFileBytes: 4096},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := key.Public().(ed25519.PublicKey)
	id := protocol.ID(public)
	h.mu.Lock()
	h.state.Nodes[id] = registration{PublicKey: hex.EncodeToString(public), IntervalSeconds: 30,
		Node: protocol.Node{ID: id, Name: "test-node", Status: "online", EnrolledAt: now().Format(time.RFC3339Nano),
			PublicKeyFingerprint: protocol.Digest(public), Sensors: []protocol.Sensor{}}}
	h.mu.Unlock()
	batch := protocol.EvidenceBatch{StreamID: strings.Repeat("a", 32), First: 1, Last: 21}
	for i := range 21 {
		payload := json.RawMessage(`{"method":"GET","path":"/"}`)
		if i == 20 {
			payload = json.RawMessage(`{"padding":"` + strings.Repeat("a", 4096) + `"}`)
		}
		envelope, err := event.New(&event.Sequencer{}, "synthetic", event.SensorRef{ID: "web", Kind: "http"},
			event.ClassificationInteraction, payload, nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		batch.Events = append(batch.Events, raw)
	}
	body, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", protocol.EvidencePath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := protocol.Sign(request, body, key, now()); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	var ack protocol.EvidenceAck
	if json.Unmarshal(response.Body.Bytes(), &ack) != nil || response.Code != 200 || ack.Accepted != 20 || ack.Invalid != 1 {
		t.Fatalf("segment-fit policy: %d %s", response.Code, response.Body.String())
	}
	copies, err := os.ReadDir(filepath.Join(dir, "hub", "tenants", "default", "evidence", id))
	if err != nil {
		t.Fatal(err)
	}
	if len(copies) < 2 {
		t.Fatal("rotation did not use configured small cap")
	}
	for _, copy := range copies {
		info, err := copy.Info()
		if err != nil || info.Size() > 4096 {
			t.Fatalf("configured segment cap exceeded: %v %v", info, err)
		}
	}
}
