package hub

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
)

// BenchmarkHeartbeat1000 measures signing, HTTP handling, verification and storage
// with 1000 enrolled identities. Setup persists one representative full registry.
func BenchmarkHeartbeat1000(b *testing.B) {
	var seconds atomic.Int64
	seconds.Store(1800000000)
	now := func() time.Time { return time.Unix(seconds.Load(), 0) }
	h, err := New(Options{StateDir: filepath.Join(b.TempDir(), "hub"), Now: now})
	if err != nil {
		b.Fatal(err)
	}
	defer h.Close()
	keys := make([]ed25519.PrivateKey, MaxNodes)
	h.mu.Lock()
	for i := range keys {
		seed := make([]byte, ed25519.SeedSize)
		seed[0], seed[1] = byte(i), byte(i>>8)
		keys[i] = ed25519.NewKeyFromSeed(seed)
		public := keys[i].Public().(ed25519.PublicKey)
		id := protocol.ID(public)
		h.state.Nodes[id] = registration{PublicKey: hex.EncodeToString(public), IntervalSeconds: 30,
			Node: protocol.Node{ID: id, Name: "bench-node", Status: "online", EnrolledAt: now().Format(time.RFC3339Nano),
				PublicKeyFingerprint: protocol.Digest(public), Sensors: []protocol.Sensor{}}}
	}
	if err := h.save(); err != nil {
		b.Fatal(err)
	}
	h.mu.Unlock()
	body, err := json.Marshal(protocol.Heartbeat{Name: "bench-node", Sensors: []protocol.Sensor{}, StorageHealthy: true})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Each node reports every 30 seconds; distinct source IPs avoid conflating the
		// per-address network throttle with the authenticated heartbeat workload.
		seconds.Store(1800000000 + int64(i/MaxNodes)*30)
		request := httptest.NewRequest("POST", protocol.HeartbeatPath, bytes.NewReader(body))
		request.RemoteAddr = fmt.Sprintf("192.0.%d.%d:1234", (i%MaxNodes)/256, (i%MaxNodes)%256)
		request.Header.Set("Content-Type", "application/json")
		if err := protocol.Sign(request, body, keys[i%MaxNodes], now()); err != nil {
			b.Fatal(err)
		}
		response := httptest.NewRecorder()
		h.ServeHTTP(response, request)
		if response.Code != 200 {
			b.Fatalf("heartbeat: %d %s", response.Code, response.Body.String())
		}
	}
	b.StopTimer()
}
