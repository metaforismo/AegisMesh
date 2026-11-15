package hub

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
	"github.com/metaforismo/aegismesh/internal/observe"
)

func TestTenantEnrollmentForwardingAndQuotas(t *testing.T) {
	indexes := map[string]*evidenceindex.Index{}
	for _, name := range []string{"default", "bravo"} {
		index, err := evidenceindex.New(1000, observe.NewRegistry())
		if err != nil {
			t.Fatal(err)
		}
		indexes[name] = index
	}
	dir := filepath.Join(t.TempDir(), "hub")
	registry, err := New(Options{
		StateDir: dir, Tenants: []string{"default", "bravo"}, Evidence: &EvidenceOptions{},
		TenantAppend: func(name, id string, envelope event.Envelope) { indexes[name].AddForwarded(envelope, id) },
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(registry)
	defer server.Close()
	defer registry.Close()
	a, b := registry.ForTenant("default"), registry.ForTenant("bravo")
	send := func(path string, input any, key ed25519.PrivateKey) int {
		t.Helper()
		body, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		request, _ := http.NewRequest("POST", server.URL+path, bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if err := protocol.Sign(request, body, key, time.Now()); err != nil {
			t.Fatal(err)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		return response.StatusCode
	}
	enroll := func(owner *Hub, seed byte) ed25519.PrivateKey {
		t.Helper()
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
		token, err := owner.Mint(3600, "tenant fixture")
		if err != nil {
			t.Fatal(err)
		}
		input := protocol.Enrollment{
			Token:           token.Token,
			PublicKey:       hex.EncodeToString(key.Public().(ed25519.PublicKey)),
			Name:            "test-node",
			IntervalSeconds: 10,
		}
		if status := send(protocol.EnrollPath, input, key); status != 200 {
			t.Fatalf("enrollment: %d", status)
		}
		return key
	}
	keyA, keyB := enroll(a, 1), enroll(b, 2)
	idA := protocol.ID(keyA.Public().(ed25519.PublicKey))
	idB := protocol.ID(keyB.Public().(ed25519.PublicKey))
	if node, err := a.Node(idA); err != nil || node.Tenant != "default" {
		t.Fatal("A node ownership missing", err)
	}
	if _, err := b.Node(idA); Code(err) != "not_found" {
		t.Fatal("B can see A node")
	}
	if _, err := a.Revoke(idB); Code(err) != "not_found" {
		t.Fatal("A can mutate B node")
	}
	tokenB, err := b.Mint(3600, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.DeleteToken(tokenB.ID); Code(err) != "not_found" {
		t.Fatal("foreign token visible")
	}
	// Re-enrollment with another tenant's token cannot move an existing identity.
	input := protocol.Enrollment{
		Token:           tokenB.Token,
		PublicKey:       hex.EncodeToString(keyA.Public().(ed25519.PublicKey)),
		Name:            "test-node",
		IntervalSeconds: 10,
	}
	_ = send(protocol.EnrollPath, input, keyA)
	if _, err := b.Node(idA); Code(err) != "not_found" {
		t.Fatal("node moved partitions")
	}
	for range MaxTokens {
		if _, err := a.Mint(3600, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.Mint(3600, ""); Code(err) != "capacity" {
		t.Fatal("A quota not enforced")
	}
	if _, err := b.Mint(3600, ""); err != nil {
		t.Fatal("A token quota exhausted B", err)
	}
	envelope, err := event.New(&event.Sequencer{}, "synthetic", event.SensorRef{ID: "web", Kind: "http"},
		event.ClassificationInteraction, json.RawMessage(`{"method":"GET","path":"/"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(envelope)
	batch := protocol.EvidenceBatch{StreamID: strings.Repeat("c", 32), First: 1, Last: 1, Events: []json.RawMessage{raw}}
	if status := send(protocol.EvidencePath, batch, keyA); status != 200 {
		t.Fatalf("A forward: %d", status)
	}
	if indexes["default"].Stats().Events != 1 || indexes["bravo"].Stats().Events != 0 {
		t.Fatal("forwarded evidence crossed tenant")
	}
	// Exhaust A's accounted retention budget without allocating 256 MiB on disk.
	a.evidenceReceiver.total.Store(TotalEvidenceBytes)
	if status := send(protocol.EvidencePath, batch, keyB); status != 200 {
		t.Fatalf("A byte quota exhausted B: %d", status)
	}
	if indexes["bravo"].Stats().Events != 1 {
		t.Fatal("B evidence missing")
	}
	// Construct a valid full A registry, then exercise the real enrollment boundary.
	a.mu.Lock()
	for i := 1; len(a.state.Nodes) < MaxNodes; i++ {
		seed := make([]byte, 32)
		seed[0], seed[1] = byte(i), byte(i>>8)
		key := ed25519.NewKeyFromSeed(seed)
		public := key.Public().(ed25519.PublicKey)
		id := protocol.ID(public)
		a.state.Nodes[id] = registration{PublicKey: hex.EncodeToString(public), IntervalSeconds: 10, Node: protocol.Node{
			ID: id, Name: "quota-node", Status: "online", EnrolledAt: time.Now().UTC().Format(time.RFC3339Nano),
			PublicKeyFingerprint: protocol.Digest(public), Sensors: []protocol.Sensor{},
		}}
	}
	a.mu.Unlock()
	// Free one credential slot while retaining the full node registry.
	tokens, _ := a.Tokens()
	if err := a.DeleteToken(tokens[0].ID); err != nil {
		t.Fatal(err)
	}
	tokenA, err := a.Mint(3600, "")
	if err != nil {
		t.Fatal(err)
	}
	newKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{255}, 32))
	input = protocol.Enrollment{
		Token:           tokenA.Token,
		PublicKey:       hex.EncodeToString(newKey.Public().(ed25519.PublicKey)),
		Name:            "new-node",
		IntervalSeconds: 10,
	}
	if status := send(protocol.EnrollPath, input, newKey); status != 503 {
		t.Fatalf("node cap: %d", status)
	}
	_ = enroll(b, 3)
	if nodes, err := b.Nodes(""); err != nil || len(nodes) != 2 {
		t.Fatalf("A node quota exhausted B: %v %d", err, len(nodes))
	}
	if registry.ForTenant("../escape") != nil {
		t.Fatal("undeclared partition created")
	}
}
