package console

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/fleet/hub"
	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/testutil/benchfixture"
)

// BenchmarkAcceptingHubOverview includes a real accepting registry and live name resolution.
// Setup enrolls eight synthetic identities and offers 50,000 current-window events.
func BenchmarkAcceptingHubOverview(b *testing.B) {
	index, err := evidenceindex.New(50000, observe.NewRegistry())
	if err != nil {
		b.Fatal(err)
	}
	registry, err := hub.New(hub.Options{
		StateDir: filepath.Join(b.TempDir(), "hub"),
		Evidence: &hub.EvidenceOptions{},
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = registry.Close() })
	ids := []string{}
	for i := 0; i < 8; i++ {
		seed := make([]byte, ed25519.SeedSize)
		seed[0] = byte(i + 1)
		key := ed25519.NewKeyFromSeed(seed)
		token, err := registry.Mint(300, "synthetic benchmark")
		if err != nil {
			b.Fatal(err)
		}
		body, _ := json.Marshal(protocol.Enrollment{
			Token:           token.Token,
			PublicKey:       hex.EncodeToString(key.Public().(ed25519.PublicKey)),
			Name:            fmt.Sprintf("synthetic-node-%d", i),
			IntervalSeconds: 10,
		})
		request := httptest.NewRequest("POST", protocol.EnrollPath, bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if err := protocol.Sign(request, body, key, time.Now()); err != nil {
			b.Fatal(err)
		}
		w := httptest.NewRecorder()
		registry.ServeHTTP(w, request)
		if w.Code != 200 {
			b.Fatalf("enroll: %d %s", w.Code, w.Body.String())
		}
		ids = append(ids, protocol.ID(key.Public().(ed25519.PublicKey)))
	}
	index.SetNodeNames(func(id string) string {
		node, err := registry.Node(id)
		if err != nil {
			return ""
		}
		return node.Name
	})
	now := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	for i := 0; i < benchfixture.Offered; i++ {
		e := benchfixture.Envelope(i)
		e.Time = now.Add(time.Duration(i-benchfixture.Offered) * time.Second)
		index.AddForwarded(e, ids[i%len(ids)])
	}
	b.Logf("offered=%d retained=%d nodes=%d", benchfixture.Offered, index.Stats().Events, len(ids))
	s, err := New(Options{
		Config: config.Console{
			Enabled: true,
			Listen:  "127.0.0.1:0",
			Operators: []config.Operator{{
				Name:        "benchmark",
				Role:        "viewer",
				TokenSHA256: auth.Digest("synthetic-benchmark"),
			}},
		},
		StateDir: filepath.Join(b.TempDir(), "console"),
		Index:    index,
		Runtime:  absentRuntime{},
		Meter:    observe.NewRegistry(),
		FleetHub: registry,
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = s.Close(context.Background()) })
	req := httptest.NewRequest(http.MethodGet, "http://"+s.Addr()+"/api/v1/overview?window=24h", nil)
	req.Header.Set("Authorization", "Bearer synthetic-benchmark")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		if w.Code != 200 {
			b.Fatalf("overview: %d %s", w.Code, w.Body.String())
		}
	}
}
