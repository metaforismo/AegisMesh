// Package benchfixture supplies deterministic, synthetic performance workloads.
// It is imported only by benchmarks, never by application code.
package benchfixture

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/observe"
)

const Offered = 50000

// Now fixes window boundaries independently of wall-clock time.
var Now = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

// Envelope mixes eight sensors, four protocols, 256 sources, three classes and detections.
func Envelope(i int) event.Envelope {
	kind := []string{"http", "mcp", "ssh", "tcp"}[i%4]
	source := fmt.Sprintf("203.0.%d.%d", (i%256)/128, i%128+1)
	classification := event.ClassificationInteraction
	body := fmt.Sprintf(`{"remote_host":%q,"method":"GET","path":"/synthetic/admin","response":{"status":403},"tool_name":"synthetic","auth_method":"password","auth_attempts":2,"outcome":"rejected","lines_exchanged":3,"bytes_total":256}`, source)
	if i%3 == 0 {
		body = body[:len(body)-1] + `,"detection":{"action":"tag","findings":[{"rule_id":"PI-001","confidence":"high"}]}}`
	}
	if i%11 == 0 {
		classification = event.ClassificationCanaryHit
	}
	if i%101 == 0 {
		classification = event.ClassificationCorrelationSignal
		body = fmt.Sprintf(`{"source_key":%q,"rule_id":"COR-001","summary":"Synthetic repeated interaction","source_event_ids":["%032x"]}`, source, max(0, i-40))
	}
	raw := json.RawMessage(body)
	return event.Envelope{Schema: event.SchemaV1, ID: fmt.Sprintf("%032x", i), Time: Now.Add(time.Duration(i-Offered) * 24 * time.Second), Seq: uint64(i + 1), Instance: "synthetic-benchmark", Sensor: event.SensorRef{ID: fmt.Sprintf("sensor-%d", i%8), Kind: kind, Listen: "127.0.0.1:8080"}, Classification: classification, Observation: raw, Integrity: event.Integrity{Algorithm: "sha256", PayloadSHA256: event.SHA256Hex(raw)}}
}

// Indexes loads Offered events into each independent tenant partition. The real
// 64 MiB byte bound remains active, so retained counts are lower than Offered.
func Indexes(tb testing.TB, tenants int) []*evidenceindex.Index {
	tb.Helper()
	indexes := make([]*evidenceindex.Index, tenants)
	for i := range indexes {
		var err error
		indexes[i], err = evidenceindex.New(Offered, observe.NewRegistry())
		if err != nil {
			tb.Fatal(err)
		}
	}
	for i := 0; i < Offered; i++ {
		e := Envelope(i)
		for _, index := range indexes {
			Add(index, e, i)
		}
	}
	for _, index := range indexes {
		stats := index.Stats()
		if stats.Events == 0 || stats.Events >= Offered || stats.History != "truncated" {
			tb.Fatalf("eviction fixture: %+v", stats)
		}
	}
	return indexes
}

// Add mixes local evidence with authenticated remote origins.
func Add(index *evidenceindex.Index, e event.Envelope, i int) {
	if i%5 == 0 {
		index.Add(e)
	} else {
		index.AddForwarded(e, fmt.Sprintf("%032x", i%8+1))
	}
}
