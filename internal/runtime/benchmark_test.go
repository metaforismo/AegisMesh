package runtime

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/fleet/agent"
	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/testutil/benchfixture"
)

// benchStored isolates tap overhead from disk cost, measured separately in storage.
type benchStored struct{}

func (benchStored) Append(context.Context, event.Envelope) error { return nil }

func BenchmarkRuntimeTap(b *testing.B) {
	for _, mode := range []string{"Primary", "Index", "IndexForwarder"} {
		b.Run(mode, func(b *testing.B) {
			indexes := benchfixture.Indexes(b, 1)
			var sink event.Sink = benchStored{}
			if mode != "Primary" {
				sink = &indexedSink{primary: sink, index: indexes[0]}
			}
			if mode == "IndexForwarder" {
				a, err := agent.New(agent.Options{HubURL: "http://127.0.0.1:1", StateDir: filepath.Join(b.TempDir(), "agent"), Name: "synthetic-bench", Interval: 30 * time.Second, Snapshot: func() protocol.Heartbeat { return protocol.Heartbeat{} }, ForwardEvidence: true, Meter: observe.NewRegistry(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
				if err != nil {
					b.Fatal(err)
				}
				defer a.Close()
				sink = &fleetSink{primary: sink, system: &System{fleetAgent: a}}
			}
			// Reuse bounded payloads; new IDs prevent duplicate-index fast paths.
			ids := make([]string, 65536)
			for i := range ids {
				ids[i] = fmt.Sprintf("%032x", benchfixture.Offered+i)
			}
			e := benchfixture.Envelope(benchfixture.Offered)
			ctx := context.Background()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				e.ID = ids[i%len(ids)]
				e.Time = benchfixture.Now.Add(time.Duration(i) * time.Millisecond)
				if err := sink.Append(ctx, e); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
