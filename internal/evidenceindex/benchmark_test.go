package evidenceindex_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/testutil/benchfixture"
)

func BenchmarkIndex(b *testing.B) {
	for _, tenants := range []int{1, 8} {
		b.Run(fmt.Sprintf("tenants=%d", tenants), func(b *testing.B) {
			indexes := benchfixture.Indexes(b, tenants)
			appendSequence := 0
			b.Run("AppendEvict", func(b *testing.B) {
				// Generation is excluded; IDs and timestamps still advance on every append.
				ids := make([]string, 65536*tenants)
				for i := range ids {
					ids[i] = fmt.Sprintf("%032x", benchfixture.Offered+i)
				}
				e := benchfixture.Envelope(benchfixture.Offered)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					e.ID = ids[(appendSequence+i)%len(ids)]
					e.Time = benchfixture.Now.Add(time.Duration(appendSequence+i) * time.Millisecond)
					benchfixture.Add(indexes[i%tenants], e, appendSequence+i)
				}
				appendSequence += b.N
				b.ReportMetric(float64(indexes[0].Stats().Events), "retained/tenant")
			})
			// Use a fresh fixture after the mutating workload.
			indexes = benchfixture.Indexes(b, tenants)
			filters := []struct {
				name string
				f    evidenceindex.Filter
			}{
				{"None", evidenceindex.Filter{}},
				{"Node", evidenceindex.Filter{Node: fmt.Sprintf("%032x", 1)}},
				{"Classification", evidenceindex.Filter{Classification: "canary_invocation"}},
				{"Sensor", evidenceindex.Filter{Sensor: "sensor-0"}},
				{"Kind", evidenceindex.Filter{Kind: "http"}},
				{"Source", evidenceindex.Filter{Source: "203.0.0.1"}},
				{"Rule", evidenceindex.Filter{Rule: "PI-001"}},
				{"Severity", evidenceindex.Filter{Severity: "high"}},
				{"Q", evidenceindex.Filter{Q: "admin"}},
				{"Since", evidenceindex.Filter{Since: benchfixture.Now.Add(-time.Hour)}},
				{"Until", evidenceindex.Filter{Until: benchfixture.Now.Add(-24 * time.Hour)}},
				{"Combined", evidenceindex.Filter{Kind: "http", Rule: "PI-001", Source: "203.0.0.1", Since: benchfixture.Now.Add(-24 * time.Hour)}},
			}
			for _, tc := range filters {
				b.Run("Query/"+tc.name, func(b *testing.B) {
					f := tc.f
					f.Limit = 50
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						page, err := indexes[i%tenants].Query(f)
						if err != nil {
							b.Fatal(err)
						}
						if tc.name == "None" && len(page.Events) != 50 {
							b.Fatal("short page")
						}
					}
				})
			}
			b.Run("Query/DeepCursor", func(b *testing.B) {
				filters := make([]evidenceindex.Filter, tenants)
				for i, index := range indexes {
					f := evidenceindex.Filter{Limit: 200}
					for range 50 {
						p, err := index.Query(f)
						if err != nil || p.NextCursor == "" {
							b.Fatal("deep cursor fixture", err)
						}
						f.Cursor = p.NextCursor
					}
					f.Limit = 50
					filters[i] = f
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					p, err := indexes[i%tenants].Query(filters[i%tenants])
					if err != nil || len(p.Events) != 50 {
						b.Fatal("deep page", err)
					}
				}
			})
			for _, window := range []string{"1h", "24h", "7d"} {
				b.Run("Overview/"+window, func(b *testing.B) {
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if _, err := indexes[i%tenants].Overview(window, benchfixture.Now); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
			b.Run("Sources", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					indexes[i%tenants].Sources(benchfixture.Now.Add(-24*time.Hour), benchfixture.Now)
				}
			})
			b.Run("SourceTimeline", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					index := indexes[i%tenants]
					if _, err := index.Query(evidenceindex.Filter{Source: "203.0.0.1", Limit: 50, CursorScope: "source"}); err != nil {
						b.Fatal(err)
					}
					index.Source("203.0.0.1", time.Time{}, benchfixture.Now.Add(time.Second))
				}
			})
			b.Run("Related", func(b *testing.B) {
				id := fmt.Sprintf("%032x", 49995)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, _, _, related, ok := indexes[i%tenants].GetNode(id, ""); !ok || len(related) != 1 {
						b.Fatal("related fixture missing")
					}
				}
			})
			b.ReportMetric(float64(indexes[0].Stats().Events), "retained/tenant")
		})
	}
}
