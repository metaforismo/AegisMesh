package evidenceview

import (
	"fmt"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

// BenchmarkSessionsFullSample measures sessions, actor profiles and campaign
// assignment over a saturated 8192-event sample from 512 sources.
func BenchmarkSessionsFullSample(b *testing.B) {
	events := make([]evidenceindex.Summary, 0, evidenceindex.AnalysisLimit)
	for i := 0; len(events) < evidenceindex.AnalysisLimit; i++ {
		source := fmt.Sprintf("198.51.100.%d", i%254+1)
		if i%512 >= 254 {
			source = fmt.Sprintf("203.0.113.%d", i%254+1)
		}
		events = append(events, walk(source, time.Duration(i)*time.Second, evidenceindex.ClientOpenAISDK,
			fmt.Sprintf("GET /v1/models/%d", i), "GET /api/tags", fmt.Sprintf("POST /v1/runs/run_%08d", i))...)
	}
	events = events[:evidenceindex.AnalysisLimit]
	b.ReportAllocs()
	for b.Loop() {
		_ = Sessions("bench", events)
	}
}
