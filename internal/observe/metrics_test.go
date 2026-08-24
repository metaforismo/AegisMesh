package observe

import (
	"strings"
	"sync"
	"testing"
)

func TestPrometheusExpositionFormat(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("aegismesh_events_total", "Total events observed")
	g := r.Gauge("aegismesh_active_sessions", "Active sessions")
	c.Add(3)
	c.Inc()
	g.Set(2)
	g.Add(-1)

	out := r.WritePrometheus()
	want := []string{
		"# HELP aegismesh_events_total Total events observed",
		"# TYPE aegismesh_events_total counter",
		"aegismesh_events_total 4",
		"# TYPE aegismesh_active_sessions gauge",
		"aegismesh_active_sessions 1",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("exposition missing %q in:\n%s", w, out)
		}
	}
}

func TestInvalidMetricNamesAreNoOps(t *testing.T) {
	r := NewRegistry()
	r.Counter("bad name!", "x").Inc()
	r.Gauge("", "x").Set(1)
	if out := r.WritePrometheus(); out != "" {
		t.Fatalf("invalid names must not render: %q", out)
	}
}

func TestConcurrentCounterUpdates(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("concurrent_total", "concurrency test")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				c.Inc()
			}
		}()
	}
	wg.Wait()
	out := r.WritePrometheus()
	if !strings.Contains(out, "concurrent_total 8000") {
		t.Fatalf("counter lost updates under concurrency:\n%s", out)
	}
}

func TestHelpSanitization(t *testing.T) {
	r := NewRegistry()
	r.Counter("sanitized_total", "help with \\ backslash and\nnewline")
	out := r.WritePrometheus()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 { // HELP + TYPE + value
		t.Fatalf("help text must be single-line, got %d lines:\n%s", len(lines), out)
	}
	if strings.Contains(lines[0], "\n") {
		t.Fatalf("raw newline survived in HELP: %q", lines[0])
	}
}

func TestCounterVecConstructionPreservesExistingSeries(t *testing.T) {
	r := NewRegistry()
	r.CounterVec("shared_total", "first", 4).Inc("one")
	r.CounterVec("shared_total", "second", 8).Inc("two")
	out := r.WritePrometheus()
	for _, want := range []string{`shared_total{label="one"} 1`, `shared_total{label="two"} 1`} {
		if !strings.Contains(out, want) {
			t.Fatalf("repeated CounterVec construction lost %q:\n%s", want, out)
		}
	}
}
