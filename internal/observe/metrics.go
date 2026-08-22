// Package observe provides the Meter seam (ADR-0008) and a minimal,
// dependency-free Prometheus text exposition of counters and gauges.
package observe

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Counter is a monotonically increasing metric.
type Counter interface {
	Inc()
	Add(delta float64)
}

// Gauge is a metric that can go up and down.
type Gauge interface {
	Set(v float64)
	Add(delta float64)
}

// Meter is the seam sensors depend on. A no-op implementation keeps sensor
// code testable without a registry.
type Meter interface {
	Counter(name, help string) Counter
	Gauge(name, help string) Gauge
	WritePrometheus() string
}

// Registry is the concrete Meter. Names must be valid Prometheus metric names;
// invalid names are rejected by returning a no-op metric rather than panicking.
type Registry struct {
	mu       sync.Mutex
	counters map[string]*counter
	gauges   map[string]*gauge
	metas    map[string]string // name -> help
}

func NewRegistry() *Registry {
	return &Registry{
		counters: map[string]*counter{},
		gauges:   map[string]*gauge{},
		metas:    map[string]string{},
	}
}

// counter and gauge store IEEE-754 bits in atomic.Uint64 because the typed
// atomic.Float64 helper is not available in every toolchain distribution.
type counter struct{ v atomic.Uint64 }
type gauge struct{ v atomic.Uint64 }

func (c *counter) Inc()          { c.Add(1) }
func (c *counter) Add(d float64) { atomicAddF64(&c.v, d) }
func (g *gauge) Set(v float64)   { g.v.Store(math.Float64bits(v)) }
func (g *gauge) Add(d float64)   { atomicAddF64(&g.v, d) }

func atomicAddF64(v *atomic.Uint64, d float64) {
	for {
		old := v.Load()
		next := math.Float64bits(math.Float64frombits(old) + d)
		if v.CompareAndSwap(old, next) {
			return
		}
	}
}

func validMetricName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_', c == ':':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

func (r *Registry) Counter(name, help string) Counter {
	if !validMetricName(name) {
		return nopCounter{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.counters[name]; !ok {
		r.counters[name] = &counter{}
		if help != "" {
			r.metas[name] = sanitizeHelp(help)
		}
	}
	return r.counters[name]
}

func (r *Registry) Gauge(name, help string) Gauge {
	if !validMetricName(name) {
		return nopGauge{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.gauges[name]; !ok {
		r.gauges[name] = &gauge{}
		if help != "" {
			r.metas[name] = sanitizeHelp(help)
		}
	}
	return r.gauges[name]
}

// WritePrometheus renders the registry in Prometheus text format (v0.0.4).
// Counters sort before gauges; names sort alphabetically within their type.
func (r *Registry) WritePrometheus() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var sb strings.Builder
	writeType := func(kind, name, help string) {
		if h := r.metas[name]; h != "" {
			sb.WriteString("# HELP " + name + " " + h + "\n")
		}
		sb.WriteString("# TYPE " + name + " " + kind + "\n")
	}
	names := make([]string, 0, len(r.counters)+len(r.gauges))
	for n := range r.counters {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		writeType("counter", n, "")
		sb.WriteString(fmt.Sprintf("%s %s\n", n, formatFloat(math.Float64frombits(r.counters[n].v.Load()))))
	}
	gnames := make([]string, 0, len(r.gauges))
	for n := range r.gauges {
		gnames = append(gnames, n)
	}
	sort.Strings(gnames)
	for _, n := range gnames {
		writeType("gauge", n, "")
		sb.WriteString(fmt.Sprintf("%s %s\n", n, formatFloat(math.Float64frombits(r.gauges[n].v.Load()))))
	}
	return sb.String()
}

func sanitizeHelp(h string) string {
	h = strings.ReplaceAll(h, "\\", "\\\\")
	h = strings.ReplaceAll(h, "\n", " ")
	return h
}

func formatFloat(v float64) string {
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.6f", v), "0"), ".") //nolint:perfsprint // rare path
}

// No-op implementations for invalid names or tests.
type nopCounter struct{}

func (nopCounter) Inc()        {}
func (nopCounter) Add(float64) {}

type nopGauge struct{}

func (nopGauge) Set(float64) {}
func (nopGauge) Add(float64) {}
