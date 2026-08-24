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

// LabeledCounter partitions one metric by a single label whose values come
// exclusively from operator/config enums (rule IDs, severities, action names)
// — never from network or file input. Cardinality is capped at construction:
// unknown labels route to a dedicated "_overflow" series instead of growing.
type LabeledCounter interface {
	Inc(label string)
}

// Meter is the seam sensors depend on. A no-op implementation keeps sensor
// code testable without a registry.
type Meter interface {
	Counter(name, help string) Counter
	Gauge(name, help string) Gauge
	CounterVec(name, help string, maxSeries int) LabeledCounter
	WritePrometheus() string
}

// Registry is the concrete Meter. Names must be valid Prometheus metric names;
// invalid names are rejected by returning a no-op metric rather than panicking.
type Registry struct {
	mu       sync.Mutex
	counters map[string]*counter
	gauges   map[string]*gauge
	vecs     map[string]*counterVec
	metas    map[string]string // name -> help
}

func NewRegistry() *Registry {
	return &Registry{
		counters: map[string]*counter{},
		gauges:   map[string]*gauge{},
		vecs:     map[string]*counterVec{},
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

const (
	maxSeriesHardCap = 64
	overflowLabel    = "_overflow"
)

// CounterVec creates a bounded-cardinality labeled counter. maxSeries is
// clamped to 1..maxSeriesHardCap; the "_overflow" series always exists and
// absorbs unknown or over-cap labels, so a caller bug (or anything worse)
// can grow this metric by at most maxSeries+1 time series.
func (r *Registry) CounterVec(name, help string, maxSeries int) LabeledCounter {
	if !validMetricName(name) {
		return nopLabeled{}
	}
	if maxSeries < 1 {
		maxSeries = 8
	}
	if maxSeries > maxSeriesHardCap {
		maxSeries = maxSeriesHardCap
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing := r.vecs[name]; existing != nil {
		return existing
	}
	v := &counterVec{reg: r, name: name, cap: maxSeries, series: map[string]*counter{}}
	r.vecs[name] = v
	if help != "" {
		r.metas[name] = sanitizeHelp(help)
	}
	return v
}

type counterVec struct {
	reg    *Registry
	name   string
	cap    int
	mu     sync.Mutex // guards series creation; counters themselves are atomic
	series map[string]*counter
}

func validLabel(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-', c == '.':
		default:
			return false
		}
	}
	return true
}

func (v *counterVec) Inc(label string) {
	if !validLabel(label) || label == overflowLabel {
		label = overflowLabel
	}
	v.mu.Lock()
	c, ok := v.series[label]
	if !ok && len(v.series) < v.cap {
		c = &counter{}
		v.series[label] = c
	}
	v.mu.Unlock()
	if c == nil { // over cardinality cap: aggregate, never grow
		c = v.overflow()
	}
	c.Inc()
}

func (v *counterVec) overflow() *counter {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.series[overflowLabel] == nil {
		v.series[overflowLabel] = &counter{}
	}
	return v.series[overflowLabel]
}

// WritePrometheus renders the registry in Prometheus text format (v0.0.4).
// Counters sort before gauges; labeled counters render as
// name{label="value"} series sorted by label.
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
	vnames := make([]string, 0, len(r.vecs))
	for n := range r.vecs {
		vnames = append(vnames, n)
	}
	sort.Strings(vnames)
	for _, n := range vnames {
		v := r.vecs[n]
		writeType("counter", n, "")
		v.mu.Lock()
		labels := make([]string, 0, len(v.series))
		for l := range v.series {
			labels = append(labels, l)
		}
		sort.Strings(labels)
		for _, l := range labels {
			sb.WriteString(fmt.Sprintf("%s{label=\"%s\"} %s\n", n, escapeLabelValue(l),
				formatFloat(math.Float64frombits(v.series[l].v.Load()))))
		}
		v.mu.Unlock()
	}
	return sb.String()
}

func escapeLabelValue(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s
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

type nopLabeled struct{}

func (nopLabeled) Inc(string) {}
