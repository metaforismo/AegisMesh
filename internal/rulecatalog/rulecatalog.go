// Package rulecatalog exposes one read-only catalog of every rule the
// binaries can emit: detection findings (PI-*/EXF-*/ESC-*/OBS-*/RES-*) and
// correlation signals (COR-*). Metadata is derived from the owning engine
// registries — this package owns no rule truth of its own, so summaries and
// severities cannot drift from what engines actually produce. Order is the
// owners' published order: detection rules first (registration order), then
// correlation signals (enum order).
package rulecatalog

import (
	"github.com/metaforismo/aegismesh/internal/correlate"
	"github.com/metaforismo/aegismesh/internal/detect"
)

// Family groups rules by the engine that owns them.
const (
	FamilyDetection   = "detection"
	FamilyCorrelation = "correlation"
)

// Class states what an emitted rule instance is: a per-interaction finding
// from detection, or a derived signal from correlation.
const (
	ClassFinding = "finding"
	ClassSignal  = "signal"
)

// Entry is one rule's stable operator-facing metadata.
type Entry struct {
	ID       string `json:"id"`
	Family   string `json:"family"`
	Class    string `json:"class"`
	Severity string `json:"severity,omitempty"` // detection only; signals carry none
	Summary  string `json:"summary"`
}

// All returns every entry in deterministic owner-defined order. The slice is
// freshly allocated; callers may mutate it without affecting later calls.
func All() []Entry {
	det := detect.RuleCatalog()
	out := make([]Entry, 0, len(det)+4)
	for _, r := range det {
		out = append(out, Entry{
			ID:       string(r.ID),
			Family:   FamilyDetection,
			Class:    ClassFinding,
			Severity: string(r.Severity),
			Summary:  r.Summary,
		})
	}
	for _, s := range correlate.SignalCatalog() {
		out = append(out, Entry{
			ID:      string(s.ID),
			Family:  FamilyCorrelation,
			Class:   ClassSignal,
			Summary: s.Summary,
		})
	}
	return out
}

// Lookup resolves one id with exact byte matching only: no case folding, no
// trimming, no prefixes. The catalogs are tiny (~10 entries), so a linear
// scan keeps the API stateless and allocation-free for misses.
func Lookup(id string) (Entry, bool) {
	if id == "" {
		return Entry{}, false
	}
	for _, e := range All() {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}

// Families lists filterable family values in canonical order.
func Families() []string { return []string{FamilyDetection, FamilyCorrelation} }

// ValidFamily reports whether f names a known family (exact match).
func ValidFamily(f string) bool {
	switch f {
	case FamilyDetection, FamilyCorrelation:
		return true
	default:
		return false
	}
}
