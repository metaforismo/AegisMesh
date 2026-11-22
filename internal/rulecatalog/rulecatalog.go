// Package rulecatalog exposes one read-only catalog of every rule the
// binaries can emit: per-interaction detection findings and
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
	Frameworks []FrameworkMapping `json:"frameworks"`
	ID         string             `json:"id"`
	Family     string             `json:"family"`
	Class      string             `json:"class"`
	Severity   string             `json:"severity,omitempty"` // detection only; signals carry none
	Summary    string             `json:"summary"`
}

// Entries derive once from compile-time engine registries. There is no runtime
// registration or invalidation; caller-visible slices are always independent.
var entries = buildEntries()

// All returns every entry in deterministic owner-defined order as a fresh slice.
func All() []Entry {
	out := append([]Entry(nil), entries...)
	for i := range out {
		out[i] = cloneEntry(out[i])
	}
	return out
}
func cloneEntry(e Entry) Entry {
	e.Frameworks = append([]FrameworkMapping{}, e.Frameworks...)
	return e
}

func buildEntries() []Entry {
	det := detect.RuleCatalog()
	signals := correlate.SignalCatalog()
	out := make([]Entry, 0, len(det)+len(signals))
	for _, r := range det {
		out = append(out, Entry{
			ID:       string(r.ID),
			Family:   FamilyDetection,
			Class:    ClassFinding,
			Severity: string(r.Severity),
			Summary:  r.Summary,
		})
	}
	for _, s := range signals {
		out = append(out, Entry{
			ID:      string(s.ID),
			Family:  FamilyCorrelation,
			Class:   ClassSignal,
			Summary: s.Summary,
		})
	}
	for i := range out {
		out[i].Frameworks = frameworks(out[i].ID)
	}
	return out
}

// Lookup resolves one id with exact byte matching only: no case folding, no
// trimming, no prefixes. The catalogs are tiny (20 entries), so a linear
// scan over immutable metadata returns independent nested mapping slices.
func Lookup(id string) (Entry, bool) {
	if id == "" {
		return Entry{}, false
	}
	for _, e := range entries {
		if e.ID == id {
			return cloneEntry(e), true
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
