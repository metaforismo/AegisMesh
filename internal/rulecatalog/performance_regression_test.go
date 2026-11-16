package rulecatalog

import (
	"reflect"
	"testing"

	"github.com/metaforismo/aegismesh/internal/correlate"
	"github.com/metaforismo/aegismesh/internal/detect"
)

func TestImmutableMetadataMatchesOwnersAndSurvivesCallerMutation(t *testing.T) {
	// Registries are compile-time metadata: no live registration, TTL, or
	// request-dependent keys exist to invalidate or grow the retained snapshot.
	var want []Entry
	for _, rule := range detect.RuleCatalog() {
		want = append(want, Entry{ID: string(rule.ID), Family: FamilyDetection, Class: ClassFinding, Severity: string(rule.Severity), Summary: rule.Summary})
	}
	for _, rule := range correlate.SignalCatalog() {
		want = append(want, Entry{ID: string(rule.ID), Family: FamilyCorrelation, Class: ClassSignal, Summary: rule.Summary})
	}
	if got := All(); !reflect.DeepEqual(got, want) {
		t.Fatalf("owner metadata changed: %v", got)
	}
	returned := All()
	returned[0].Summary = "mutated"
	returned[0].ID = "mutated"
	if got := All(); !reflect.DeepEqual(got, want) {
		t.Fatal("All aliases retained metadata")
	}
	for _, entry := range want {
		got, ok := Lookup(entry.ID)
		if !ok || got != entry {
			t.Fatalf("lookup after mutation: %+v %t", got, ok)
		}
	}
	for i := 0; i < 100; i++ {
		if _, ok := Lookup("absent"); ok {
			t.Fatal("unknown rule")
		}
	}
	if len(entries) != len(want) {
		t.Fatal("misses grew catalog")
	}
}
