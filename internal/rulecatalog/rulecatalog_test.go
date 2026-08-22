package rulecatalog

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/metaforismo/aegismesh/internal/correlate"
	"github.com/metaforismo/aegismesh/internal/detect"
)

func TestAllIsDeterministicAndGroupedByFamily(t *testing.T) {
	a, b := All(), All()
	if len(a) == 0 {
		t.Fatal("catalog must not be empty")
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("two calls produced different catalogs")
	}
	seenCorrelation := false
	for i, e := range a {
		if e.Family == FamilyDetection && seenCorrelation {
			t.Fatalf("entry %d returns to %q after the %q block", i, e.Family, FamilyCorrelation)
		}
		if e.Family == FamilyCorrelation {
			seenCorrelation = true
		}
	}
	if first := a[0]; first.ID != string(detect.RuleDirectInjection) || first.Family != FamilyDetection {
		t.Fatalf("first entry = %+v, want PI-001/detection", first)
	}
	last := a[len(a)-1]
	wantLast := correlate.KnownRuleIDs()
	if last.ID != wantLast[len(wantLast)-1] || last.Family != FamilyCorrelation {
		t.Fatalf("last entry = %+v, want COR-004/correlation", last)
	}
}

func TestCatalogCoversBothRegistriesExactly(t *testing.T) {
	all := All()
	got := map[string]Entry{}
	for _, e := range all {
		if _, dup := got[e.ID]; dup {
			t.Fatalf("duplicate id %q", e.ID)
		}
		got[e.ID] = e
	}
	for _, id := range detect.KnownRuleIDs() {
		e, ok := got[id]
		if !ok {
			t.Fatalf("detection rule %s missing from catalog", id)
		}
		if e.Family != FamilyDetection || e.Class != ClassFinding {
			t.Fatalf("detection rule %s misclassified: %+v", id, e)
		}
		delete(got, id)
	}
	for _, id := range correlate.KnownRuleIDs() {
		e, ok := got[id]
		if !ok {
			t.Fatalf("correlation rule %s missing from catalog", id)
		}
		if e.Family != FamilyCorrelation || e.Class != ClassSignal {
			t.Fatalf("correlation rule %s misclassified: %+v", id, e)
		}
		delete(got, id)
	}
	if len(got) != 0 {
		t.Fatalf("catalog has entries no registry owns: %v", keys(got))
	}
}

func TestSeverityInvariantPerClass(t *testing.T) {
	for _, e := range All() {
		switch e.Class {
		case ClassFinding:
			switch e.Severity {
			case "info", "low", "medium", "high":
			default:
				t.Fatalf("finding %s has invalid severity %q", e.ID, e.Severity)
			}
		case ClassSignal:
			if e.Severity != "" {
				t.Fatalf("signal %s must carry no severity, has %q", e.ID, e.Severity)
			}
		default:
			t.Fatalf("entry %s unknown class %q", e.ID, e.Class)
		}
		if e.Summary == "" {
			t.Fatalf("entry %s has empty summary", e.ID)
		}
	}
}

func TestLookupIsExactMatchOnly(t *testing.T) {
	if e, ok := Lookup("PI-001"); !ok || e.ID != "PI-001" || e.Summary == "" {
		t.Fatalf("known id must resolve with summary: %+v ok=%v", e, ok)
	}
	if e, ok := Lookup("COR-003"); !ok || e.Family != FamilyCorrelation {
		t.Fatalf("correlation lookup wrong: %+v ok=%v", e, ok)
	}
	for _, bad := range []string{"pi-001", " PI-001", "PI-001 ", "PI-", "EXF-001x", "COR-999", "", "P"} {
		if e, ok := Lookup(bad); ok {
			t.Fatalf("%q must not resolve, got %+v", bad, e)
		}
	}
}

func TestEntryJSONShapeIsStable(t *testing.T) {
	det := All()[0] // detection: severity present
	raw, err := json.Marshal(det)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	wantKeys := map[string]bool{"id": true, "family": true, "class": true, "severity": true, "summary": true}
	if len(m) != len(wantKeys) || !reflect.DeepEqual(keySet(m), wantKeys) {
		t.Fatalf("detection entry keys drifted: %v", m)
	}

	var sig Entry
	for _, e := range All() {
		if e.Class == ClassSignal {
			sig = e
			break
		}
	}
	raw, err = json.Marshal(sig)
	if err != nil {
		t.Fatal(err)
	}
	m = nil
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	delete(wantKeys, "severity") // omitempty: signals marshal without it
	if len(m) != len(wantKeys) || !reflect.DeepEqual(keySet(m), wantKeys) {
		t.Fatalf("signal entry keys drifted (severity must be omitted): %v", m)
	}
}

func TestFamiliesAndValidationHelpers(t *testing.T) {
	fams := Families()
	if !reflect.DeepEqual(fams, []string{FamilyDetection, FamilyCorrelation}) {
		t.Fatalf("families = %v", fams)
	}
	if !ValidFamily(FamilyDetection) || !ValidFamily(FamilyCorrelation) {
		t.Fatal("canonical families must validate")
	}
	for _, bad := range []string{"", "Detection", "detect", "all"} {
		if ValidFamily(bad) {
			t.Fatalf("%q must not be a valid family", bad)
		}
	}
}

func keys(m map[string]Entry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func keySet(m map[string]any) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}
