package correlate

import (
	"testing"
)

func TestSignalCatalogMatchesRegistry(t *testing.T) {
	cat := SignalCatalog()
	known := KnownRuleIDs()
	if len(cat) != len(known) {
		t.Fatalf("catalog has %d entries, registry %d", len(cat), len(known))
	}
	for i, info := range cat {
		if string(info.ID) != known[i] {
			t.Fatalf("entry %d = %q, want enum order %q", i, info.ID, known[i])
		}
		if info.Summary == "" || info.Summary != ruleSummaries[info.ID] {
			t.Fatalf("rule %s summary missing or not from registry", info.ID)
		}
	}
}
