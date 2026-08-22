package correlate

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func baseEvent(n int, key string) Event {
	return Event{
		ID:             "ev-" + intStr(n),
		Time:           time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC).Add(time.Duration(n) * time.Second),
		SourceKey:      key,
		SensorID:       "http-decoy",
		SensorKind:     "http",
		Classification: "interaction",
	}
}

func intStr(n int) string { return strconv.Itoa(n) }

func TestOptionsNormalizeAppliesDefaultsAndClamps(t *testing.T) {
	o := Options{Window: -1, PerSourceEvents: 100000, MaxSources: 10}
	o.Normalize()
	if o.Window != DefaultWindow {
		t.Fatalf("window default not applied: %v", o.Window)
	}
	if o.PerSourceEvents != MaxPerSourceEvents {
		t.Fatalf("per-source clamp wrong: %d", o.PerSourceEvents)
	}
	if o.MaxSources != 10 { // explicit value preserved when in range
		t.Fatalf("max_sources changed: %d", o.MaxSources)
	}

}

func TestOptionsValidateRejectsOutOfBounds(t *testing.T) {
	cases := []struct {
		name    string
		opts    Options
		wantErr string
	}{
		{"window over cap", Options{Window: MaxWindow + time.Minute}, "window"},
		{"negative window", Options{Window: -time.Second}, "window"},
		{"per-source over cap", Options{PerSourceEvents: MaxPerSourceEvents + 1}, "per_source_events"},
		{"sources over cap", Options{MaxSources: MaxMaxSources + 1}, "max_sources"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.opts.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
	zero := Options{}
	if err := zero.Validate(); err != nil {
		t.Fatalf("all-zero options are valid pre-normalize: %v", err)
	}
}

func TestRegistryValidation(t *testing.T) {
	if got := len(KnownRuleIDs()); got != 4 {
		t.Fatalf("expected 4 rules, got %d", got)
	}
	if err := ValidateRuleIDs([]string{"COR-001", "COR-004"}); err != nil {
		t.Fatalf("known ids rejected: %v", err)
	}
	err := ValidateRuleIDs([]string{"NOPE-9"})
	if err == nil || !strings.Contains(err.Error(), "unknown correlation rule") || !strings.Contains(err.Error(), "COR-001") {
		t.Fatalf("unknown id must list the registry: %v", err)
	}
	if err := ValidateRuleIDs(nil); err != nil {
		t.Fatalf("empty list valid: %v", err)
	}
}

func TestPerSourceRingIsCappedWithAccounting(t *testing.T) {
	e := New(Options{PerSourceEvents: 4, Now: func() time.Time { return time.Unix(0, 0) }})
	for i := 0; i < 10; i++ {
		e.Ingest(baseEvent(i, "src-a"))
	}
	st := e.Stats()
	if st.TrimmedEvents != 6 {
		t.Fatalf("trimmed = %d, want 6", st.TrimmedEvents)
	}
	if st.SourcesTracked != 1 {
		t.Fatalf("sources = %d", st.SourcesTracked)
	}
	if got := len(e.sources["src-a"].events); got != 4 {
		t.Fatalf("ring length = %d, want 4 (newest kept)", got)
	}
	// Newest survive: last four ids.
	last := e.sources["src-a"].events[3].ID
	if last != "ev-9" {
		t.Fatalf("newest event lost: %q", last)
	}
}

func TestMaxSourcesEvictsOldestFirstArrival(t *testing.T) {
	e := New(Options{MaxSources: 3, PerSourceEvents: 2})
	for i := 0; i < 5; i++ {
		e.Ingest(baseEvent(i, "src-"+intStr(i)))
	}
	if got := e.Stats(); got.EvictedSources != 2 || got.SourcesTracked != 3 {
		t.Fatalf("evicted=%d tracked=%d, want 2/3", got.EvictedSources, got.SourcesTracked)
	}
	for _, k := range []string{"src-0", "src-1"} {
		if _, ok := e.sources[k]; ok {
			t.Fatalf("%s should have been evicted (oldest arrival)", k)
		}
	}
	for _, k := range []string{"src-2", "src-3", "src-4"} {
		if _, ok := e.sources[k]; !ok {
			t.Fatalf("%s must remain", k)
		}
	}
	// Re-arming an existing source does not change its firstSeen slot.
	e.Ingest(baseEvent(50, "src-2"))
	if got := e.Stats(); got.SourcesTracked != 3 || got.EvictedSources != 2 {
		t.Fatalf("touching a source must not evict: %+v", e.Stats())
	}
}

func TestWindowPruningDropsStaleEventsOnly(t *testing.T) {
	win := 30 * time.Second
	e := New(Options{Window: win})
	base := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

	old := baseEvent(1, "s")
	old.Time = base.Add(-win) // exactly at cutoff boundary → kept? Before(cutoff) is false at equality
	recent := baseEvent(2, "s")
	recent.Time = base.Add(-time.Second)
	stale := baseEvent(3, "s")
	stale.Time = base.Add(-2 * win)

	e.Ingest(old)
	e.Ingest(recent)
	// Third ingest prunes against its own reference time (base+3s): old is
	// within cutoff(base+3s-window)=base-27s? old=base-30s < that → pruned.
	e.Ingest(baseEvent(4, "s"))

	st := e.Stats()
	if st.PrunedEvents != 1 {
		t.Fatalf("pruned=%d, want 1 (boundary event stays)", st.PrunedEvents)
	}
	ring := e.sources["s"].events
	if len(ring) != 2 {
		t.Fatalf("ring=%d, want 2", len(ring))
	}
	if ring[0].ID != "ev-2" {
		t.Fatalf("arrival order broken after prune: %q", ring[0].ID)
	}
}

func TestIngestSignalsAreNilUntilRulesLand(t *testing.T) {
	e := New(Options{})
	for i := 0; i < 5; i++ {
		if sigs := e.Ingest(baseEvent(i, "x")); sigs != nil {
			t.Fatalf("contracts slice must not emit signals, got %v", sigs)
		}
	}
}
