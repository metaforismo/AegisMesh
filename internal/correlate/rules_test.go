package correlate

import (
	"reflect"
	"testing"
	"time"
)

var base = time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

func ev(n int, key string, mutate func(*Event)) Event {
	e := Event{
		ID:             "ev-" + intStr(n),
		Time:           base.Add(time.Duration(n) * time.Second),
		SourceKey:      key,
		SensorID:       "sensor-" + intStr(n%3),
		SensorKind:     "http",
		Classification: "interaction",
	}
	if mutate != nil {
		mutate(&e)
	}
	return e
}

func withPI(x *Event) {
	x.FindingIDs = []string{"PI-001"}
}

func TestRepeatedInjectionFiresAtThresholdThenCoolsDown(t *testing.T) {
	e := New(Options{Window: time.Minute})
	var got []Signal
	for i := 0; i < 3; i++ {
		got = append(got, e.Ingest(ev(i, "src", withPI))...)
	}
	if len(got) != 1 || got[0].RuleID != RuleRepeatedInjection {
		t.Fatalf("expected exactly one COR-001 on the third finding: %+v", got)
	}
	if ids := got[0].SourceEventIDs; !reflect.DeepEqual(ids, []string{"ev-0", "ev-1", "ev-2"}) {
		t.Fatalf("provenance wrong: %v", ids)
	}
	// Fourth finding inside the window stays silent (cooldown).
	if sigs := e.Ingest(ev(3, "src", withPI)); len(sigs) != 0 {
		t.Fatalf("cooldown violated: %+v", sigs)
	}

	// Beyond the window the ring has been pruned clean, so re-arming takes a
	// fresh threshold's worth of findings — deterministic and documented.
	e.Ingest(ev(130, "src", withPI))
	e.Ingest(ev(131, "src", withPI))
	sigs := e.Ingest(ev(132, "src", withPI)) // 130..132s all past the old fire
	if len(sigs) != 1 || sigs[0].RuleID != RuleRepeatedInjection {
		t.Fatalf("re-arm after cooldown failed: %+v", sigs)
	}
	if !sigs[0].Time.After(got[0].Time.Add(time.Minute)) {
		t.Fatalf("second fire must be outside the original cooldown: %v vs %v", got[0].Time, sigs[0].Time)
	}
}

func TestProtocolHoppingNeedsThreeKinds(t *testing.T) {
	e := New(Options{Window: time.Minute})
	kinds := []string{"http", "tcp"}
	for i, k := range kinds {
		e.Ingest(ev(i, "src", func(x *Event) { x.SensorKind = k }))
	}
	if sigs := e.Ingest(ev(9, "src", func(x *Event) { x.SensorKind = "" })); len(sigs) != 0 {
		t.Fatalf("two kinds and an empty kind must not fire: %+v", sigs)
	}
	sigs := e.Ingest(ev(10, "src", func(x *Event) { x.SensorKind = "mcp" }))
	if len(sigs) != 1 || sigs[0].RuleID != RuleProtocolHopping || len(sigs[0].SourceEventIDs) != 3 {
		t.Fatalf("third kind must fire with per-kind provenance: %+v", sigs)
	}
}

func TestToolProbingCountsDistinctToolsOnly(t *testing.T) {
	e := New(Options{Window: time.Minute})
	mk := func(i int) func(*Event) {
		return func(x *Event) {
			x.SensorKind = "mcp"
			x.Classification = "canary_invocation"
			x.ToolName = "tool-" + intStr(i)
		}
	}
	for i := 0; i < 3; i++ {
		e.Ingest(ev(i, "src", mk(i)))
	}
	e.Ingest(ev(3, "src", mk(2))) // duplicate tool: no progress
	if sigs := e.Ingest(ev(4, "src", mk(2))); len(sigs) != 0 {
		t.Fatalf("duplicate tools must not fire: %+v", sigs)
	}
	sigs := e.Ingest(ev(5, "src", mk(9)))
	if len(sigs) != 1 || sigs[0].RuleID != RuleToolProbing || len(sigs[0].SourceEventIDs) != 4 {
		t.Fatalf("fourth distinct tool must fire: %+v", sigs)
	}
}

func TestSustainedReconRequiresTwoKinds(t *testing.T) {
	e := New(Options{Window: time.Minute})
	for i := 0; i < 6; i++ {
		e.Ingest(ev(i, "src", nil)) // all http
	}
	if got := e.Stats().FiredSignals; got != 0 {
		t.Fatalf("single-kind recon must stay quiet: %d", got)
	}
	sigs := e.Ingest(ev(10, "src", func(x *Event) { x.SensorKind = "tcp" }))
	if len(sigs) != 1 || sigs[0].RuleID != RuleSustainedRecon {
		t.Fatalf("cross-kind volume must fire: %+v", sigs)
	}
}

func TestMultipleRulesFireInFixedOrder(t *testing.T) {
	e := New(Options{Window: time.Minute, InjectionThreshold: 2, ReconThreshold: 2})
	// One source: two PI findings across two kinds completes three rules'
	// preconditions at once except protocol hopping (needs a third kind).
	var batch []Signal
	batch = append(batch, e.Ingest(ev(0, "src", func(x *Event) { withPI(x); x.SensorKind = "http" }))...)
	batch = append(batch, e.Ingest(ev(1, "src", func(x *Event) { withPI(x); x.SensorKind = "tcp" }))...)
	var ids []RuleID
	for _, s := range batch {
		ids = append(ids, s.RuleID)
	}
	want := []RuleID{RuleRepeatedInjection, RuleSustainedRecon} // enum order, not map luck
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("same-batch signal order = %v, want %v", ids, want)
	}

	// Third kind arrives afterwards: hopping alone (others cooling down).
	sigs := e.Ingest(ev(2, "src", func(x *Event) { x.SensorKind = "mcp" }))
	if len(sigs) != 1 || sigs[0].RuleID != RuleProtocolHopping {
		t.Fatalf("expected only COR-002: %+v", sigs)
	}
}

func TestDeterministicReplay(t *testing.T) {
	buildStream := func() []Event {
		out := []Event{}
		for i := 0; i < 4; i++ {
			out = append(out, ev(i, "a", withPI))
		}
		for i := 10; i < 16; i++ {
			out = append(out, ev(i, "b", func(x *Event) { x.SensorKind = "tcp" }))
			out = append(out, ev(i+1, "b", nil))
		}
		return out
	}
	run := func() [][]Signal {
		e := New(Options{Window: time.Minute})
		var all [][]Signal
		for _, evx := range buildStream() {
			all = append(all, e.Ingest(evx))
		}
		return all
	}
	a, b := run(), run()
	if !reflect.DeepEqual(a, b) {
		t.Fatal("same input sequence produced different signals")
	}
	if len(a) == 0 {
		t.Fatal("stream should have produced signals somewhere")
	}
}

func TestLateArrivalWithinWindowStillCounts(t *testing.T) {
	e := New(Options{Window: time.Minute, InjectionThreshold: 3})
	// t=0 and t=50s arrive normally...
	e.Ingest(ev(0, "s", withPI))
	e.Ingest(ev(50, "s", withPI))
	// ...then a delayed t=25s event arrives (out of order but in window).
	late := ev(25, "s", withPI)
	if sigs := e.Ingest(late); len(sigs) != 1 {
		t.Fatalf("late-but-in-window arrival must complete the threshold: %+v", sigs)
	}

}

func TestEvictionForgetsCooldownDocumentedTradeoff(t *testing.T) {
	e := New(Options{Window: time.Hour, MaxSources: 2, InjectionThreshold: 2})
	e.Ingest(ev(0, "target", withPI))
	e.Ingest(ev(1, "target", withPI)) // fires once
	// Flood with new sources to evict "target" (oldest first-seen).
	for i := 100; i < 104; i++ {
		e.Ingest(ev(i, "noise-"+intStr(i), nil))
	}
	// Target returns; its cooldown was forgotten along with its ring.
	e.Ingest(ev(200, "target", withPI))
	if sigs := e.Ingest(ev(201, "target", withPI)); len(sigs) == 0 {
		t.Log("cooldown retained despite eviction — stronger than documented")
	}
	// Either behavior is acceptable here; the invariant is bounded memory.
	if got := e.Stats().SourcesTracked; got > 2 {
		t.Fatalf("source bound violated: %d", got)
	}
}

func TestStatsReflectSignalAccounting(t *testing.T) {
	e := New(Options{Window: time.Minute})
	for i := 0; i < 3; i++ {
		e.Ingest(ev(i, "s", withPI))
	}
	if got := e.Stats().FiredSignals; got != 1 {
		t.Fatalf("fired=%d, want 1", got)
	}
}
