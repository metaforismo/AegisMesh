package correlate

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/detect"
)

func containsSignal(signals []Signal, id RuleID) bool {
	for _, s := range signals {
		if s.RuleID == id {
			return true
		}
	}
	return false
}
func TestNewCorrelations(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	eventAt := func(i int) Event {
		return Event{ID: fmt.Sprint(i), SourceKey: "source", Time: base.Add(time.Duration(i) * 10 * time.Second), SensorID: "http-one", SensorKind: "http"}
	}
	for _, tc := range []struct {
		name   string
		rule   RuleID
		events []Event
		fire   bool
	}{
		{"multi-family", RuleAIEnumeration, []Event{func() Event { e := eventAt(0); e.AIFamily = detect.FamilyOllama; return e }(), func() Event { e := eventAt(1); e.AIFamily = detect.FamilyOpenAI; return e }()}, true},
		{"same family", RuleAIEnumeration, []Event{func() Event { e := eventAt(0); e.AIFamily = detect.FamilyOpenAI; return e }(), func() Event { e := eventAt(1); e.AIFamily = detect.FamilyOpenAI; return e }()}, false},
		{"cross sensor replay", RuleCredentialReplay, []Event{eventAt(0), func() Event {
			e := eventAt(1)
			e.SensorID = "ssh-one"
			e.SensorKind = "ssh"
			e.FindingIDs = []string{"HT-001"}
			return e
		}()}, true},
		{"same sensor replay", RuleCredentialReplay, []Event{eventAt(0), func() Event { e := eventAt(1); e.FindingIDs = []string{"HT-001"}; return e }()}, false},
		{"other source", RuleCredentialReplay, []Event{eventAt(0), func() Event {
			e := eventAt(1)
			e.SourceKey = "other"
			e.SensorID = "ssh-one"
			e.FindingIDs = []string{"HT-001"}
			return e
		}()}, false},
		{"future event excluded", RuleAIEnumeration, []Event{func() Event { e := eventAt(5); e.AIFamily = detect.FamilyOllama; return e }(), func() Event { e := eventAt(1); e.AIFamily = detect.FamilyOpenAI; return e }()}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := New(Options{})
			var got []Signal
			for _, ev := range tc.events {
				got = append(got, engine.Ingest(ev)...)
			}
			if containsSignal(got, tc.rule) != tc.fire {
				t.Fatal(got)
			}
		})
	}
	for _, tc := range []struct {
		name    string
		offsets []int
		fire    bool
	}{
		{"regular", []int{0, 10, 20, 30, 40, 50, 60, 70}, true},
		{"single outlier", []int{0, 10, 20, 30, 70, 80, 90, 100}, true},
		{"two outliers", []int{0, 10, 20, 60, 100, 110, 120, 130}, false},
		{"irregular", []int{0, 2, 5, 13, 29, 58, 115, 229}, false},
		{"slow", []int{0, 40, 80, 120, 160, 200, 240, 280}, false},
		{"simultaneous", []int{0, 0, 0, 0, 0, 0, 0, 0}, true},
		{"too few", []int{0, 10, 20, 30, 40, 50, 60}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := New(Options{})
			var got []Signal
			for i, offset := range tc.offsets {
				ev := eventAt(i)
				ev.Time = base.Add(time.Duration(offset) * time.Second)
				got = append(got, engine.Ingest(ev)...)
			}
			if containsSignal(got, RuleAutomationCadence) != tc.fire {
				t.Fatal(got)
			}
		})
	}
	for _, distinct := range []bool{true, false} {
		t.Run(fmt.Sprintf("distinct=%v", distinct), func(t *testing.T) {
			engine := New(Options{})
			var got []Signal
			for i := 0; i < 8; i++ {
				ev := eventAt(i)
				digest := "same"
				if distinct {
					digest = fmt.Sprint(i)
				}
				ev.AuthAttempts = []string{digest, digest}
				got = append(got, engine.Ingest(ev)...)
			}
			if containsSignal(got, RuleCredentialStuffing) != distinct {
				t.Fatal(got)
			}
		})
	}
}

func TestNewCorrelationBoundsDisableAndDeterminism(t *testing.T) {
	for _, opts := range []Options{{AutomationThreshold: 3}, {CredentialThreshold: 2}, {AutomationThreshold: 65, PerSourceEvents: 64}, {CredentialThreshold: -1}} {
		if opts.Validate() == nil {
			t.Fatal("invalid threshold accepted")
		}
	}
	want := []string{"COR-001", "COR-002", "COR-003", "COR-004", "COR-005", "COR-006", "COR-007", "COR-008"}
	if !reflect.DeepEqual(KnownRuleIDs(), want) {
		t.Fatal(KnownRuleIDs())
	}
	makeSequence := func(engine *Engine) []Signal {
		var out []Signal
		for i := 0; i < 20; i++ {
			family := detect.FamilyOllama
			if i%2 == 1 {
				family = detect.FamilyOpenAI
			}
			out = append(out, engine.Ingest(Event{ID: fmt.Sprint(i), Time: time.Unix(int64(i*10), 0), SourceKey: "one", SensorID: fmt.Sprint(i % 2), SensorKind: "http", AIFamily: family, FindingIDs: []string{"HT-001"}, AuthAttempts: []string{fmt.Sprint(i)}})...)
		}
		return out
	}
	a, b := makeSequence(New(Options{})), makeSequence(New(Options{}))
	if !reflect.DeepEqual(a, b) {
		t.Fatal("replay differs")
	}
	disabled := []RuleID{RuleAutomationCadence, RuleAIEnumeration, RuleCredentialStuffing, RuleCredentialReplay}
	for _, s := range makeSequence(New(Options{DisabledRules: disabled})) {
		for _, id := range disabled {
			if s.RuleID == id {
				t.Fatal("disabled signal")
			}
		}
	}
	// Ring and source caps still bound new-rule state.
	engine := New(Options{PerSourceEvents: 8, MaxSources: 1})
	makeSequence(engine)
	engine.Ingest(Event{SourceKey: "other", Time: time.Unix(200, 0)})
	if engine.Stats().SourcesTracked != 1 || engine.Stats().TrimmedEvents == 0 || engine.Stats().EvictedSources != 1 {
		t.Fatal(engine.Stats())
	}
}
