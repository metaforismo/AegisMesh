package evidenceview

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

func sample(i int, offset time.Duration) evidenceindex.Summary {
	return evidenceindex.Summary{
		ID: fmt.Sprintf("%032x", i+1), Time: time.Unix(1000, 0).Add(offset).UTC().Format(time.RFC3339Nano),
		Source: "192.0.2.1", Sensor: event.SensorRef{ID: "web", Kind: "http"},
		Classification: "interaction", RuleIDs: []string{},
	}
}

func TestSessionIdleBoundaryIdentityAndOrder(t *testing.T) {
	events := []evidenceindex.Summary{sample(0, 0), sample(1, IdleGap), sample(2, 2*IdleGap+time.Nanosecond)}
	sessions := Sessions("a", events)
	if len(sessions) != 2 || sessions[1].EventCount != 2 || sessions[0].EventCount != 1 {
		t.Fatalf("wrong idle split: %+v", sessions)
	}
	if sessions[1].DurationMS != 1800000 || sessions[1].ID == Sessions("b", events)[1].ID {
		t.Fatal("duration or tenant identity")
	}
	events[0], events[2] = events[2], events[0]
	if !reflect.DeepEqual(sessions, Sessions("a", events)) {
		t.Fatal("input order changed projection")
	}
	unknown := sample(5, 0)
	unknown.Source = ""
	if len(Sessions("a", []evidenceindex.Summary{unknown})) != 0 {
		t.Fatal("unknown sources grouped")
	}
}

func TestAutomationObservations(t *testing.T) {
	for _, tc := range []struct {
		name       string
		count      int
		gap        time.Duration
		rules      []string
		assessment string
		code       string
	}{
		{"few", 7, time.Millisecond, []string{"AGT-001"}, "inconclusive", "insufficient_events"},
		{"fast", 8, 500 * time.Millisecond, nil, "consistent_with_automation", "sub_second_cadence"},
		{"regular", 8, 30 * time.Second, nil, "consistent_with_automation", "regular_cadence"},
		{"slow", 8, 31 * time.Second, nil, "mixed", ""},
		{"signal", 8, 31 * time.Second, []string{"AGT-001", "COR-005", "COR-006", "HT-001", "COR-008"}, "consistent_with_automation", "honeytoken_replay"},
		{"ties", 8, 0, nil, "consistent_with_automation", "sub_second_cadence"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := []evidenceindex.Summary{}
			for i := 0; i < tc.count; i++ {
				e := sample(i, time.Duration(i)*tc.gap)
				e.RuleIDs = tc.rules
				events = append(events, e)
			}
			s := Sessions("one", events)[0]
			if s.Automation.Assessment != tc.assessment || s.Cadence.Regularity < 0 || s.Cadence.Regularity > 1 {
				t.Fatalf("%+v", s.Automation)
			}
			if tc.code != "" {
				found := false
				for _, e := range s.Automation.Evidence {
					found = found || e.Code == tc.code
				}
				if !found {
					t.Fatalf("missing evidence %s", tc.code)
				}
			}
		})
	}
}

func TestSignalsDoNotManufactureTimingEvidence(t *testing.T) {
	events := []evidenceindex.Summary{sample(0, 0)}
	for i := 1; i < 10; i++ {
		e := sample(i, time.Duration(i)*time.Millisecond)
		e.Classification = "correlation_signal"
		events = append(events, e)
	}
	s := Sessions("one", events)[0]
	if s.Automation.Assessment != "inconclusive" || len(s.Automation.Evidence) != 1 {
		t.Fatal(s.Automation)
	}
}

func TestCadenceFormula(t *testing.T) {
	events := []evidenceindex.Summary{sample(0, 0), sample(1, time.Second), sample(2, 3*time.Second), sample(3, 6*time.Second), sample(4, 8*time.Second)}
	c := Sessions("one", events)[0].Cadence
	if c.MinGapMS != 1000 || c.MedianGapMS != 2000 || c.P90GapMS != 3000 || c.Regularity != .5 || c.EventsPerMinute != 30 {
		t.Fatal(c)
	}
}

func TestDetailCapsAndPhases(t *testing.T) {
	events := []evidenceindex.Summary{}
	for i := 0; i < TimelineLimit+1; i++ {
		e := sample(i, time.Duration(i)*time.Second)
		e.RuleIDs = [][]string{{"LLM-001"}, {"EXF-001"}, {"LLM-002"}, {"HT-001"}}[i%4]
		events = append(events, e)
	}
	d := SessionDetail(Sessions("one", events)[0])
	if !d.TimelineTruncated || len(d.Timeline) != TimelineLimit || len(d.Phases) != TimelineLimit || d.Timeline[0].GapMS != nil || *d.Timeline[1].GapMS != 1000 {
		t.Fatal("detail bounds or gaps")
	}
	for i, stage := range []string{"discovery", "credential_access", "ai_service_abuse", "decoy_credential_replay"} {
		if d.Phases[i].Stage != stage || len(d.Phases[i].EventIDs) != 1 {
			t.Fatal(d.Phases[i])
		}
	}
	body, _ := json.Marshal(d)
	if len(body) == 0 || len(d.Frameworks) == 0 || len(d.RuleIDs) != 4 {
		t.Fatal("missing framework or rule aggregation")
	}
}

func TestCoverageDeduplicatesPerTechniquePerEvent(t *testing.T) {
	e := sample(0, 0)
	e.RuleIDs = []string{"HT-001", "LLM-004", "COR-008"}
	frameworks := Coverage([]evidenceindex.Summary{e, sample(1, -time.Hour)}, Time(e).Add(-time.Minute), Time(e))
	if len(frameworks) != 3 {
		t.Fatal(frameworks)
	}
	found, unobserved := false, false
	for _, framework := range frameworks {
		for _, technique := range framework.Techniques {
			if technique.ID == "T1078" {
				found = true
				if technique.ObservedEventCount != 1 || technique.LastSeen != e.Time || len(technique.RuleIDs) < 3 {
					t.Fatal(technique)
				}
			}
			if technique.ObservedEventCount == 0 && technique.LastSeen == "" {
				unobserved = true
			}
		}
	}
	if !found || !unobserved {
		t.Fatal("missing mapped/unobserved techniques")
	}
}
