// Package evidenceview derives bounded, deterministic observations from redacted
// index summaries. It has no I/O, model, policy, or enforcement capability.
package evidenceview

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/rulecatalog"
)

const (
	// IdleGap is the largest gap that keeps consecutive source events together.
	IdleGap = 30 * time.Minute
	// MinAutomationEvents avoids assessments on tiny samples.
	MinAutomationEvents = 8
	// TimelineLimit caps detail timelines and phase event references.
	TimelineLimit = 200
	// SensorLimit bounds each summary's distinct sensor and kind lists.
	SensorLimit = 64
)

// Cadence describes sorted inter-event gaps; the first event has no gap.
type Cadence struct {
	MinGapMS        float64 `json:"min_gap_ms"`
	MedianGapMS     float64 `json:"median_gap_ms"`
	P90GapMS        float64 `json:"p90_gap_ms"`
	EventsPerMinute float64 `json:"events_per_minute"`
	Regularity      float64 `json:"regularity"`
}

// Observation explains a measured predicate, never a client identity or verdict.
type Observation struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// Automation is an evidence-backed observation, not attribution.
type Automation struct {
	Assessment string        `json:"assessment"`
	Evidence   []Observation `json:"evidence"`
}

// Session is a consecutive retained sequence for one tenant and source key.
type Session struct {
	ID                   string                         `json:"id"`
	Source               string                         `json:"source"`
	FirstSeen            string                         `json:"first_seen"`
	LastSeen             string                         `json:"last_seen"`
	DurationMS           float64                        `json:"duration_ms"`
	EventCount           int                            `json:"event_count"`
	Sensors              []string                       `json:"sensors"`
	SensorKinds          []string                       `json:"sensor_kinds"`
	SensorsTruncated     bool                           `json:"sensors_truncated"`
	ClassificationCounts map[string]int                 `json:"classification_counts"`
	RuleIDs              []string                       `json:"rule_ids"`
	MaxSeverity          string                         `json:"max_severity"`
	Frameworks           []rulecatalog.FrameworkMapping `json:"frameworks"`
	Cadence              Cadence                        `json:"cadence"`
	Automation           Automation                     `json:"automation"`
	// CampaignID references the campaign this session joined, or null.
	CampaignID *string `json:"campaign_id"`
	// Actor is a hedged behavioural assessment with every evaluated signal.
	Actor  Actor                   `json:"actor"`
	Events []evidenceindex.Summary `json:"-"`

	steps          []step
	stepsTruncated bool
	client         string
}

// TimelineEvent carries safe display metadata and an origin for fleet collisions.
type TimelineEvent struct {
	EventID        string   `json:"event_id"`
	NodeID         string   `json:"node_id"`
	Time           string   `json:"time"`
	GapMS          *float64 `json:"gap_ms"`
	Sensor         string   `json:"sensor"`
	Kind           string   `json:"kind"`
	Classification string   `json:"classification"`
	RuleIDs        []string `json:"rule_ids"`
	Summary        string   `json:"summary"`
}

// Phase is a contiguous run of events in one static stage, not inferred intent.
type Phase struct {
	Stage     string   `json:"stage"`
	FirstSeen string   `json:"first_seen"`
	LastSeen  string   `json:"last_seen"`
	EventIDs  []string `json:"event_ids"`
}

// Detail adds the oldest TimelineLimit events and their contiguous stage runs.
type Detail struct {
	Session
	Timeline          []TimelineEvent `json:"timeline"`
	Phases            []Phase         `json:"phases"`
	TimelineTruncated bool            `json:"timeline_truncated"`
}

// Time parses the index's canonical UTC timestamp. The projection always
// writes "2006-01-02T15:04:05.000000000Z"; that exact shape is decoded
// directly, and anything else (including out-of-range fields) takes the
// time.Parse path, whose result, or zero time on error, is returned unchanged.
func Time(e evidenceindex.Summary) time.Time {
	if t, ok := canonicalTime(e.Time); ok {
		return t
	}
	t, _ := time.Parse(time.RFC3339Nano, e.Time)
	return t
}

// canonicalTime decodes the fixed-width projection format exactly as
// time.Parse(time.RFC3339Nano, value) would for valid input.
func canonicalTime(value string) (time.Time, bool) {
	if len(value) != 30 || value[4] != '-' || value[7] != '-' || value[10] != 'T' ||
		value[13] != ':' || value[16] != ':' || value[19] != '.' || value[29] != 'Z' {
		return time.Time{}, false
	}
	number := func(from, to int) (int, bool) {
		n := 0
		for i := from; i < to; i++ {
			c := value[i]
			if c < '0' || c > '9' {
				return 0, false
			}
			n = n*10 + int(c-'0')
		}
		return n, true
	}
	year, ok1 := number(0, 4)
	month, ok2 := number(5, 7)
	day, ok3 := number(8, 10)
	hour, ok4 := number(11, 13)
	minute, ok5 := number(14, 16)
	second, ok6 := number(17, 19)
	nanos, ok7 := number(20, 29)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || !ok7 ||
		month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > 59 {
		return time.Time{}, false
	}
	t := time.Date(year, time.Month(month), day, hour, minute, second, nanos, time.UTC)
	if t.Day() != day { // day beyond the month's length
		return time.Time{}, false
	}
	return t, true
}

// EventKey distinguishes equal IDs arriving from different authenticated origins.
func EventKey(e evidenceindex.Summary) string {
	node := "local"
	if e.Node != nil {
		node = e.Node.ID
	}
	return node + ":" + e.ID
}

// Chronological copies and sorts by native time, then origin and event ID.
func Chronological(events []evidenceindex.Summary) []evidenceindex.Summary {
	out := append([]evidenceindex.Summary{}, events...)
	sort.Slice(out, func(i, j int) bool {
		a, b := Time(out[i]), Time(out[j])
		if !a.Equal(b) {
			return a.Before(b)
		}
		return EventKey(out[i]) < EventKey(out[j])
	})
	return out
}

// Sessions groups all sampled events before applying any display window. IDs
// remain stable while the first retained event remains; eviction can change IDs.
func Sessions(tenant string, events []evidenceindex.Summary) []Session {
	groups := map[string][]evidenceindex.Summary{}
	out := []Session{}
	for _, e := range Chronological(events) {
		if e.Source == "" {
			continue // unknown peers must not be grouped into one actor
		}
		group := groups[e.Source]
		if len(group) > 0 && Time(e).Sub(Time(group[len(group)-1])) > IdleGap {
			out = append(out, summarize(tenant, group))
			group = nil
		}
		groups[e.Source] = append(group, e)
	}
	for _, group := range groups {
		out = append(out, summarize(tenant, group))
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := Time(out[i].Events[len(out[i].Events)-1]), Time(out[j].Events[len(out[j].Events)-1])
		if !a.Equal(b) {
			return a.After(b)
		}
		return out[i].ID < out[j].ID
	})
	assignCampaigns(tenant, out)
	return out
}

func summarize(tenant string, events []evidenceindex.Summary) Session {
	first, last := events[0], events[len(events)-1]
	identity, _ := json.Marshal([]string{tenant, first.Source, EventKey(first)})
	digest := sha256.Sum256(identity)
	s := Session{
		ID:                   hex.EncodeToString(digest[:16]),
		Source:               first.Source,
		FirstSeen:            first.Time,
		LastSeen:             last.Time,
		DurationMS:           float64(Time(last).Sub(Time(first))) / float64(time.Millisecond),
		EventCount:           len(events),
		Sensors:              []string{},
		SensorKinds:          []string{},
		ClassificationCounts: map[string]int{},
		RuleIDs:              []string{},
		Frameworks:           []rulecatalog.FrameworkMapping{},
		Events:               events,
	}
	sensors, kinds, rules := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, e := range events {
		sensors[e.Sensor.ID], kinds[e.Sensor.Kind] = true, true
		s.ClassificationCounts[e.Classification]++
		for _, id := range e.RuleIDs {
			rules[id] = true
		}
		if evidenceindex.Rank(e.Severity) > evidenceindex.Rank(s.MaxSeverity) {
			s.MaxSeverity = e.Severity
		}
	}
	s.Sensors, s.SensorKinds, s.RuleIDs = keys(sensors), keys(kinds), keys(rules)
	s.SensorsTruncated = len(s.Sensors) > SensorLimit || len(s.SensorKinds) > SensorLimit
	s.Sensors = s.Sensors[:min(len(s.Sensors), SensorLimit)]
	s.SensorKinds = s.SensorKinds[:min(len(s.SensorKinds), SensorLimit)]
	s.Frameworks = Mappings(s.RuleIDs)
	s.Cadence = cadence(events)
	s.Automation = automation(events, rules)
	items := interactions(events)
	s.steps, s.stepsTruncated = collapse(items)
	s.client = singleClient(items)
	s.Actor = assessActor(items, rules)
	return s
}

// singleClient returns the one client family shared by every HTTP interaction
// that reported one, or "" when none reported or families differ.
func singleClient(items []interaction) string {
	family := ""
	for _, item := range items {
		if item.client == "" {
			continue
		}
		if family != "" && family != item.client {
			return ""
		}
		family = item.client
	}
	return family
}

func keys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// Mappings returns unique sorted catalog references for known rule IDs only.
func Mappings(ids []string) []rulecatalog.FrameworkMapping {
	seen := map[string]rulecatalog.FrameworkMapping{}
	for _, id := range ids {
		if rule, ok := rulecatalog.Lookup(id); ok {
			for _, mapping := range rule.Frameworks {
				seen[mapping.Framework+":"+mapping.ID] = mapping
			}
		}
	}
	out := make([]rulecatalog.FrameworkMapping, 0, len(seen))
	for _, mapping := range seen {
		out = append(out, mapping)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Framework+out[i].ID < out[j].Framework+out[j].ID
	})
	return out
}

func cadence(events []evidenceindex.Summary) Cadence {
	c := Cadence{}
	if len(events) < 2 {
		return c
	}
	gaps := make([]float64, 0, len(events)-1)
	for i := 1; i < len(events); i++ {
		gaps = append(gaps, float64(Time(events[i]).Sub(Time(events[i-1])))/float64(time.Millisecond))
	}
	sort.Float64s(gaps)
	c.MinGapMS, c.MedianGapMS = gaps[0], gaps[len(gaps)/2]
	c.P90GapMS = gaps[int(math.Ceil(.9*float64(len(gaps))))-1]
	regular := 0
	for _, gap := range gaps {
		if math.Abs(gap-c.MedianGapMS) <= c.MedianGapMS/4 {
			regular++
		}
	}
	c.Regularity = float64(regular) / float64(len(gaps))
	duration := Time(events[len(events)-1]).Sub(Time(events[0])).Minutes()
	if duration > 0 {
		c.EventsPerMinute = float64(len(events)-1) / duration
	}
	return c
}

func automation(events []evidenceindex.Summary, rules map[string]bool) Automation {
	a := Automation{Assessment: "inconclusive", Evidence: []Observation{}}
	// Timing uses actual interactions only. Appended signals have artificial
	// near-zero gaps and must not manufacture timing evidence.
	interactions := []evidenceindex.Summary{}
	for _, e := range events {
		if e.Classification != "correlation_signal" {
			interactions = append(interactions, e)
		}
	}
	c := cadence(interactions)
	if len(interactions) >= MinAutomationEvents && c.MedianGapMS < 1000 {
		a.Evidence = append(a.Evidence, Observation{"sub_second_cadence", "Median interaction gap below 1000 ms; timestamps alone do not establish reactions or intent."})
	}
	if len(interactions) >= MinAutomationEvents && c.MedianGapMS >= 1000 && c.MedianGapMS <= 30000 && c.Regularity >= float64(len(interactions)-2)/float64(len(interactions)-1) {
		a.Evidence = append(a.Evidence, Observation{"regular_cadence", "Median interaction gap at most 30 s, with at most one gap outside 25% of the median."})
	}
	for _, predicate := range []struct{ id, code, detail string }{
		{"AGT-001", "agent_canary", "AGT-001 observed an instruction marker from decoy content; this does not prove an LLM client."},
		{"COR-005", "correlation_cadence", "COR-005 fired in the retained sequence."},
		{"COR-006", "multi_surface_enumeration", "COR-006 observed multiple AI surface families."},
		{"HT-001", "honeytoken_replay", "HT-001 observed an operator-owned decoy credential marker inbound."},
		{"COR-008", "cross_sensor_replay", "COR-008 linked a decoy credential observation to earlier contact on another sensor."},
	} {
		if rules[predicate.id] {
			a.Evidence = append(a.Evidence, Observation{predicate.code, predicate.detail})
		}
	}
	if len(interactions) < MinAutomationEvents {
		a.Evidence = append(a.Evidence, Observation{"insufficient_events", fmt.Sprintf("At least %d non-signal events are required; retained %d.", MinAutomationEvents, len(interactions))})
		return a
	}
	a.Assessment = "mixed"
	if len(a.Evidence) > 0 {
		a.Assessment = "consistent_with_automation"
	}
	return a
}

// SessionDetail segments the capped timeline using rule/kind stage precedence.
func SessionDetail(s Session) Detail {
	d := Detail{Session: s, Timeline: []TimelineEvent{}, Phases: []Phase{}, TimelineTruncated: len(s.Events) > TimelineLimit}
	for i, e := range s.Events[:min(len(s.Events), TimelineLimit)] {
		node := "local"
		if e.Node != nil {
			node = e.Node.ID
		}
		var gap *float64
		if i > 0 {
			value := float64(Time(e).Sub(Time(s.Events[i-1]))) / float64(time.Millisecond)
			gap = &value
		}
		d.Timeline = append(d.Timeline, TimelineEvent{e.ID, node, e.Time, gap, e.Sensor.ID, e.Sensor.Kind, e.Classification, e.RuleIDs, e.Summary})
		stage := eventStage(e)
		if len(d.Phases) == 0 || d.Phases[len(d.Phases)-1].Stage != stage {
			d.Phases = append(d.Phases, Phase{Stage: stage, FirstSeen: e.Time, EventIDs: []string{}})
		}
		phase := &d.Phases[len(d.Phases)-1]
		phase.LastSeen = e.Time
		phase.EventIDs = append(phase.EventIDs, e.ID)
	}
	return d
}

func eventStage(e evidenceindex.Summary) string {
	has := func(ids ...string) bool {
		for _, id := range ids {
			for _, rule := range e.RuleIDs {
				if id == rule {
					return true
				}
			}
		}
		return false
	}
	switch {
	case has("HT-001", "COR-008"):
		return "decoy_credential_replay"
	case has("LLM-002", "LLM-003", "AGT-001", "PI-001", "PI-002", "ESC-001"):
		return "ai_service_abuse"
	case has("EXF-001", "LLM-004", "COR-007") || e.Sensor.Kind == "ssh":
		return "credential_access"
	default:
		return "discovery"
	}
}
