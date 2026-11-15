package evidenceindex

import (
	"sort"
	"time"
)

// SourceSummary aggregates retained observations for one stored source value.
type SourceSummary struct {
	// Source is the stored source value.
	Source string `json:"source"`
	// Events counts matching observations within the window.
	Events int `json:"events"`
	// FirstSeen is the earliest matching timestamp.
	FirstSeen string `json:"first_seen"`
	// LastSeen is the latest matching timestamp.
	LastSeen string `json:"last_seen"`
	// Sensors lists unique sensor ids.
	Sensors []string `json:"sensors"`
	// Kinds lists unique sensor protocols.
	Kinds []string `json:"kinds"`
	// CanaryInvocations counts canary-invocation observations.
	CanaryInvocations int `json:"canary_invocations"`
	// Signals counts correlation signals.
	Signals int `json:"signals"`
	// MaxSeverity is the highest observed catalog severity.
	MaxSeverity string `json:"max_severity"`
}

// Totals counts observation classifications, sources, and sensors for a time window.
type Totals struct {
	// Events counts all observations in the window.
	Events int `json:"events"`
	// Interaction counts interaction observations.
	Interaction int `json:"interaction"`
	// CanaryInvocation counts canary-invocation observations.
	CanaryInvocation int `json:"canary_invocation"`
	// CorrelationSignal counts correlation signals.
	CorrelationSignal int `json:"correlation_signal"`
	// Sources counts distinct nonempty source values.
	Sources int `json:"sources"`
	// SensorsActive counts sensors represented in the window.
	SensorsActive int `json:"sensors_active"`
}

// Bucket holds classification counts for one fixed time interval.
type Bucket struct {
	// Start is the UTC beginning of the bucket.
	Start string `json:"start"`
	// Interaction counts interaction observations.
	Interaction int `json:"interaction"`
	// CanaryInvocation counts canary-invocation observations.
	CanaryInvocation int `json:"canary_invocation"`
	// CorrelationSignal counts correlation signals.
	CorrelationSignal int `json:"correlation_signal"`
}

// SensorCount counts retained observations for one sensor.
type SensorCount struct {
	// Buckets has the same classification shape and boundaries as the main series.
	Buckets []Bucket `json:"buckets"`
	// SensorID is the configured sensor identifier.
	SensorID string `json:"sensor_id"`
	// Kind is its sensor protocol.
	Kind string `json:"kind"`
	// Events counts retained observations in the window.
	Events int `json:"events"`
}

// RuleCount counts retained observations associated with one catalog rule.
type RuleCount struct {
	// RuleID is the catalog rule identifier.
	RuleID string `json:"rule_id"`
	// Events counts observations referencing the rule.
	Events int `json:"events"`
	// Severity records the associated observation severity.
	Severity string `json:"severity"`
}

// NodeCount counts window observations from an authenticated origin.
type NodeCount struct {
	// ID is the cryptographic node ID, or local.
	ID string `json:"id"`
	// Name is the current enrolled node name.
	Name string `json:"name"`
	// Events counts indexed window observations.
	Events int `json:"events"`
}

// Overview combines bounded window aggregates and recent correlation signals.
type Overview struct {
	// ByNode is added by accepting hubs and absent on single-node consoles.
	ByNode *[]NodeCount `json:"by_node,omitempty"`
	// Window is the selected window label.
	Window string `json:"window"`
	// GeneratedAt is the UTC aggregation time.
	GeneratedAt string `json:"generated_at"`
	// Totals counts observations in the current window.
	Totals Totals `json:"totals"`
	// PreviousTotals counts the preceding equal-length window.
	PreviousTotals Totals `json:"previous_totals"`
	// Buckets contains fixed-duration classification counts.
	Buckets []Bucket `json:"buckets"`
	// BySensor counts current-window observations by sensor.
	BySensor []SensorCount `json:"by_sensor"`
	// BySeverity counts current-window observations by severity.
	BySeverity map[string]int `json:"by_severity"`
	// TopRules ranks associated rules by count with stable id tie-breaking.
	TopRules []RuleCount `json:"top_rules"`
	// TopSources contains at most ten sources ranked by activity.
	TopSources []SourceSummary `json:"top_sources"`
	// RecentSignals contains at most ten recent correlation signals.
	RecentSignals []Summary `json:"recent_signals"`
	// OpenInvestigations counts annotations whose status is not closed.
	OpenInvestigations int `json:"open_investigations"`
}

// Window validates a supported window and returns its duration and bucket count.
func Window(window string) (time.Duration, int, error) {
	switch window {
	case "1h":
		return time.Hour, 60, nil
	case "", "24h":
		return 24 * time.Hour, 48, nil
	case "7d":
		return 7 * 24 * time.Hour, 56, nil
	}

	return 0, 0, ErrQuery
}

func inWindow(summary Summary, from, to time.Time) bool {
	timestamp, err := time.Parse(time.RFC3339Nano, summary.Time)
	return err == nil && !timestamp.Before(from) && timestamp.Before(to)
}

// Sources aggregates observations in the half-open time window and sorts by activity.
func Sources(summaries []Summary, from, to time.Time) []SourceSummary {
	counts := sourceCounts{}
	for _, summary := range summaries {
		if inWindow(summary, from, to) {
			counts.add(summary)
		}
	}
	return counts.sorted()
}

type sourceCounts map[string]*SourceSummary

func (counts sourceCounts) add(summary Summary) {
	if summary.Source == "" {
		return
	}
	source := counts[summary.Source]
	if source == nil {
		source = &SourceSummary{
			Source:    summary.Source,
			FirstSeen: summary.Time,
			LastSeen:  summary.Time,
			Sensors:   []string{},
			Kinds:     []string{},
		}
		counts[summary.Source] = source
	}
	source.Events++
	if summary.Time < source.FirstSeen {
		source.FirstSeen = summary.Time
	}
	if summary.Time > source.LastSeen {
		source.LastSeen = summary.Time
	}
	source.Sensors = unique(source.Sensors, summary.Sensor.ID)
	source.Kinds = unique(source.Kinds, summary.Sensor.Kind)
	if summary.Classification == "canary_invocation" {
		source.CanaryInvocations++
	}
	if summary.Classification == "correlation_signal" {
		source.Signals++
	}
	if Rank(summary.Severity) > Rank(source.MaxSeverity) {
		source.MaxSeverity = summary.Severity
	}
}

func (counts sourceCounts) sorted() []SourceSummary {
	out := make([]SourceSummary, 0, len(counts))
	for _, source := range counts {
		sort.Strings(source.Sensors)
		sort.Strings(source.Kinds)
		out = append(out, *source)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Events != out[j].Events {
			return out[i].Events > out[j].Events
		}
		return out[i].Source < out[j].Source
	})
	return out
}

func unique(values []string, source string) []string {
	for _, value := range values {
		if source == value {
			return values
		}
	}

	return append(values, source)
}

type totalCounts struct {
	counts  Totals
	sources map[string]bool
	sensors map[string]bool
}

func newTotalCounts() totalCounts {
	return totalCounts{sources: map[string]bool{}, sensors: map[string]bool{}}
}

func (counts *totalCounts) add(summary Summary) {
	counts.counts.Events++
	switch summary.Classification {
	case "interaction":
		counts.counts.Interaction++
	case "canary_invocation":
		counts.counts.CanaryInvocation++
	case "correlation_signal":
		counts.counts.CorrelationSignal++
	}
	if summary.Source != "" {
		counts.sources[summary.Source] = true
	}
	counts.sensors[summary.Sensor.ID] = true
}

func (counts totalCounts) totals() Totals {
	counts.counts.Sources = len(counts.sources)
	counts.counts.SensorsActive = len(counts.sensors)
	return counts.counts
}

// Overview aggregates retained evidence for the selected window and preceding comparison window.
func (index *Index) Overview(window string, now time.Time) (Overview, error) {
	duration, bucketCount, err := Window(window)
	if err != nil {
		return Overview{}, err
	}

	if window == "" {
		window = "24h"
	}

	from := now.Add(-duration)
	items := index.snapshot(from.Add(-duration), now, "")
	current, previous := newTotalCounts(), newTotalCounts()
	sources := sourceCounts{}
	overview := Overview{
		Window:      window,
		GeneratedAt: now.UTC().Format(time.RFC3339Nano),
		Buckets:     make([]Bucket, bucketCount),
		BySensor:    []SensorCount{},
		BySeverity: map[string]int{
			"critical": 0,
			"high":     0,
			"medium":   0,
			"low":      0,
			"info":     0,
			"none":     0,
		},
		TopRules:      []RuleCount{},
		TopSources:    []SourceSummary{},
		RecentSignals: []Summary{},
	}

	step := duration / time.Duration(bucketCount)
	for i := range overview.Buckets {
		overview.Buckets[i].Start = from.Add(time.Duration(i) * step).UTC().Format(time.RFC3339Nano)
	}

	sensors := map[string]SensorCount{}
	rules := map[string]RuleCount{}
	for _, item := range items {
		summary, timestamp := item.summary, item.envelope.Time
		if timestamp.Before(from) {
			previous.add(summary)
			continue
		}
		current.add(summary)
		sources.add(summary)
		bucket := &overview.Buckets[min(bucketCount-1, int(timestamp.Sub(from)/step))]
		switch summary.Classification {
		case "interaction":
			bucket.Interaction++
		case "canary_invocation":
			bucket.CanaryInvocation++
		case "correlation_signal":
			bucket.CorrelationSignal++
			if len(overview.RecentSignals) < 10 {
				overview.RecentSignals = append(overview.RecentSignals, index.resolved(summary))
			}
		}
		severity := summary.Severity
		if Rank(severity) == 0 {
			severity = "none"
		}
		overview.BySeverity[severity]++
		sensorCount, exists := sensors[summary.Sensor.ID]
		if exists || len(sensors) < 64 {
			if !exists {
				sensorCount.Buckets = make([]Bucket, len(overview.Buckets))
				for i, bucket := range overview.Buckets {
					sensorCount.Buckets[i].Start = bucket.Start
				}
			}
			sensorBucket := &sensorCount.Buckets[min(bucketCount-1, int(timestamp.Sub(from)/step))]
			switch summary.Classification {
			case "interaction":
				sensorBucket.Interaction++
			case "canary_invocation":
				sensorBucket.CanaryInvocation++
			case "correlation_signal":
				sensorBucket.CorrelationSignal++
			}
			sensorCount.SensorID = summary.Sensor.ID
			sensorCount.Kind = summary.Sensor.Kind
			sensorCount.Events++
			sensors[summary.Sensor.ID] = sensorCount
		}
		for _, id := range summary.RuleIDs {
			ruleCount := rules[id]
			ruleCount.RuleID = id
			ruleCount.Events++
			ruleCount.Severity = summary.Severity
			rules[id] = ruleCount
		}
	}

	overview.Totals = current.totals()
	overview.PreviousTotals = previous.totals()
	overview.TopSources = sources.sorted()

	for _, sensorCount := range sensors {
		overview.BySensor = append(overview.BySensor, sensorCount)
	}

	sort.Slice(overview.BySensor, func(i, j int) bool {
		return overview.BySensor[i].SensorID < overview.BySensor[j].SensorID
	})
	for _, ruleCount := range rules {
		overview.TopRules = append(overview.TopRules, ruleCount)
	}

	sort.Slice(overview.TopRules, func(i, j int) bool {
		if overview.TopRules[i].Events != overview.TopRules[j].Events {
			return overview.TopRules[i].Events > overview.TopRules[j].Events
		}
		return overview.TopRules[i].RuleID < overview.TopRules[j].RuleID
	})
	if len(overview.TopSources) > 10 {
		overview.TopSources = overview.TopSources[:10]
	}

	return overview, nil
}

// ByNode counts retained observations in the selected overview window.
func (index *Index) ByNode(window string, now time.Time) []NodeCount {
	duration, _, _ := Window(window)
	counts := map[string]NodeCount{}
	for _, item := range index.snapshot(now.Add(-duration), now, "") {
		summary := index.resolved(item.summary)
		id, name := "local", ""
		if summary.Node != nil {
			id, name = summary.Node.ID, summary.Node.Name
		}
		count := counts[id]
		count.ID, count.Name = id, name
		count.Events++
		counts[id] = count
	}
	out := make([]NodeCount, 0, len(counts))
	for _, count := range counts {
		out = append(out, count)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Sources aggregates retained sources in the half-open time window.
func (index *Index) Sources(from, to time.Time) []SourceSummary {
	counts := sourceCounts{}
	for _, item := range index.snapshot(from, to, "") {
		counts.add(item.summary)
	}
	return counts.sorted()
}

// Source aggregates one exact stored source value in the half-open window.
func (index *Index) Source(value string, from, to time.Time) *SourceSummary {
	if value == "" {
		return nil
	}
	counts := sourceCounts{}
	for _, item := range index.snapshot(from, to, value) {
		counts.add(item.summary)
	}
	if source := counts[value]; source != nil {
		sort.Strings(source.Sensors)
		sort.Strings(source.Kinds)
		return source
	}
	return nil
}
