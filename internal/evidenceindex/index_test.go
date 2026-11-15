package evidenceindex

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
)

func envelope(t *testing.T, sequencer *event.Sequencer, classification, obs string) event.Envelope {
	t.Helper()
	envelope, err := event.New(sequencer, "test", event.SensorRef{
		ID:     "web",
		Kind:   "http",
		Listen: "127.0.0.1:8080",
	}, classification, json.RawMessage(obs), nil)
	if err != nil {
		t.Fatal(err)
	}

	return envelope
}

func TestProjectionDefensive(t *testing.T) {
	for _, raw := range []string{
		`null`,
		`[]`,
		`42`,
		`{"method":[],"path":{},"detection":7}`,
		`{"detection":{"findings":[null,2,{"rule_id":"bogus","reason":"attacker"}]}}`,
		`{"method":"GET","path":"/admin","response":{"status":200},"remote_host":"203.0.113.7",` +
			`"detection":{"action":"refuse","findings":[` +
			`{"rule_id":"PI-001","reason":"attacker text","severity":"critical"}]}}`,
	} {
		observation := envelope(t, &event.Sequencer{}, "interaction", raw)
		summary, findings, _ := Project(observation)
		if len([]rune(summary.Summary)) > 160 {
			t.Fatal(summary)
		}
		for _, finding := range findings {
			if strings.Contains(finding.Reason, "attacker") {
				t.Fatal("raw reason exposed")
			}
		}
		if strings.Contains(raw, "/admin") &&
			(summary.Summary != "GET /admin → 200" ||
				summary.Source != "203.0.113.7" ||
				summary.Severity != "high" ||
				len(summary.RuleIDs) != 1 ||
				summary.Action != "refuse") {
			t.Fatalf("projection: %+v", summary)
		}
	}
}

func TestEvictionCursorRelatedAndSubscribers(t *testing.T) {
	index, err := New(3, observe.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}

	sequencer := &event.Sequencer{}
	events := []event.Envelope{}
	observations, cancel, ok := index.Subscribe()
	if !ok {
		t.Fatal("subscribe")
	}

	defer cancel()

	for range 3 {
		observation := envelope(t, sequencer, "interaction", `{"remote_host":"203.0.113.7"}`)
		events = append(events, observation)
		index.Add(observation)
	}

	if (<-observations).ID != events[0].ID {
		t.Fatal("subscriber ordering")
	}

	filter := Filter{Limit: 1}
	page, err := index.Query(filter)
	if err != nil || page.TotalMatched != 3 || page.Events[0].ID != events[2].ID || page.NextCursor == "" {
		t.Fatalf("%+v %v", page, err)
	}

	filter.Cursor = page.NextCursor
	nextPage, err := index.Query(filter)
	if err != nil || nextPage.Events[0].ID != events[1].ID {
		t.Fatalf("%+v %v", nextPage, err)
	}

	filter.Source = "other"
	if _, err = index.Query(filter); err == nil {
		t.Fatal("cursor reused with different filters")
	}

	filter.Source = ""
	filter.Cursor = filter.Cursor[:len(filter.Cursor)-2] + "xx"
	if _, err = index.Query(filter); err == nil {
		t.Fatal("tamper accepted")
	}

	signal := envelope(
		t, sequencer, "correlation_signal",
		`{"rule_id":"COR-001","source_key":"203.0.113.7","source_event_ids":["`+events[2].ID+`"]}`,
	)
	index.Add(signal)
	if index.Stats().History != "truncated" || index.Stats().Events != 3 {
		t.Fatal(index.Stats())
	}

	_, _, _, related, ok := index.Get(signal.ID)
	if !ok || len(related) != 1 || related[0].ID != events[2].ID {
		t.Fatal("signal provenance missing")
	}

	_, _, _, related, _ = index.Get(events[2].ID)
	if len(related) != 1 || related[0].ID != signal.ID {
		t.Fatal("reverse provenance missing")
	}

	if _, _, _, _, ok = index.Get(events[0].ID); ok {
		t.Fatal("oldest not evicted")
	}

	for range 40 {
		index.Add(envelope(t, sequencer, "interaction", `{}`))
	}

	for range observations {
	}

	// slow subscribers must be closed
	streams := []func(){}
	for range MaxStreams {
		_, cancelStream, ok := index.Subscribe()
		if !ok {
			t.Fatal("early stream limit")
		}
		streams = append(streams, cancelStream)
	}

	if _, _, ok = index.Subscribe(); ok {
		t.Fatal("stream limit bypass")
	}

	for _, cancelStream := range streams {
		cancelStream()
	}
}

func TestOverviewWindows(t *testing.T) {
	index, _ := New(20, observe.NewRegistry())
	now := time.Now().UTC()
	sequencer := &event.Sequencer{}
	for _, age := range []time.Duration{
		time.Minute,
		25 * time.Hour,
	} {
		observation := envelope(t, sequencer, "interaction", `{"remote_host":"203.0.113.7"}`)
		observation.Time = now.Add(-age)
		index.Add(observation)
	}

	for _, testCase := range []struct {
		window   string
		buckets  int
		events   int
		previous int
	}{
		{
			window:   "1h",
			buckets:  60,
			events:   1,
			previous: 0,
		},
		{
			window:   "24h",
			buckets:  48,
			events:   1,
			previous: 1,
		},
		{
			window:   "7d",
			buckets:  56,
			events:   2,
			previous: 0,
		},
	} {
		overview, err := index.Overview(testCase.window, now)
		if err != nil ||
			len(overview.Buckets) != testCase.buckets ||
			overview.Totals.Events != testCase.events ||
			overview.PreviousTotals.Events != testCase.previous ||
			overview.BySeverity["none"] != testCase.events {
			t.Fatalf("%+v: %+v %v", testCase, overview, err)
		}
	}
}

func TestFilters(t *testing.T) {
	for _, queryText := range []string{
		"unknown=x",
		"limit=201",
		"limit=-1",
		"severity=bad",
		"classification=bad",
		"since=yesterday",
		"since=2026-11-14T00:00:00Z&until=2026-11-13T00:00:00Z",
		"q=" + strings.Repeat("x", 129),
		"sensor=a&sensor=b",
	} {
		values, _ := url.ParseQuery(queryText)
		if _, err := ParseFilter(values); err == nil {
			t.Errorf("accepted %s", queryText)
		}
	}

	index, _ := New(10, observe.NewRegistry())
	index.Add(envelope(t, &event.Sequencer{}, "interaction", `{"method":"GET","path":"/admin","remote_host":"203.0.113.7",`+
		`"detection":{"findings":[{"rule_id":"PI-001"}]}}`))
	for _, queryText := range []string{
		"q=ADMIN&severity=medium&rule=PI-001&source=203.0.113.7&kind=http&sensor=web&classification=interaction",
		"severity=critical",
		"source=other",
	} {
		values, _ := url.ParseQuery(queryText)
		filter, err := ParseFilter(values)
		if err != nil {
			t.Fatal(err)
		}
		page, err := index.Query(filter)
		want := 0
		if strings.HasPrefix(queryText, "q=") {
			want = 1
		}
		if err != nil || page.TotalMatched != want {
			t.Fatalf("%s: %+v %v", queryText, page, err)
		}
	}
}

func FuzzObservationProjection(fuzzer *testing.F) {
	for _, raw := range []string{
		`{}`,
		`null`,
		`{"detection":{"findings":[{"rule_id":"PI-001"}]}}`,
		`{"source_event_ids":[null,{},"abc"]}`,
		`{"outcome":"authentication_failed","last_auth_method":"password","auth_attempts":3}`,
		`{"lines_exchanged":2,"bytes_total":64,"response":{"rule_id":"banner"}}`,
		`{"method":"tools/call","tool_name":"canary_demo"}`,
	} {
		fuzzer.Add([]byte(raw))
	}

	fuzzer.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > event.MaxStoredEnvelopeBytes {
			return
		}
		summary, findings, ids := Project(event.Envelope{
			Observation:    body,
			Classification: event.ClassificationCorrelationSignal,
		})
		if len([]rune(summary.Summary)) > 160 || len(summary.Source) > 255 || len(findings) > 64 || len(ids) > 64 {
			t.Fatal("projection bound")
		}
		for _, kind := range []string{
			"http",
			"mcp",
			"ssh",
			"tcp",
			"unknown",
		} {
			projected, _, _ := Project(event.Envelope{
				Observation:    body,
				Sensor:         event.SensorRef{Kind: kind},
				Classification: event.ClassificationInteraction,
			})
			if len([]rune(projected.Summary)) > 160 {
				t.Fatalf("%s summary exceeded bound", kind)
			}
			for _, character := range projected.Summary {
				if unicode.IsControl(character) {
					t.Fatalf("%s summary contains a control character", kind)
				}
			}
		}
	})
}

func FuzzCursorFilter(fuzzer *testing.F) {
	fuzzer.Add("limit=1")
	fuzzer.Add("cursor=bad")
	fuzzer.Add("q=%ff")
	index, _ := New(10, observe.NewRegistry())
	fuzzer.Fuzz(func(t *testing.T, queryText string) {
		if len(queryText) > 8192 {
			return
		}
		values, err := url.ParseQuery(queryText)
		if err != nil {
			return
		}
		parsed, err := ParseFilter(values)
		if err != nil {
			return
		}
		if _, err = index.Query(parsed); err == nil && (parsed.Limit < 1 || parsed.Limit > 200) {
			t.Fatal("limit")
		}
	})
}

func TestTimestampOrderAndByteBudget(t *testing.T) {
	index, _ := New(1000, observe.NewRegistry())
	sequencer := &event.Sequencer{}
	now := time.Now().UTC()
	envelopes := []event.Envelope{}
	for _, offset := range []int{
		0,
		3,
		1,
		2,
	} {
		observation := envelope(t, sequencer, "interaction", `{}`)
		observation.Time = now.Add(time.Duration(offset) * time.Second)
		envelopes = append(envelopes, observation)
		index.Add(observation)
	}

	page, err := index.Query(Filter{Limit: 2})
	if err != nil || page.Events[0].ID != envelopes[1].ID || page.Events[1].ID != envelopes[3].ID {
		t.Fatalf("timestamp sort: %+v %v", page, err)
	}

	page, err = index.Query(Filter{
		Limit:  2,
		Cursor: page.NextCursor,
	})
	if err != nil || page.Events[0].ID != envelopes[2].ID || page.Events[1].ID != envelopes[0].ID {
		t.Fatalf("timestamp cursor: %+v %v", page, err)
	}

	payload := `{"preview":"` + strings.Repeat("x", 700000) + `"}`
	for range 100 {
		index.Add(envelope(t, sequencer, "interaction", payload))
	}

	if index.bytes > MaxBytes || index.Stats().History != "truncated" || index.Stats().Events >= 100 {
		t.Fatal("byte budget not enforced", index.Stats())
	}
}

func TestSourceByteBound(t *testing.T) {
	observation := envelope(t, &event.Sequencer{}, "interaction", `{"remote_host":"`+strings.Repeat("界", 255)+`"}`)
	summary, _, _ := Project(observation)
	if len(summary.Source) > 255 || !strings.HasPrefix(summary.Source, "界") {
		t.Fatal("source is not queryable within its decoded-byte limit")
	}
}
