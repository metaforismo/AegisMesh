package evidenceindex

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
)

func TestInterArrivalAllRetainedAndBoundaries(t *testing.T) {
	index, _ := New(100, observe.NewRegistry())
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	gaps := []time.Duration{0, 99 * time.Millisecond, 100 * time.Millisecond, 999 * time.Millisecond, time.Second, 10 * time.Second, time.Minute, 5 * time.Minute, 30 * time.Minute}
	timestamp := now
	add := func(i int) {
		body := json.RawMessage(`{"remote_host":"192.0.2.1"}`)
		index.Add(event.Envelope{
			ID:   fmt.Sprintf("%032x", i+1),
			Time: timestamp,
			Sensor: event.SensorRef{
				ID:   "web",
				Kind: "http",
			},
			Classification: "interaction",
			Observation:    body,
		})
	}
	add(0)
	for i, gap := range gaps {
		timestamp = timestamp.Add(gap)
		add(i + 1)
	}
	histogram := index.InterArrival("192.0.2.1")
	want := []int{2, 2, 1, 1, 1, 1, 1}
	if len(histogram) != len(want) {
		t.Fatal(histogram)
	}
	for i, count := range want {
		if histogram[i].Count != count {
			t.Fatal(histogram)
		}
	}
	if histogram[len(histogram)-1].LessThanMS != nil {
		t.Fatal("missing overflow bucket")
	}
	for _, b := range index.InterArrival("missing") {
		if b.Count != 0 {
			t.Fatal("foreign source histogram")
		}
	}
}
func TestSharedStreamEncodingOwnershipAndSlowDrop(t *testing.T) {
	index, _ := New(100, observe.NewRegistry())
	a, cancelA, ok := index.SubscribeEncoded()
	if !ok {
		t.Fatal("subscribe")
	}
	defer cancelA()
	b, cancelB, ok := index.SubscribeEncoded()
	if !ok {
		t.Fatal("subscribe")
	}
	defer cancelB()
	body := json.RawMessage(`{"remote_host":"192.0.2.1","method":"GET","path":"/"}`)
	e, err := event.New(&event.Sequencer{}, "synthetic", event.SensorRef{
		ID:   "web",
		Kind: "http",
	}, "interaction", body, nil)
	if err != nil {
		t.Fatal(err)
	}
	index.Add(e)
	first, second := <-a, <-b
	if first != second {
		t.Fatal("per-subscriber encoding object")
	}
	var wg sync.WaitGroup
	results := make(chan []byte, 2)
	for _, stream := range []*StreamEvent{first, second} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var out bytes.Buffer
			if _, err := stream.WriteTo(&out); err != nil {
				t.Error(err)
			}
			results <- out.Bytes()
		}()
	}
	wg.Wait()
	close(results)
	var previous []byte
	for raw := range results {
		if previous != nil && !bytes.Equal(previous, raw) {
			t.Fatal("different shared frames")
		}
		previous = raw
	}
	for i := 0; i < 33; i++ {
		e.ID = fmt.Sprintf("%032x", i+100)
		index.Add(e)
		<-a
	}
	for range b {
	}
	if len(index.streams) != 1 {
		t.Fatal("slow subscriber retained")
	}
}
func TestExportOriginCollisionAndEviction(t *testing.T) {
	index, _ := New(2, observe.NewRegistry())
	e, _ := event.New(&event.Sequencer{}, "synthetic", event.SensorRef{
		ID:   "web",
		Kind: "http",
	}, "interaction", json.RawMessage(`{}`), nil)
	index.Add(e)
	index.AddForwarded(e, strings.Repeat("a", 32))
	selected := index.Analysis().Events
	records, err := index.ExportEvidence(selected)
	if err != nil || len(records) != 2 || records[0].NodeID == records[1].NodeID {
		t.Fatal("origin collision", records, err)
	}
	e.ID = strings.Repeat("b", 32)
	index.Add(e)
	if records, err := index.ExportEvidence(selected); err == nil || len(records) != 0 {
		t.Fatal("partial stale export")
	}
}

func TestByNodeResolvesNameOncePerOrigin(t *testing.T) {
	index, _ := New(100, observe.NewRegistry())
	calls := 0
	index.SetNodeNames(func(string) string { calls++; return "current name" })
	for i := 0; i < 20; i++ {
		index.AddForwarded(event.Envelope{ID: fmt.Sprintf("%032x", i+1), Time: time.Unix(1800000000+int64(i), 0), Sensor: event.SensorRef{ID: "web", Kind: "http"}, Observation: json.RawMessage(`{}`)}, strings.Repeat("a", 32))
	}
	nodes := index.ByNode("24h", time.Unix(1800001000, 0))
	if len(nodes) != 1 || nodes[0].Name != "current name" || nodes[0].Events != 20 || calls != 1 {
		t.Fatal(nodes, calls)
	}
}
