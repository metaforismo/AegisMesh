package evidenceindex

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
)

func TestOriginScopingAndFilters(t *testing.T) {
	index, err := New(100, observe.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	name := "current-name"
	index.SetNodeNames(func(string) string { return name })
	envelope, err := event.New(&event.Sequencer{}, "synthetic", event.SensorRef{ID: "web", Kind: "http"},
		event.ClassificationInteraction, json.RawMessage(`{"path":"/","method":"GET"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	first, second := strings.Repeat("a", 32), strings.Repeat("b", 32)
	index.AddForwarded(envelope, first)
	index.AddForwarded(envelope, second)
	if _, _, _, _, ok := index.Get(envelope.ID); ok {
		t.Fatal("ambiguous unscoped ID selected")
	}
	index.Add(envelope)
	for _, node := range []string{"local", first, second} {
		filter, err := ParseFilter(url.Values{"node": {node}})
		if err != nil {
			t.Fatal(err)
		}
		page, err := index.Query(filter)
		if err != nil || len(page.Events) != 1 {
			t.Fatalf("node %s: %+v %v", node, page, err)
		}
		summary, _, _, _, ok := index.GetNode(envelope.ID, node)
		if !ok || node != "local" && (summary.Node == nil || summary.Node.ID != node) {
			t.Fatal("origin lookup failed")
		}
	}
	if len(index.Envelopes(100)) != 1 {
		t.Fatal("remote evidence entered local recommendation input")
	}
	signal := envelope
	signal.ID = strings.Repeat("c", 32)
	signal.Classification = event.ClassificationCorrelationSignal
	signal.Observation = json.RawMessage(`{"source_event_ids":["` + envelope.ID + `"]}`)
	index.AddForwarded(signal, first)
	_, _, _, related, ok := index.GetNode(signal.ID, first)
	if !ok || len(related) != 1 || related[0].Node.ID != first {
		t.Fatal("cross-node related-event link")
	}
	name = "renamed-current"
	summary, _, _, _, _ := index.GetNode(envelope.ID, second)
	if summary.Node.Name != name {
		t.Fatal("stale node name")
	}
	byNode := index.ByNode("1h", time.Now().Add(time.Second))
	if len(byNode) != 3 {
		t.Fatalf("node counts: %+v", byNode)
	}
	summary.Node.Name = "mutated-copy"
	fresh, _, _, _, _ := index.GetNode(envelope.ID, second)
	if fresh.Node.Name != name {
		t.Fatal("metadata alias escaped")
	}
}
