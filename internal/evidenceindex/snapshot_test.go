package evidenceindex

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
)

func TestAnalysisSnapshotBound(t *testing.T) {
	index, err := New(AnalysisLimit+1, observe.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= AnalysisLimit; i++ {
		e := event.Envelope{ID: fmt.Sprintf("%032x", i), Time: time.Unix(int64(i+1), 0), Sensor: event.SensorRef{ID: "web", Kind: "http"}, Observation: json.RawMessage(`{"remote_host":"192.0.2.1"}`)}
		index.Add(e)
	}
	snapshot := index.Analysis()
	if len(snapshot.Events) != AnalysisLimit || !snapshot.Truncated || snapshot.Scanned != AnalysisLimit || snapshot.Index.Events != AnalysisLimit+1 || snapshot.Events[0].ID != fmt.Sprintf("%032x", AnalysisLimit) {
		t.Fatal("wrong snapshot bounds", snapshot.Index)
	}
	snapshot.Events[0].RuleIDs = append(snapshot.Events[0].RuleIDs, "changed")
	if len(index.Analysis().Events[0].RuleIDs) != 0 {
		t.Fatal("snapshot aliases index")
	}
}

func TestLocalEvidenceNeverResolvesForwardedCollision(t *testing.T) {
	index, err := New(3, observe.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("%032x", 1)
	envelope := event.Envelope{ID: id, Time: time.Unix(1, 0), Observation: json.RawMessage(`{}`)}
	index.AddForwarded(envelope, fmt.Sprintf("%032x", 9))
	got, missing, err := index.LocalEvidence([]string{id})
	if err != nil || len(got) != 0 || missing != 1 {
		t.Fatal(got, missing, err)
	}
	index.Add(envelope)
	got, missing, err = index.LocalEvidence([]string{id})
	if err != nil || len(got) != 1 || missing != 0 {
		t.Fatal(got, missing, err)
	}
	got[0].Observation[0] = '!'
	again, _, _ := index.LocalEvidence([]string{id})
	if !json.Valid(again[0].Observation) {
		t.Fatal("aliased observation")
	}
	if _, _, err := index.LocalEvidence(make([]string, 4097)); err == nil {
		t.Fatal("unbounded local read")
	}
}
