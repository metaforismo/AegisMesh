package evidenceindex

import (
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
)

func TestAppendedAndLocalSummaries(t *testing.T) {
	index, err := New(4, observe.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	sequencer := &event.Sequencer{}
	ids := []string{}
	start := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	for i := range 6 {
		e := envelope(t, sequencer, "interaction", `{"remote_host":"203.0.113.7"}`)
		// Out-of-order native times: the index keeps chronological order.
		e.Time = start.Add(time.Duration((i*7)%6) * time.Minute)
		index.Add(e)
		ids = append(ids, e.ID)
	}
	select {
	case <-index.Appends():
	default:
		t.Fatal("append did not signal")
	}
	got, next := index.Appended(0, 0)
	if next != 6 || len(got) != 4 {
		t.Fatalf("appended %d, next %d; capacity 4 keeps the newest-retained four", len(got), next)
	}
	got, _ = index.Appended(4, 0)
	if len(got) != 2 || got[0].ID != ids[4] || got[1].ID != ids[5] {
		t.Fatalf("after 4: %+v", got)
	}
	if got, _ = index.Appended(0, 1); len(got) != 1 || got[0].ID != ids[5] {
		t.Fatalf("max 1: %+v", got)
	}
	if got, _ = index.Appended(6, 0); len(got) != 0 {
		t.Fatal("nothing after the newest ordinal")
	}
	// LocalSummaries matches the newest-first order of Summaries.
	all := index.Summaries()
	request := []string{}
	for i := len(all) - 1; i >= 0; i-- {
		request = append(request, all[i].ID, all[i].ID)
	}
	request = append(request, "00000000000000000000000000000000")
	local, missing := index.LocalSummaries(request)
	if missing != 1 || len(local) != len(all) {
		t.Fatalf("local %d missing %d", len(local), missing)
	}
	for i := range all {
		if local[i].ID != all[i].ID {
			t.Fatalf("order differs at %d", i)
		}
	}
}
