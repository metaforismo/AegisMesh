package console

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/demoseed"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/evidenceview"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/recommend"
)

// seededMemoServer serves two tenants: the local one holds the small seeded
// profile, "other" holds a disjoint copy of its first 500 envelopes.
func seededMemoServer(t *testing.T) (*Server, *evidenceindex.Index, *evidenceindex.Index) {
	t.Helper()
	cfg, err := demoseed.Config(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	cfg.Correlation.Enabled = &enabled
	profile, _ := demoseed.Lookup(demoseed.Small)
	local, _ := evidenceindex.New(50000, observe.NewRegistry())
	other, _ := evidenceindex.New(50000, observe.NewRegistry())
	n := 0
	if _, err := demoseed.Generate(profile, cfg, time.Now(), func(e event.Envelope) error {
		local.Add(e)
		if n < 500 {
			other.Add(e)
		}
		n++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{
		Config: config.Console{Enabled: true, Listen: "127.0.0.1:0", SessionTTLSeconds: 3600, IndexMaxEvents: 50000,
			LocalTenant: "local", Tenants: []string{"local", "other"},
			Operators: []config.Operator{{Name: "memo", Role: "viewer", Tenants: []string{"local", "other"}, TokenSHA256: auth.Digest("synthetic-memo")}}},
		StateDir: filepath.Join(t.TempDir(), "console"), Index: local, Runtime: absentRuntime{}, Meter: observe.NewRegistry(),
		TenantIndexes: map[string]*evidenceindex.Index{"other": other},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close(context.Background()) })
	return s, local, other
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// TestMemoisedAnalysisMatchesReference compares every memoised derivation
// with the former per-request computation on seeded data, for both tenants.
func TestMemoisedAnalysisMatchesReference(t *testing.T) {
	s, local, other := seededMemoServer(t)
	for tenant, index := range map[string]*evidenceindex.Index{"local": local, "other": other} {
		view := s.views[tenant]
		reference := index.Analysis()
		memo := view.analysis()
		if memo.snapshot.Generation() == 0 || !bytes.Equal(mustJSON(t, memo.snapshot), mustJSON(t, reference)) ||
			!bytes.Equal(mustJSON(t, memo.snapshot.Events), mustJSON(t, reference.Events)) {
			t.Fatalf("%s: shared snapshot differs from a fresh copy", tenant)
		}
		sessions := evidenceview.Sessions(tenant, reference.Events)
		if len(sessions) == 0 || !bytes.Equal(mustJSON(t, memo.Sessions()), mustJSON(t, sessions)) {
			t.Fatalf("%s: sessions differ", tenant)
		}
		details := func(list []evidenceview.Session) []byte {
			var out bytes.Buffer
			for _, session := range list {
				out.Write(mustJSON(t, evidenceview.SessionDetail(session)))
			}
			return out.Bytes()
		}
		if !bytes.Equal(details(memo.Sessions()), details(sessions)) {
			t.Fatalf("%s: session details differ", tenant)
		}
		campaigns := evidenceview.Campaigns(tenant, sessions)
		got := memo.Campaigns()
		if !bytes.Equal(mustJSON(t, got.Campaigns), mustJSON(t, campaigns.Campaigns)) || got.ScannedSessions != campaigns.ScannedSessions || got.SessionsTruncated != campaigns.SessionsTruncated {
			t.Fatalf("%s: campaigns differ", tenant)
		}
		for i := range campaigns.Campaigns {
			if !bytes.Equal(mustJSON(t, got.Campaigns[i].Detail()), mustJSON(t, campaigns.Campaigns[i].Detail())) {
				t.Fatalf("%s: campaign detail %d differs", tenant, i)
			}
		}
		for _, source := range []string{"", "192.0.2.7", "<script>& ", "2001:db8::1", "\"quoted\"\\"} {
			for _, window := range []string{"3600000000000", "604800000000000"} {
				if got, want := memo.digest(source, window), analysisDigest(reference, source, window); got != want {
					t.Fatalf("%s: digest(%q,%q) = %s, want %s", tenant, source, window, got, want)
				}
			}
		}
		for _, e := range reference.Events {
			want := ""
			for _, session := range sessions {
				for _, member := range session.Events {
					if evidenceview.EventKey(member) == evidenceview.EventKey(e) {
						want = session.ID
						break
					}
				}
			}
			if got := memo.sessionOf(evidenceview.EventKey(e)); got != want {
				t.Fatalf("%s: session of %s = %q, want %q", tenant, e.ID, got, want)
			}
		}
		for _, limit := range []int{20, 5, 20} {
			want, err := recommend.Generate(index.Envelopes(recommend.MaxEvidence), recommend.Options{Limit: limit})
			if err != nil {
				t.Fatal(err)
			}
			got, err := view.recommendationReport(limit)
			if err != nil || !bytes.Equal(mustJSON(t, got), mustJSON(t, want)) {
				t.Fatalf("%s: recommendations(limit=%d) differ: %v", tenant, limit, err)
			}
		}
		ids := []string{}
		for _, e := range reference.Events[:min(len(reference.Events), 300)] {
			ids = append(ids, e.ID)
		}
		ids = append(ids, fmt.Sprintf("%032x", 7)) // missing
		envelopes, missing, err := index.LocalEvidence(ids)
		if err != nil {
			t.Fatal(err)
		}
		proposals, err := recommend.Generate(envelopes, recommend.Options{Limit: 20})
		if err != nil {
			t.Fatal(err)
		}
		for range 2 { // second call is served from the memo
			count, gotMissing, err := view.digestRecommendations(memo.snapshot, ids)
			if err != nil || count != len(proposals.Recommendations) || gotMissing != missing || missing != 1 {
				t.Fatalf("%s: digest recommendations %d/%d, want %d/%d (%v)", tenant, count, gotMissing, len(proposals.Recommendations), missing, err)
			}
		}
	}
	if s.views["local"].analysis().Sessions()[0].ID == s.views["other"].analysis().Sessions()[0].ID {
		t.Fatal("tenant views share session identities")
	}
}

// TestAnalysisMemoReuseAndInvalidation checks one computation per generation,
// replacement on append, and no memoisation with a live name resolver.
func TestAnalysisMemoReuseAndInvalidation(t *testing.T) {
	s, local, _ := seededMemoServer(t)
	view := s.views["local"]
	first := view.analysis()
	if again := view.analysis(); again != first || &again.Sessions()[0] != &first.Sessions()[0] {
		t.Fatal("unchanged generation was recomputed")
	}
	if _, err := view.recommendationReport(20); err != nil {
		t.Fatal(err)
	}
	reportGeneration := view.memo.recommendations.generation
	local.Add(benchEnvelopeForMemo())
	second := view.analysis()
	if second == first || second.snapshot.Generation() <= first.snapshot.Generation() || len(second.snapshot.Events) != len(first.snapshot.Events)+1 {
		t.Fatal("append did not invalidate the memo")
	}
	if _, err := view.recommendationReport(20); err != nil || view.memo.recommendations.generation == reportGeneration || view.memo.recommendations.generation != local.Generation() {
		t.Fatal("recommendations not recomputed after append")
	}
	// A request still holding the older snapshot never replaces the newer entry.
	view.memo.mu.Lock()
	view.memo.current = second
	view.memo.mu.Unlock()
	if got := view.analysis(); got != second {
		t.Fatal("current generation not reused")
	}

	local.SetNodeNames(func(string) string { return "renamed" })
	resolved := view.analysis()
	if resolved.snapshot.Generation() != 0 || view.analysis() == resolved {
		t.Fatal("snapshots with a live name resolver must not be memoised")
	}
}

func benchEnvelopeForMemo() event.Envelope {
	observation := json.RawMessage(`{"method":"GET","path":"/memo","remote_host":"198.51.100.200","response":{"status":404},"synthetic":true}`)
	return event.Envelope{
		Schema: event.SchemaV1, ID: fmt.Sprintf("%032x", 0xabcdef), Time: time.Now().UTC(), Seq: 1, Instance: "synthetic-memo",
		Sensor: event.SensorRef{ID: "demo-http", Kind: "http"}, Classification: event.ClassificationInteraction,
		Integrity: event.Integrity{PayloadSHA256: event.SHA256Hex(observation), Algorithm: "sha256"}, Observation: observation,
	}
}

// TestSharedAnalysisIsolatesCallerAppends keeps the shared sample safe from
// a caller appending to a summary's slices.
func TestSharedAnalysisIsolatesCallerAppends(t *testing.T) {
	_, local, _ := seededMemoServer(t)
	shared := local.SharedAnalysis()
	for i := range shared.Events {
		if cap(shared.Events[i].RuleIDs) != len(shared.Events[i].RuleIDs) || cap(shared.Events[i].TokenIDs) != len(shared.Events[i].TokenIDs) {
			t.Fatal("shared summary slices are not clipped")
		}
	}
	before := mustJSON(t, local.SharedAnalysis().Events)
	e := shared.Events[0]
	e.RuleIDs = append(e.RuleIDs, "changed")
	e.TokenIDs = append(e.TokenIDs, "changed")
	if !bytes.Equal(before, mustJSON(t, local.SharedAnalysis().Events)) {
		t.Fatal("caller append reached the shared sample")
	}
}

// TestCatalogWindowMatchesReference compares the subslice fast path with the
// former filtering copy, including a non-contiguous layout.
func TestCatalogWindowMatchesReference(t *testing.T) {
	s, local, _ := seededMemoServer(t)
	view := s.views["local"]
	reference := func(events []evidenceindex.Summary, duration time.Duration, now time.Time) []evidenceindex.Summary {
		out := []evidenceindex.Summary{}
		for _, e := range events {
			at := evidenceview.Time(e)
			if !at.Before(now.Add(-duration)) && at.Before(now) {
				out = append(out, e)
			}
		}
		return out
	}
	for _, window := range []string{"1h", "24h", "7d"} {
		duration, _, _ := evidenceindex.Window(window)
		r := httptest.NewRequest("GET", "/api/v1/decoys?window="+window, nil)
		before := time.Now().UTC()
		snapshot, events, ok := view.catalogWindow(httptest.NewRecorder(), r)
		after := time.Now().UTC()
		if !ok || window == "7d" && len(events) == 0 {
			t.Fatalf("%s: no events", window)
		}
		// now is taken inside catalogWindow; the reference must match at one of the bounds' instants.
		got := mustJSON(t, events)
		if !bytes.Equal(got, mustJSON(t, reference(snapshot.Events, duration, before))) && !bytes.Equal(got, mustJSON(t, reference(snapshot.Events, duration, after))) {
			t.Fatalf("%s: window events differ", window)
		}
	}
	// A future-dated event ahead of the window keeps the run contiguous; one
	// injected out of order inside the sample exercises the copy path.
	future := benchEnvelopeForMemo()
	future.Time = time.Now().Add(time.Hour)
	local.Add(future)
	_, events, _ := view.catalogWindow(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/v1/decoys?window=7d", nil))
	for _, e := range events {
		if e.ID == future.ID {
			t.Fatal("future event inside the window")
		}
	}
}

// TestIncrementalSessionsAfterAppendsMatchFullRecompute replays seeded
// envelopes as new observations in random batches (some with earlier native
// times) and compares the memo's incremental sessions, campaigns and every
// campaign detail with a full recompute after every batch.
func TestIncrementalSessionsAfterAppendsMatchFullRecompute(t *testing.T) {
	s, local, _ := seededMemoServer(t)
	view := s.views["local"]
	view.analysis().Sessions() // the base generation
	replay := local.EnvelopesAt
	envelopes, _ := replay(400)
	r := rand.New(rand.NewPCG(7, 7))
	before := incrementalSessions.Load()
	next := 0
	for step := range 40 {
		for range 1 + r.IntN(15) {
			e := envelopes[next%len(envelopes)]
			next++
			e.ID = fmt.Sprintf("%032x", 0xfeed0000+next)
			e.Time = time.Now().UTC().Add(-time.Duration(r.IntN(3600)) * time.Second)
			local.Add(e)
		}
		analysis := view.analysis()
		got := analysis.Sessions()
		want := evidenceview.Sessions("local", analysis.snapshot.Events)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("step %d: sessions differ from full recompute", step)
		}
		gotCampaigns, wantCampaigns := analysis.Campaigns(), evidenceview.Campaigns("local", want)
		if !bytes.Equal(mustJSON(t, gotCampaigns.Campaigns), mustJSON(t, wantCampaigns.Campaigns)) {
			t.Fatalf("step %d: campaigns differ", step)
		}
		for i := range gotCampaigns.Campaigns {
			if !bytes.Equal(mustJSON(t, gotCampaigns.Campaigns[i].Detail()), mustJSON(t, wantCampaigns.Campaigns[i].Detail())) {
				t.Fatalf("step %d: campaign detail differs", step)
			}
		}
	}
	if taken := incrementalSessions.Load() - before; taken < 40 {
		t.Fatalf("incremental path taken %d of 40 generations", taken)
	}
}
