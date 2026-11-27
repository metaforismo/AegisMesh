package evidenceview

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

var campaignSeq = 0

// walk emits one HTTP interaction per path for source, starting at offset.
func walk(source string, offset time.Duration, client string, paths ...string) []evidenceindex.Summary {
	out := []evidenceindex.Summary{}
	for i, path := range paths {
		campaignSeq++
		out = append(out, evidenceindex.Summary{
			ID: fmt.Sprintf("%032x", campaignSeq), Time: actorEpoch.Add(offset + time.Duration(i)*time.Second).Format(time.RFC3339Nano),
			Source: source, Sensor: event.SensorRef{ID: "web", Kind: "http"}, Classification: "interaction",
			Summary: path + " → 200", HTTPStatus: 200, RuleIDs: []string{"LLM-001"}, Severity: "low", ClientFamily: client,
		})
	}
	return out
}

func joined(parts ...[]evidenceindex.Summary) []evidenceindex.Summary {
	out := []evidenceindex.Summary{}
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestCampaignExactSequenceAcrossSources(t *testing.T) {
	events := joined(
		walk("192.0.2.10", 0, evidenceindex.ClientOpenAISDK, "GET /api/tags", "GET /v1/models", "GET /v1/models", "POST /v1/chat/completions"),
		walk("198.51.100.20", time.Minute, evidenceindex.ClientOpenAISDK, "GET /api/tags", "GET /v1/models", "POST /v1/chat/completions"),
		walk("203.0.113.30", 2*time.Minute, "", "GET /", "GET /robots.txt", "GET /admin"),
		walk("203.0.113.31", 3*time.Minute, "", "GET /api/tags", "GET /v1/models"),
	)
	sessions := Sessions("alpha", events)
	set := Campaigns("alpha", sessions)
	if len(set.Campaigns) != 1 || set.ScannedSessions != 4 || set.SessionsTruncated {
		t.Fatalf("%+v", set)
	}
	c := set.Campaigns[0]
	if !regexp.MustCompile(`^cmp_[0-9a-f]{12}$`).MatchString(c.ID) || c.SourceCount != 2 || c.SessionCount != 2 || c.EventCount != 7 {
		t.Fatalf("%+v", c)
	}
	if !reflect.DeepEqual(c.Basis, []string{BasisSameSequence, BasisSameClient}) || c.FingerprintSteps != 3 {
		t.Fatalf("basis %v steps %d", c.Basis, c.FingerprintSteps)
	}
	if !reflect.DeepEqual(c.Sources, []string{"192.0.2.10", "198.51.100.20"}) || c.MaxSeverity != "low" || !reflect.DeepEqual(c.RuleIDs, []string{"LLM-001"}) {
		t.Fatalf("%+v", c)
	}
	if c.Label != "GET /api/tags → GET /v1/models → POST /v1/chat/completions" || !reflect.DeepEqual(c.Stages, []string{"discovery"}) {
		t.Fatalf("label %q stages %v", c.Label, c.Stages)
	}
	if c.AutomationCounts[AssessmentInconclusive] != 2 || len(c.AutomationCounts) != 4 {
		t.Fatal(c.AutomationCounts)
	}
	if Campaigns("alpha", Sessions("alpha", events)).Campaigns[0].ID != c.ID {
		t.Fatal("campaign ID not stable across calls")
	}
	members := 0
	for _, s := range sessions {
		if s.CampaignID != nil {
			members++
			if *s.CampaignID != c.ID {
				t.Fatal("wrong campaign reference")
			}
		}
	}
	if members != 2 {
		t.Fatal("campaign_id not assigned to exactly the members")
	}
	d := c.Detail()
	if len(d.Steps) != 3 || d.Steps[2] != (CampaignStep{Index: 2, SensorKind: "http", Shape: "POST /v1/chat/completions", Stage: "discovery", Sessions: 2}) ||
		len(d.Sessions) != 2 || len(d.Caveats) == 0 || d.StepsTruncated {
		t.Fatalf("%+v", d)
	}
}

func TestCampaignPrefixAndThresholds(t *testing.T) {
	long := []string{"GET /a", "GET /b", "GET /c", "GET /d", "GET /e", "GET /f", "GET /g", "GET /h"}
	events := joined(
		walk("192.0.2.1", 0, "", append(append([]string{}, long...), "GET /x")...),
		walk("192.0.2.2", time.Minute, evidenceindex.ClientCLI, append(append([]string{}, long...), "GET /y", "GET /z")...),
		// Same source twice is one source: never a campaign on its own.
		walk("192.0.2.3", 2*time.Minute, "", "GET /p", "GET /q", "GET /r"),
		walk("192.0.2.3", 2*time.Hour, "", "GET /p", "GET /q", "GET /r"),
		// Two steps are below MinCampaignSteps.
		walk("192.0.2.4", 3*time.Minute, "", "GET /m", "GET /n"),
		walk("192.0.2.5", 4*time.Minute, "", "GET /m", "GET /n"),
	)
	set := Campaigns("alpha", Sessions("alpha", events))
	if len(set.Campaigns) != 1 {
		t.Fatalf("%+v", set.Campaigns)
	}
	c := set.Campaigns[0]
	if !reflect.DeepEqual(c.Basis, []string{BasisSamePrefix}) || c.FingerprintSteps != CampaignPrefixSteps || len(c.ClientFamilies) != 1 {
		t.Fatalf("%+v", c)
	}
	d := c.Detail()
	if len(d.Steps) != 10 || d.Steps[8].Sessions != 1 || d.Steps[9].Shape != "GET /z" || d.Steps[0].Sessions != 2 {
		t.Fatalf("%+v", d.Steps)
	}
	// Ties at index 8 resolve lexically to "GET /x"; the /y-/z session marks 0..7 and 9.
	for _, s := range d.Sessions {
		marks := []string{}
		for _, m := range s.StepMarks {
			marks = append(marks, fmt.Sprintf("%d@%.0f", m.Index, m.OffsetMS))
		}
		want := "0@0,1@1000,2@2000,3@3000,4@4000,5@5000,6@6000,7@7000,8@8000"
		if s.Source == "192.0.2.2" {
			want = "0@0,1@1000,2@2000,3@3000,4@4000,5@5000,6@6000,7@7000,9@9000"
		}
		if strings.Join(marks, ",") != want {
			t.Fatalf("%s: %v", s.Source, marks)
		}
	}
}

func TestCampaignNeverMixesTenants(t *testing.T) {
	alpha := walk("192.0.2.10", 0, "", "GET /a", "GET /b", "GET /c")
	bravo := walk("198.51.100.20", time.Minute, "", "GET /a", "GET /b", "GET /c")
	// One source per tenant: neither tenant alone has two sources, so the
	// shared behaviour must not form a campaign in either partition.
	if len(Campaigns("alpha", Sessions("alpha", alpha)).Campaigns) != 0 || len(Campaigns("bravo", Sessions("bravo", bravo)).Campaigns) != 0 {
		t.Fatal("campaign formed from another tenant's sessions")
	}
	both := joined(alpha, bravo)
	a := Campaigns("alpha", Sessions("alpha", both)).Campaigns[0]
	b := Campaigns("bravo", Sessions("bravo", both)).Campaigns[0]
	if a.ID == b.ID {
		t.Fatal("equal behaviour in two tenants produced the same campaign ID")
	}
}

func TestCampaignCaps(t *testing.T) {
	events := []evidenceindex.Summary{}
	for i := 0; i < CampaignSessionRefLimit+5; i++ {
		events = append(events, walk(fmt.Sprintf("203.0.113.%d", i+1), time.Duration(i)*time.Minute, "", "GET /a", "GET /b", "GET /c")...)
	}
	c := Campaigns("alpha", Sessions("alpha", events)).Campaigns[0]
	if len(c.Sources) != CampaignSourceLimit || !c.SourcesTruncated || c.SourceCount != CampaignSessionRefLimit+5 ||
		len(c.SessionIDs) != CampaignSessionRefLimit || !c.SessionIDsTruncated {
		t.Fatalf("%d %t %d %d", len(c.Sources), c.SourcesTruncated, c.SourceCount, len(c.SessionIDs))
	}
	d := c.Detail()
	if len(d.Sessions) != CampaignSessionRefLimit || !d.SessionsTruncated {
		t.Fatal("detail sessions uncapped")
	}
	many := make([]Session, CampaignSessionLimit+1)
	set := Campaigns("alpha", many)
	if set.ScannedSessions != CampaignSessionLimit || !set.SessionsTruncated {
		t.Fatal("session scan cap")
	}
}

func TestEventSampleRoundRobinNewestFirst(t *testing.T) {
	mk := func(source string, n int) Session {
		s := Session{ID: source}
		for i := range n {
			s.Events = append(s.Events, evidenceindex.Summary{ID: fmt.Sprintf("%s-%d", source, i)})
		}
		return s
	}
	ids := func(events []evidenceindex.Summary) string {
		out := []string{}
		for _, e := range events {
			out = append(out, e.ID)
		}
		return strings.Join(out, ",")
	}
	sessions := []Session{mk("a", 3), mk("b", 1), mk("c", 2)}
	if got := ids(sampleSessions(sessions, 10, nil)); got != "a-2,b-0,c-1,a-1,c-0,a-0" {
		t.Fatalf("sample = %s", got)
	}
	if got := ids(sampleSessions(sessions, 4, nil)); got != "a-2,b-0,c-1,a-1" {
		t.Fatalf("bounded = %s", got)
	}
	skipB := func(e evidenceindex.Summary) bool { return !strings.HasPrefix(e.ID, "b") }
	if got := ids(sampleSessions(sessions, 10, skipB)); got != "a-2,c-1,a-1,c-0,a-0" {
		t.Fatalf("filtered = %s", got)
	}
	if got := sampleSessions(nil, 5, nil); len(got) != 0 {
		t.Fatal("empty")
	}
}
