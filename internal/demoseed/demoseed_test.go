package demoseed_test

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/demoseed"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/evidenceview"
	"github.com/metaforismo/aegismesh/internal/observe"
)

var anchor = time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

func demoConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := demoseed.Config(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	enabled := true // as the demo's seed mode configures it
	cfg.Correlation.Enabled = &enabled
	return cfg
}

func generate(t *testing.T, cfg *config.Config, name string) ([]event.Envelope, demoseed.Result) {
	t.Helper()
	profile, err := demoseed.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	var out []event.Envelope
	result, err := demoseed.Generate(profile, cfg, anchor, func(e event.Envelope) error {
		out = append(out, e)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out, result
}

var documentation = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32"),
}

func TestLookupRejectsUnknownProfile(t *testing.T) {
	if _, err := demoseed.Lookup("medium"); err == nil || !strings.Contains(err.Error(), "large, small") && !strings.Contains(err.Error(), "[large small]") {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := demoseed.Names(); len(got) != 2 || got[0] != "large" || got[1] != "small" {
		t.Fatalf("names: %v", got)
	}
}

func TestSmallProfileShape(t *testing.T) {
	cfg := demoConfig(t)
	envelopes, result := generate(t, cfg, demoseed.Small)
	if result.Events != 2000 || len(envelopes) != result.Events+result.Signals || result.Signals == 0 {
		t.Fatalf("result %+v with %d envelopes", result, len(envelopes))
	}
	if result.Oldest.Before(anchor.Add(-7*24*time.Hour)) || !result.Newest.Before(anchor.Add(-time.Minute)) {
		t.Fatalf("time bounds %s..%s", result.Oldest, result.Newest)
	}
	kinds, classes := map[string]int{}, map[string]int{}
	secrets := []string{}
	for _, token := range cfg.Honeytokens {
		secrets = append(secrets, token.Value)
	}
	for _, e := range envelopes {
		if err := e.Validate(); err != nil {
			t.Fatal(err)
		}
		if err := e.VerifyIntegrity(); err != nil {
			t.Fatal(err)
		}
		if !demoseed.Marked(e) {
			t.Fatalf("unmarked envelope %s", e.ID)
		}
		raw, _ := json.Marshal(e)
		for _, secret := range append(secrets, "-synthetic-") {
			if secret != "" && bytes.Contains(raw, []byte(secret)) {
				t.Fatalf("raw synthetic secret %q reached evidence: %s", secret, raw)
			}
		}
		kinds[e.Sensor.Kind]++
		classes[e.Classification]++
		summary, _, _ := evidenceindex.Project(e)
		if !summary.Synthetic {
			t.Fatalf("projection lost the synthetic marker for %s", e.ID)
		}
		address, err := netip.ParseAddr(summary.Source)
		if err != nil {
			t.Fatalf("source %q: %v", summary.Source, err)
		}
		inside := false
		for _, prefix := range documentation {
			inside = inside || prefix.Contains(address)
		}
		if !inside {
			t.Fatalf("source %s is outside documentation ranges", address)
		}
	}
	for _, kind := range []string{"http", "tcp", "mcp", "ssh", "correlation"} {
		if kinds[kind] == 0 {
			t.Fatalf("no %s evidence: %v", kind, kinds)
		}
	}
	if classes[event.ClassificationCanaryHit] == 0 || classes[event.ClassificationInteraction] == 0 {
		t.Fatalf("classes %v", classes)
	}

	index, err := evidenceindex.New(50000, observe.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range envelopes {
		index.Add(e)
	}
	snapshot := index.Analysis()
	sessions := evidenceview.Sessions("local", snapshot.Events)
	campaigns := evidenceview.Campaigns("local", sessions)
	rules := map[string]bool{}
	for _, e := range snapshot.Events {
		for _, id := range e.RuleIDs {
			rules[id] = true
		}
	}
	automated, multiSource := 0, 0
	for _, session := range sessions {
		if session.Automation.Assessment == "consistent_with_automation" {
			automated++
		}
	}
	for _, campaign := range campaigns.Campaigns {
		if campaign.SourceCount >= 3 {
			multiSource++
		}
	}
	for _, id := range []string{"HT-001", "AGT-001", "COR-005", "COR-007"} {
		if !rules[id] {
			t.Errorf("expected rule %s in seeded history; have %v", id, rules)
		}
	}
	if len(sessions) < 100 || automated == 0 || len(campaigns.Campaigns) < 3 || multiSource == 0 {
		t.Fatalf("sessions=%d automated=%d campaigns=%d multi-source=%d", len(sessions), automated, len(campaigns.Campaigns), multiSource)
	}
}

func TestGenerateIsDeterministic(t *testing.T) {
	cfg := demoConfig(t)
	first, a := generate(t, cfg, demoseed.Small)
	second, b := generate(t, cfg, demoseed.Small)
	if a != b || len(first) != len(second) {
		t.Fatalf("results differ: %+v vs %+v", a, b)
	}
	for i := range first {
		x, _ := json.Marshal(first[i])
		y, _ := json.Marshal(second[i])
		if !bytes.Equal(x, y) {
			t.Fatalf("envelope %d differs:\n%s\n%s", i, x, y)
		}
	}
}

func TestGenerateRejectsIncompleteConfig(t *testing.T) {
	cfg := demoConfig(t)
	cfg.Sensors = cfg.Sensors[:3]
	profile, _ := demoseed.Lookup(demoseed.Small)
	if _, err := demoseed.Generate(profile, cfg, anchor, func(event.Envelope) error { return nil }); err == nil {
		t.Fatal("expected an error without an ssh sensor")
	}
}

func TestMarkedRequiresExactTrue(t *testing.T) {
	for raw, want := range map[string]bool{
		`{"synthetic":true}`: true, `{"synthetic":false}`: false, `{"synthetic":"true"}`: false, `{}`: false, `[]`: false,
	} {
		if got := demoseed.Marked(event.Envelope{Observation: json.RawMessage(raw)}); got != want {
			t.Errorf("%s: got %t", raw, got)
		}
		summary, _, _ := evidenceindex.Project(event.Envelope{Observation: json.RawMessage(raw)})
		if summary.Synthetic != want {
			t.Errorf("projection %s: got %t", raw, summary.Synthetic)
		}
	}
}

func TestCountsDoNotDependOnAnchorOffset(t *testing.T) {
	cfg := demoConfig(t)
	profile, _ := demoseed.Lookup(demoseed.Small)
	var want demoseed.Result
	for i, at := range []time.Time{anchor, anchor.Add(1234567 * time.Microsecond), anchor.Add(37*time.Hour + 999*time.Microsecond)} {
		got, err := demoseed.Generate(profile, cfg, at, func(event.Envelope) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		got.Oldest, got.Newest = time.Time{}, time.Time{}
		if i == 0 {
			want = got
		} else if got != want {
			t.Fatalf("anchor %s: %+v, want %+v", at, got, want)
		}
	}
}
