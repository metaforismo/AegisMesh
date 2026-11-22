package digest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

func digestFixture() Input {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	events := []evidenceindex.Summary{}
	add := func(offset time.Duration, source string, rules ...string) {
		events = append(events, evidenceindex.Summary{
			ID:     fmt.Sprintf("%032x", len(events)+1),
			Time:   now.Add(offset).Format(time.RFC3339Nano),
			Source: source,
			Sensor: event.SensorRef{
				ID:   "web",
				Kind: "http",
			},
			Classification: "interaction",
			RuleIDs:        rules,
		})
	}
	add(-48*time.Hour, "previous-only", "PI-001")
	add(-24*time.Hour-time.Second, "returning", "PI-001")
	for i := 0; i < 8; i++ {
		add(-time.Hour+time.Duration(i)*time.Second, "returning", "HT-001")
	}
	add(-24*time.Hour, "new", "AGT-001")
	add(0, "excluded", "MCP-001")
	add(-48*time.Hour-time.Nanosecond, "excluded-old", "MCP-001")
	open := 2
	return Input{
		Window: "24h",
		AsOf:   now,
		Tenant: "default",
		Bounds: evidenceindex.Snapshot{
			Events: events,
			Index: evidenceindex.Stats{
				Events:   len(events),
				Capacity: 100,
				History:  "truncated",
			},
			Scanned: len(events),
			Limit:   8192,
		},
		OpenInvestigations: &open,
		Recommendations:    3,
	}
}

func TestDigestWindowsAndGoldens(t *testing.T) {
	in := digestFixture()
	report, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if report.Totals.Events != 9 || report.PreviousTotals.Events != 2 || report.NewSources != 1 || report.ReturningSources != 1 || report.AutomationSessions != 1 || report.HoneytokenHits != 8 || report.AgentCanaryHits != 1 || *report.OpenInvestigations != 2 || report.DryRunRecommendations != 3 {
		t.Fatalf("wrong comparison: %+v", report)
	}
	for _, m := range report.NewTechniques {
		if m.ID == "AML.T0051" {
			t.Fatal("returning technique marked new")
		}
	}
	if len(report.NewTechniques) == 0 || report.TopRules[0].Title == "" || report.Limits.History != "truncated" {
		t.Fatal("missing titles, relations or limits")
	}
	for _, format := range []string{"json", "md"} {
		body, err := Render(report, format)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join("testdata", "digest.golden."+format)
		if os.Getenv("AEGISMESH_UPDATE_DIGEST_GOLDENS") == "1" {
			if err := os.MkdirAll("testdata", 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(body, want) {
			t.Fatalf("golden drift %s: %v\n%s", format, err, body)
		}
		again, _ := Render(report, format)
		if !bytes.Equal(body, again) {
			t.Fatal("digest drift")
		}
	}
	in.Window = "7d"
	if report, err := Build(in); err != nil || report.Totals.Events != 12 {
		t.Fatal(report, err)
	}
	in.Window = "1h"
	if _, err := Build(in); err == nil {
		t.Fatal("accepted unsupported window")
	}
}
func TestDigestEmptyAndMarkdownNeutralisation(t *testing.T) {
	in := digestFixture()
	in.Bounds.Events = nil
	in.OpenInvestigations = nil
	report, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if report.Limits.InvestigationsAvailable || report.OpenInvestigations != nil || report.Totals.Events != 0 || len(report.NewTechniques) != 0 {
		t.Fatal(report)
	}
	report.TopRules = []evidenceindex.RuleCount{{Title: "```\n# FORGED <script>\u202e"}}
	body, _ := Render(report, "md")
	if strings.Contains(string(body), "\n# FORGED") || strings.Contains(string(body), "<script>") || strings.ContainsRune(string(body), '\u202e') {
		t.Fatal(string(body))
	}
	raw, _ := Render(report, "json")
	if !json.Valid(raw) {
		t.Fatal("invalid JSON")
	}
	if _, err := Render(report, "html"); err == nil {
		t.Fatal("unsupported output")
	}
}
