package evidenceview

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

var actorEpoch = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

// timed builds n HTTP interactions with the given successive gaps (cycled).
func timed(n int, gaps ...time.Duration) []interaction {
	out := []interaction{}
	at := actorEpoch
	for i := 0; i < n; i++ {
		if i > 0 {
			at = at.Add(gaps[(i-1)%len(gaps)])
		}
		out = append(out, interaction{at: at, kind: "http", sensor: "web", path: fmt.Sprintf("/p%d", i), status: 200})
	}
	return out
}

func rules(ids ...string) map[string]bool {
	out := map[string]bool{}
	for _, id := range ids {
		out[id] = true
	}
	return out
}

type signalCase struct {
	name  string
	items []interaction
	rules map[string]bool
	want  bool
}

func runSignal(t *testing.T, code string, fn func([]interaction, map[string]bool) ActorSignal, cases []signalCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(code+"/"+tc.name, func(t *testing.T) {
			got := fn(tc.items, tc.rules)
			if got.Code != code || got.Present != tc.want || got.Label == "" || got.Detail == "" {
				t.Fatalf("%+v, want present=%t", got, tc.want)
			}
			switch got.Strength {
			case StrengthStrong, StrengthModerate, StrengthWeak:
			default:
				t.Fatalf("strength %q", got.Strength)
			}
		})
	}
}

func TestSignalRegularCadence(t *testing.T) {
	runSignal(t, "regular_cadence", signalRegularCadence, []signalCase{
		{"too few", timed(7, 420*time.Millisecond), nil, false},
		{"constant", timed(8, 420*time.Millisecond), nil, true},
		{"one outlier", timed(9, 5*time.Second, 5*time.Second, 5*time.Second, 5*time.Second, 5*time.Second, 5*time.Second, 5*time.Second, time.Minute), nil, true},
		{"two outliers", timed(9, 5*time.Second, 5*time.Second, 5*time.Second, time.Minute, 5*time.Second, 5*time.Second, 5*time.Second, time.Minute), nil, false},
		{"too slow", timed(8, 31*time.Second), nil, false},
		{"COR-005 alone", timed(2, time.Second), rules("COR-005"), true},
	})
}

func TestSignalSubSecondBursts(t *testing.T) {
	runSignal(t, "sub_second_bursts", signalSubSecondBursts, []signalCase{
		{"too few", timed(7, time.Millisecond), nil, false},
		{"fast", timed(8, 999*time.Millisecond), nil, true},
		{"exactly one second", timed(8, time.Second), nil, false},
	})
}

func TestSignalRulePredicates(t *testing.T) {
	runSignal(t, "agent_canary_followed", signalAgentCanary, []signalCase{
		{"absent", nil, rules("HT-001"), false}, {"present", nil, rules("AGT-001"), true},
	})
	runSignal(t, "honeytoken_replayed", signalHoneytokenReplay, []signalCase{
		{"absent", nil, rules("AGT-001"), false}, {"HT-001", nil, rules("HT-001"), true}, {"COR-008", nil, rules("COR-008"), true},
	})
	runSignal(t, "multi_surface_sweep", signalMultiSurfaceSweep, []signalCase{
		{"absent", nil, rules("COR-005"), false}, {"COR-002", nil, rules("COR-002"), true}, {"COR-006", nil, rules("COR-006"), true},
	})
}

func mcpCalls(methods ...string) []interaction {
	out := []interaction{}
	for i, m := range methods {
		method, tool, _ := strings.Cut(m, " ")
		out = append(out, interaction{at: actorEpoch.Add(time.Duration(i) * time.Second), kind: "mcp", method: method, tool: tool})
	}
	return out
}

func TestSignalToolChaining(t *testing.T) {
	runSignal(t, "tool_call_chaining", signalToolChaining, []signalCase{
		{"chain after discovery", mcpCalls("initialize", "tools/list", "tools/call list_files", "tools/call read_file", "tools/call read_file"), nil, true},
		{"no discovery", mcpCalls("tools/call list_files", "tools/call read_file", "tools/call read_file"), nil, false},
		{"one call per tool sweep", mcpCalls("tools/list", "tools/call a", "tools/call b", "tools/call c"), nil, false},
		{"single tool repeated", mcpCalls("tools/list", "tools/call a", "tools/call a", "tools/call a"), nil, false},
		{"too few calls", mcpCalls("tools/list", "tools/call a", "tools/call b"), nil, false},
		{"discovery after calls", mcpCalls("tools/call a", "tools/list", "tools/call b", "tools/call b"), nil, false},
	})
}

func TestSignalSDKClient(t *testing.T) {
	sdk := timed(2, time.Second)
	sdk[1].client = evidenceindex.ClientOpenAISDK
	curl := timed(2, time.Second)
	curl[0].client = evidenceindex.ClientCLI
	runSignal(t, "sdk_client_family", signalSDKClient, []signalCase{
		{"sdk", sdk, nil, true}, {"curl", curl, nil, false}, {"none", timed(2, time.Second), nil, false},
	})
}

func TestSignalAdaptiveAfterError(t *testing.T) {
	corrected := timed(3, 2*time.Second)
	corrected[0].status, corrected[1].path = 422, corrected[0].path
	slow := timed(3, 4*time.Second)
	slow[0].status, slow[1].path = 422, slow[0].path
	notFound := timed(3, time.Second)
	notFound[0].status, notFound[1].path = 404, notFound[0].path
	otherSensor := timed(3, time.Second)
	otherSensor[0].status, otherSensor[1].path, otherSensor[1].sensor = 400, otherSensor[0].path, "other"
	stillFailing := timed(3, time.Second)
	stillFailing[0].status, stillFailing[1].path, stillFailing[1].status = 405, stillFailing[0].path, 405
	runSignal(t, "adaptive_after_error", signalAdaptiveAfterError, []signalCase{
		{"corrected fast", corrected, nil, true},
		{"too slow", slow, nil, false},
		{"404 is not request-shape error", notFound, nil, false},
		{"different sensor", otherSensor, nil, false},
		{"retry still failing", stillFailing, nil, false},
	})
}

func TestSignalHumanThinkTime(t *testing.T) {
	irregular := []time.Duration{3 * time.Second, 11 * time.Second, 5 * time.Second, 40 * time.Second, 7 * time.Second, 2 * time.Second, 19 * time.Second}
	runSignal(t, "human_think_time", signalHumanThinkTime, []signalCase{
		{"irregular multi-second", timed(8, irregular...), nil, true},
		{"too few", timed(7, irregular...), nil, false},
		{"regular multi-second", timed(8, 5*time.Second), nil, false},
		{"fast", timed(8, 100*time.Millisecond, 3*time.Second), nil, false},
		{"very slow", timed(8, 5*time.Minute, 10*time.Minute), nil, false},
	})
}

func TestSignalTypoCorrections(t *testing.T) {
	pair := func(first, second string, status int, gap time.Duration) []interaction {
		return []interaction{
			{at: actorEpoch, kind: "http", sensor: "web", path: first, status: status},
			{at: actorEpoch.Add(gap), kind: "http", sensor: "web", path: second, status: 200},
		}
	}
	runSignal(t, "typo_corrections", signalTypoCorrections, []signalCase{
		{"transposition", pair("/v1/modles", "/v1/models", 404, 4*time.Second), nil, true},
		{"machine speed", pair("/v1/modles", "/v1/models", 404, 100*time.Millisecond), nil, false},
		{"not 404", pair("/v1/modles", "/v1/models", 200, 4*time.Second), nil, false},
		{"different resource", pair("/v1/models", "/api/tags", 404, 4*time.Second), nil, false},
		{"short path", pair("/ab", "/ba", 404, 4*time.Second), nil, false},
	})
}

func TestEditDistanceBound(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{{"kitten", "sitting", 3}, {"abc", "abc", 0}, {"abc", "abd", 1}, {"abcdef", "a", 3}, {"é", "e", 1}} {
		if got := editDistance(tc.a, tc.b, 2); got != min(tc.want, 3) {
			t.Fatalf("%q %q = %d", tc.a, tc.b, got)
		}
	}
}

func TestActorRule(t *testing.T) {
	for _, tc := range []struct {
		name    string
		n       int
		present []string
		want    string
	}{
		{"canary with few events", 3, []string{"agent_canary_followed"}, AssessmentAgent},
		{"canary below agent minimum", 2, []string{"agent_canary_followed"}, AssessmentInconclusive},
		{"chaining beats cadence", 20, []string{"tool_call_chaining", "regular_cadence"}, AssessmentAgent},
		{"fast regular only automated", 20, []string{"regular_cadence", "sub_second_bursts"}, AssessmentAutomated},
		{"sdk only automated", 20, []string{"sdk_client_family"}, AssessmentAutomated},
		{"replay is not agent evidence", 20, []string{"honeytoken_replayed", "multi_surface_sweep"}, AssessmentInconclusive},
		{"few events", 7, []string{"regular_cadence"}, AssessmentInconclusive},
		{"human", 9, []string{"human_think_time"}, AssessmentHuman},
		{"typo human", 9, []string{"typo_corrections"}, AssessmentHuman},
		{"conflict", 9, []string{"human_think_time", "sub_second_bursts"}, AssessmentInconclusive},
		{"absence is not human", 30, nil, AssessmentInconclusive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			present := map[string]bool{}
			for _, code := range tc.present {
				present[code] = true
			}
			got, summary := actorRule(tc.n, present)
			if got != tc.want || summary == "" {
				t.Fatalf("%s: %q", got, summary)
			}
			for _, word := range []string{"certain", "confirmed", "definitely", "is an AI"} {
				if strings.Contains(summary, word) {
					t.Fatalf("unhedged summary %q", summary)
				}
			}
		})
	}
}

func TestSessionActorListsEverySignal(t *testing.T) {
	events := []evidenceindex.Summary{}
	for i := 0; i < 8; i++ {
		e := sample(i, time.Duration(i)*300*time.Millisecond)
		e.Summary = "GET /v1/models → 200"
		e.HTTPStatus = 200
		events = append(events, e)
	}
	signal := sample(9, 3*time.Second)
	signal.Classification = event.ClassificationCorrelationSignal
	signal.RuleIDs = []string{"COR-005"}
	session := Sessions("t", append(events, signal))[0]
	if len(session.Actor.Signals) != 10 || session.Actor.Assessment != AssessmentAutomated {
		t.Fatalf("%+v", session.Actor)
	}
	codes := []string{}
	for _, s := range session.Actor.Signals {
		codes = append(codes, s.Code)
	}
	want := "regular_cadence,sub_second_bursts,agent_canary_followed,honeytoken_replayed,tool_call_chaining,sdk_client_family,adaptive_after_error,human_think_time,typo_corrections,multi_surface_sweep"
	if strings.Join(codes, ",") != want {
		t.Fatal(codes)
	}
	if session.Automation.Assessment != "consistent_with_automation" {
		t.Fatal("existing automation field changed")
	}
}
