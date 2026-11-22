package evidenceview

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

// Actor assessment vocabulary. Each is a hedged observation, never attribution.
const (
	AssessmentAgent        = "possibly_ai_agent"
	AssessmentAutomated    = "likely_automated"
	AssessmentHuman        = "likely_human"
	AssessmentInconclusive = "inconclusive"
)

// Signal strengths.
const (
	StrengthStrong   = "strong"
	StrengthModerate = "moderate"
	StrengthWeak     = "weak"
)

// Actor thresholds. They are documented, with caveats, in
// docs/ai-threat-detection.md#actor-profile; change both together.
const (
	// MinActorEvents is the interaction count below which timing-based
	// assessments (likely_automated, likely_human) are not made.
	MinActorEvents = 8
	// MinAgentEvents is the interaction count below which possibly_ai_agent is not made.
	MinAgentEvents = 3
	// RegularMaxMedian is the largest median gap still considered a cadence.
	RegularMaxMedian = 30 * time.Second
	// RegularTolerance is the relative distance from the median that keeps a gap regular.
	RegularTolerance = 0.25
	// RegularMaxOutliers is how many gaps may fall outside the tolerance.
	RegularMaxOutliers = 1
	// SubSecondMedian is the median gap below which bursts are reported.
	SubSecondMedian = time.Second
	// ThinkMinMedian and ThinkMaxMedian bound human think-time medians.
	ThinkMinMedian = 2 * time.Second
	ThinkMaxMedian = 2 * time.Minute
	// ThinkMaxRegularity is the largest regular-gap fraction still called irregular.
	ThinkMaxRegularity = 0.5
	// ThinkMaxFastShare is the largest share of sub-second gaps allowed for think time.
	ThinkMaxFastShare = 0.25
	// AdaptiveMaxGap is the longest delay between a decoy request error and the
	// corrected request on the same endpoint that still counts as adaptive.
	AdaptiveMaxGap = 3 * time.Second
	// AdaptiveLookahead is how many following interactions are checked for the correction.
	AdaptiveLookahead = 3
	// TypoMaxDistance is the largest path edit distance treated as a correction.
	TypoMaxDistance = 2
	// TypoMinPathRunes ignores very short paths where any edit is a different resource.
	TypoMinPathRunes = 4
	// TypoMinGap and TypoMaxGap bound the delay of a typed correction.
	TypoMinGap = time.Second
	TypoMaxGap = time.Minute
	// ToolChainMinCalls is the minimum number of MCP tools/call events for chaining.
	ToolChainMinCalls = 3
)

// ActorSignal is one evaluated predicate. Present=false means it was evaluated
// on the retained events and not observed.
type ActorSignal struct {
	Code     string `json:"code"`
	Label    string `json:"label"`
	Strength string `json:"strength"`
	Present  bool   `json:"present"`
	Detail   string `json:"detail"`
}

// Actor is a hedged behavioural assessment with every evaluated signal.
type Actor struct {
	Assessment string        `json:"assessment"`
	Summary    string        `json:"summary"`
	Signals    []ActorSignal `json:"signals"`
}

// adaptiveStatuses are decoy responses that describe a malformed request
// (not a missing resource), so a fast corrected retry implies reading them.
var adaptiveStatuses = map[int]bool{400: true, 405: true, 415: true, 422: true}

type gapStats struct {
	count      int
	median     time.Duration
	outliers   int
	regularity float64
	fastShare  float64
}

func gaps(items []interaction) gapStats {
	if len(items) < 2 {
		return gapStats{}
	}
	values := make([]time.Duration, 0, len(items)-1)
	for i := 1; i < len(items); i++ {
		values = append(values, max(0, items[i].at.Sub(items[i-1].at)))
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	s := gapStats{count: len(values), median: values[len(values)/2]}
	fast := 0
	for _, gap := range values {
		if math.Abs(float64(gap-s.median)) > RegularTolerance*float64(s.median) {
			s.outliers++
		}
		if gap < time.Second {
			fast++
		}
	}
	s.regularity = float64(s.count-s.outliers) / float64(s.count)
	s.fastShare = float64(fast) / float64(s.count)
	return s
}

func ms(d time.Duration) string { return fmt.Sprintf("%d ms", d.Milliseconds()) }

// signalRegularCadence: near-constant inter-request gaps, or COR-005.
func signalRegularCadence(items []interaction, rules map[string]bool) ActorSignal {
	s := ActorSignal{Code: "regular_cadence", Label: "Requests arrive at a near-constant interval", Strength: StrengthModerate}
	g := gaps(items)
	if len(items) < MinActorEvents {
		s.Detail = fmt.Sprintf("%d interactions; at least %d needed", len(items), MinActorEvents)
	} else {
		s.Detail = fmt.Sprintf("median gap %s, %d outlier(s) of %d", ms(g.median), g.outliers, g.count)
		s.Present = g.median <= RegularMaxMedian && g.outliers <= RegularMaxOutliers
	}
	if rules["COR-005"] {
		s.Present = true
		s.Detail += "; COR-005 fired"
	}
	return s
}

// signalSubSecondBursts: upper-median inter-request gap below one second.
func signalSubSecondBursts(items []interaction, _ map[string]bool) ActorSignal {
	s := ActorSignal{Code: "sub_second_bursts", Label: "Most requests follow the previous one in under a second", Strength: StrengthModerate}
	if len(items) < MinActorEvents {
		s.Detail = fmt.Sprintf("%d interactions; at least %d needed", len(items), MinActorEvents)
		return s
	}
	g := gaps(items)
	s.Present = g.median < SubSecondMedian
	s.Detail = fmt.Sprintf("median gap %s over %d gaps", ms(g.median), g.count)
	return s
}

// signalAgentCanary: AGT-001, an agent-instruction marker from decoy content came back.
func signalAgentCanary(_ []interaction, rules map[string]bool) ActorSignal {
	s := ActorSignal{Code: "agent_canary_followed", Label: "An instruction planted for AI agents was followed", Strength: StrengthStrong, Present: rules["AGT-001"]}
	s.Detail = "AGT-001 not observed"
	if s.Present {
		s.Detail = "AGT-001 observed; a person copying the marker would look the same"
	}
	return s
}

// signalHoneytokenReplay: HT-001 or COR-008, a decoy credential was presented.
func signalHoneytokenReplay(_ []interaction, rules map[string]bool) ActorSignal {
	s := ActorSignal{Code: "honeytoken_replayed", Label: "A decoy credential was presented back", Strength: StrengthModerate}
	found := []string{}
	for _, id := range []string{"HT-001", "COR-008"} {
		if rules[id] {
			found = append(found, id)
		}
	}
	s.Present = len(found) > 0
	s.Detail = "HT-001 and COR-008 not observed"
	if s.Present {
		s.Detail = strings.Join(found, ", ") + " observed"
	}
	return s
}

// signalToolChaining: MCP tool discovery followed by several calls that reuse
// at least one tool, unlike a one-call-per-tool sweep.
func signalToolChaining(items []interaction, _ map[string]bool) ActorSignal {
	s := ActorSignal{Code: "tool_call_chaining", Label: "MCP tools were discovered and then called in a chain", Strength: StrengthStrong}
	discovered, calls := false, 0
	distinct := map[string]bool{}
	for _, item := range items {
		if item.kind != "mcp" {
			continue
		}
		if item.method == "tools/list" && calls == 0 {
			discovered = true
		}
		if item.method == "tools/call" && item.tool != "" {
			calls++
			distinct[item.tool] = true
		}
	}
	s.Present = discovered && calls >= ToolChainMinCalls && len(distinct) >= 2 && calls > len(distinct)
	s.Detail = fmt.Sprintf("%d tool call(s) across %d tool(s); tools/list before first call: %t", calls, len(distinct), discovered)
	return s
}

// signalSDKClient: an HTTP User-Agent self-identified as an LLM SDK or agent framework.
func signalSDKClient(items []interaction, _ map[string]bool) ActorSignal {
	s := ActorSignal{Code: "sdk_client_family", Label: "The client identified itself as an LLM SDK or agent framework", Strength: StrengthModerate}
	families := map[string]bool{}
	for _, item := range items {
		if evidenceindex.SDKClient(item.client) {
			families[item.client] = true
		}
	}
	s.Present = len(families) > 0
	s.Detail = "no SDK or agent-framework User-Agent among HTTP requests"
	if s.Present {
		s.Detail = "self-reported " + strings.Join(keys(families), ", ") + " (User-Agent is client-controlled)"
	}
	return s
}

// signalAdaptiveAfterError: a request-shape error from the decoy (400/405/415/422)
// followed within AdaptiveMaxGap by a successful request to the same path.
func signalAdaptiveAfterError(items []interaction, _ map[string]bool) ActorSignal {
	s := ActorSignal{Code: "adaptive_after_error", Label: "A rejected request was corrected within seconds", Strength: StrengthStrong}
	count := 0
	for i, item := range items {
		if item.kind != "http" || !adaptiveStatuses[item.status] {
			continue
		}
		for _, next := range items[i+1 : min(len(items), i+1+AdaptiveLookahead)] {
			if next.kind == "http" && next.sensor == item.sensor && next.path == item.path &&
				next.status >= 200 && next.status < 300 && next.at.Sub(item.at) <= AdaptiveMaxGap {
				count++
				break
			}
		}
	}
	s.Present = count > 0
	s.Detail = fmt.Sprintf("%d error(s) corrected on the same path within %s", count, AdaptiveMaxGap)
	return s
}

// signalHumanThinkTime: irregular, multi-second pauses with few sub-second gaps.
func signalHumanThinkTime(items []interaction, _ map[string]bool) ActorSignal {
	s := ActorSignal{Code: "human_think_time", Label: "Pauses between requests are irregular and several seconds long", Strength: StrengthModerate}
	if len(items) < MinActorEvents {
		s.Detail = fmt.Sprintf("%d interactions; at least %d needed", len(items), MinActorEvents)
		return s
	}
	g := gaps(items)
	s.Present = g.median >= ThinkMinMedian && g.median <= ThinkMaxMedian && g.regularity <= ThinkMaxRegularity && g.fastShare <= ThinkMaxFastShare
	s.Detail = fmt.Sprintf("median gap %s, %.0f%% of gaps near the median, %.0f%% under 1 s", ms(g.median), 100*g.regularity, 100*g.fastShare)
	return s
}

// signalTypoCorrections: a 404 followed after a typing-speed pause by a path
// within TypoMaxDistance edits on the same sensor.
func signalTypoCorrections(items []interaction, _ map[string]bool) ActorSignal {
	s := ActorSignal{Code: "typo_corrections", Label: "A not-found path was retried with a small spelling change", Strength: StrengthModerate}
	count := 0
	for i := 1; i < len(items); i++ {
		prev, next := items[i-1], items[i]
		gap := next.at.Sub(prev.at)
		if prev.kind != "http" || next.kind != "http" || prev.sensor != next.sensor || prev.status != 404 ||
			gap < TypoMinGap || gap > TypoMaxGap || prev.path == next.path ||
			len([]rune(prev.path)) < TypoMinPathRunes || len([]rune(next.path)) < TypoMinPathRunes {
			continue
		}
		if editDistance(prev.path, next.path, TypoMaxDistance) <= TypoMaxDistance {
			count++
		}
	}
	s.Present = count > 0
	s.Detail = fmt.Sprintf("%d near-identical retry(ies) after a 404, %s..%s later", count, TypoMinGap, TypoMaxGap)
	return s
}

// signalMultiSurfaceSweep: COR-002 or COR-006, several protocols or AI families touched.
func signalMultiSurfaceSweep(_ []interaction, rules map[string]bool) ActorSignal {
	s := ActorSignal{Code: "multi_surface_sweep", Label: "Several decoy protocols or AI API families were probed", Strength: StrengthWeak}
	found := []string{}
	for _, id := range []string{"COR-002", "COR-006"} {
		if rules[id] {
			found = append(found, id)
		}
	}
	s.Present = len(found) > 0
	s.Detail = "COR-002 and COR-006 not observed"
	if s.Present {
		s.Detail = strings.Join(found, ", ") + " observed"
	}
	return s
}

// editDistance returns the Levenshtein distance, or limit+1 once it exceeds limit.
// Inputs are bounded (128 runes) by the projection.
func editDistance(a, b string, limit int) int {
	x, y := []rune(a), []rune(b)
	if d := len(x) - len(y); d > limit || -d > limit {
		return limit + 1
	}
	prev := make([]int, len(y)+1)
	cur := make([]int, len(y)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(x); i++ {
		cur[0] = i
		best := cur[0]
		for j := 1; j <= len(y); j++ {
			cost := 1
			if x[i-1] == y[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			best = min(best, cur[j])
		}
		if best > limit {
			return limit + 1
		}
		prev, cur = cur, prev
	}
	return prev[len(y)]
}

var actorSignals = []func([]interaction, map[string]bool) ActorSignal{
	signalRegularCadence, signalSubSecondBursts, signalAgentCanary, signalHoneytokenReplay,
	signalToolChaining, signalSDKClient, signalAdaptiveAfterError, signalHumanThinkTime,
	signalTypoCorrections, signalMultiSurfaceSweep,
}

// assessActor evaluates every signal in fixed order and applies the documented rule.
func assessActor(items []interaction, rules map[string]bool) Actor {
	a := Actor{Signals: make([]ActorSignal, 0, len(actorSignals))}
	present := map[string]bool{}
	for _, evaluate := range actorSignals {
		signal := evaluate(items, rules)
		a.Signals = append(a.Signals, signal)
		present[signal.Code] = signal.Present
	}
	a.Assessment, a.Summary = actorRule(len(items), present)
	return a
}

// actorRule is the documented decision table over present signal codes.
func actorRule(n int, present map[string]bool) (string, string) {
	agent := []string{}
	for _, code := range []string{"agent_canary_followed", "tool_call_chaining", "adaptive_after_error"} {
		if present[code] {
			agent = append(agent, code)
		}
	}
	automated := present["regular_cadence"] || present["sub_second_bursts"] || present["sdk_client_family"]
	human := present["human_think_time"] || present["typo_corrections"]
	switch {
	case len(agent) > 0 && n >= MinAgentEvents:
		return AssessmentAgent, "Behaviour is consistent with an AI agent or LLM-driven tool (" + strings.Join(agent, ", ") + "); this is an observation, not attribution."
	case n < MinActorEvents:
		return AssessmentInconclusive, fmt.Sprintf("Only %d interaction(s) retained; at least %d are needed before timing is assessed.", n, MinActorEvents)
	case automated && human:
		return AssessmentInconclusive, "Automation and human-like signals are both present; no assessment is made."
	case automated:
		return AssessmentAutomated, "Timing or client signals suggest scripted or automated traffic; this does not establish whether an AI model was involved."
	case human:
		return AssessmentHuman, "Irregular pauses or corrections suggest a person may have been interacting; proxies, NAT or deliberate jitter can look the same."
	}
	return AssessmentInconclusive, "No automation or human signal was observed in the retained events; no assessment is made."
}
