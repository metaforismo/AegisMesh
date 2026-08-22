// Actions and enforcement: this file turns detection findings into a single
// deterministic action per interaction, with explicit precedence.
//
// Action semantics (what each surface does is defined at the sensor):
//
//	observe  — record evidence only (default for benign traffic)
//	tag      — record evidence with findings attached; decoy behaves normally
//	throttle — rate-escalated tag: signaled interactions beyond the per-minute
//	           cap get throttled until the window resets
//	isolate  — keep engaging, but static responses ONLY: provider fallback is
//	           bypassed so flagged input never reaches an LLM
//	refuse   — answer a generic protocol-level refusal; no content processing
//	           beyond the bounded detection evaluation itself
//
// Precedence when several apply: refuse > throttle > isolate > tag > observe.
package policy

import (
	"sync"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/detect"
	"github.com/metaforismo/aegismesh/internal/observe"
)

type Action string

const (
	ActionObserve  Action = "observe"
	ActionTag      Action = "tag"
	ActionThrottle Action = "throttle"
	ActionIsolate  Action = "isolate"
	ActionRefuse   Action = "refuse"
)

var actionRank = map[Action]int{
	ActionObserve:  0,
	ActionTag:      1,
	ActionIsolate:  2,
	ActionThrottle: 3,
	ActionRefuse:   4,
}

// AtLeast returns the higher-precedence of two actions.
func AtLeast(a, b Action) Action {
	if actionRank[a] >= actionRank[b] {
		return a
	}
	return b
}

// Decision is the enforcer's verdict for one interaction. Findings are
// attached verbatim for the evidence pipeline; they carry static reasons only.
type Decision struct {
	Action   Action
	Findings []detect.Finding
}

const (
	defaultThrottlePerMinute = 600
	volumeWindowLen          = time.Minute
)

// Enforcer evaluates bounded inputs against the rule engine and maps the
// strongest finding's severity to its configured action. One Enforcer serves
// all sensors; volume accounting is per sensor ID (operator-configured
// strings, never attacker data).
type Enforcer struct {
	engine *detect.Engine
	bySev  map[detect.Severity]Action

	findings observe.LabeledCounter // label = stable rule id
	actionsC observe.LabeledCounter // label = action enum
	limit    int

	mu      sync.Mutex
	windows map[string]*volumeWindow
}

// NewEnforcer builds the shared enforcement layer from configuration. It
// always returns a usable engine: when detection is disabled every rule is
// inactive and all actions collapse to observe.
func NewEnforcer(det config.Detection, m observe.Meter) *Enforcer {
	opts := detect.Options{
		DisabledRules: det.DisabledRules,
		MaxInputBytes: det.MaxInputBytes,
	}
	if !det.IsEnabled() {
		opts.DisabledRules = detect.KnownRuleIDs()
	}
	actions := map[detect.Severity]Action{
		detect.SevInfo:   Action(det.Actions.Info),
		detect.SevLow:    Action(det.Actions.Low),
		detect.SevMedium: Action(det.Actions.Medium),
		detect.SevHigh:   Action(det.Actions.High),
	}
	if !det.IsEnabled() {
		for sev := range actions {
			actions[sev] = ActionObserve
		}
	} else {
		// Normalize anything unvalidated to observe: programmatic configs
		// that skipped the loader, or future enum drift, must fail toward
		// the safest behavior, never toward a garbage action string.
		valid := map[string]bool{}
		for _, a := range config.ValidActions {
			valid[a] = true
		}
		for sev, act := range actions {
			if !valid[string(act)] {
				actions[sev] = ActionObserve
			}
		}
	}
	limit := det.ThrottlePerMinute
	if limit <= 0 {
		limit = defaultThrottlePerMinute
	}
	return &Enforcer{
		engine:   detect.New(opts),
		bySev:    actions,
		findings: m.CounterVec("aegismesh_detect_findings_total", "detection rule hits", len(detect.KnownRuleIDs())),
		actionsC: m.CounterVec("aegismesh_policy_actions_total", "policy actions applied", len(config.ValidActions)),
		limit:    limit,
		windows:  map[string]*volumeWindow{},
	}
}

// EngineMaxInput reports the evaluation bound for callers that must truncate
// detector input before handing it over.
func (e *Enforcer) EngineMaxInput() int { return e.engine.MaxInputBytes() }

var severityRank = map[detect.Severity]int{
	detect.SevInfo: 0, detect.SevLow: 1, detect.SevMedium: 2, detect.SevHigh: 3,
}

// Evaluate runs detection and resolves one action. Deterministic per input;
// safe for concurrent use across sensors.
func (e *Enforcer) Evaluate(sensorID string, in detect.Input) Decision {
	findings := e.engine.Evaluate(in)
	action := ActionObserve
	top := -1
	for _, f := range findings {
		e.findings.Inc(string(f.RuleID))
		if r := severityRank[f.Severity]; r > top {
			top = r
			action = e.bySev[f.Severity]
		}
	}
	if action != ActionObserve && e.signaled(sensorID) > e.limit {
		action = AtLeast(action, ActionThrottle)
	}
	e.actionsC.Inc(string(action))
	return Decision{Action: action, Findings: findings}
}

// signaled counts this interaction toward the sensor's current minute window
// and returns the count including it.
func (e *Enforcer) signaled(sensorID string) int {
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	w := e.windows[sensorID]
	if w == nil || now.Sub(w.start) >= volumeWindowLen {
		// Bound the map by dropping windows idle for two full periods.
		if len(e.windows) > 2*64 {
			for id, old := range e.windows {
				if now.Sub(old.start) >= 2*volumeWindowLen {
					delete(e.windows, id)
				}
			}
		}
		w = &volumeWindow{start: now}
		e.windows[sensorID] = w
	}
	w.count++
	return w.count
}

type volumeWindow struct {
	start time.Time
	count int
}
