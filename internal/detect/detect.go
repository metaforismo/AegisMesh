// Package detect is the deterministic prompt-injection and abuse detection
// engine. It evaluates bounded text captured at decoy boundaries and emits
// findings that are SIGNALS, not proof: every rule matches patterns that also
// occur in benign traffic, so findings raise attention and shape responses —
// they never assert attacker intent on their own.
//
// Invariants:
//
//   - Deterministic: identical input produces identical findings in identical
//     order. No randomness, no clocks, no global state.
//   - Evidence-safe: Reason strings are static rule-authored text. Matched
//     content is NEVER echoed into findings; raw payloads live only in the
//     redacted observation pipeline.
//   - Fail-open by design: Evaluate returns no error. A rule that cannot run
//     degrades to silence, never to blocking decoy operation. Availability of
//     the deception surface outranks detection completeness.
package detect

import (
	"fmt"
	"regexp"
	"strings"
)

// RuleID values are stable identifiers published in operator documentation.
// Never renumber or repurpose one; add a new ID instead.
type RuleID string

const (
	RuleDirectInjection RuleID = "PI-001"  // explicit instruction-overriding phrasing
	RuleHiddenPayload   RuleID = "PI-002"  // zero-width / unicode-tag / ANSI smuggling
	RuleSecretExfil     RuleID = "EXF-001" // requests to disclose or relay secrets
	RuleToolEscalation  RuleID = "ESC-001" // pushes toward tool/command invocation authority
	RuleEncodedPayload  RuleID = "OBS-001" // large encoded blobs, double encoding
	RuleExcessInput     RuleID = "RES-001" // interaction exceeds evaluation bounds
)

// KnownRuleIDs lists every rule this engine can emit, for config validation.
func KnownRuleIDs() []string {
	return []string{
		string(RuleDirectInjection),
		string(RuleHiddenPayload),
		string(RuleSecretExfil),
		string(RuleToolEscalation),
		string(RuleEncodedPayload),
		string(RuleExcessInput),
	}
}

// ValidateRuleIDs reports unknown IDs with actionable context. Used by config
// validation so a typo cannot silently disable nothing.
func ValidateRuleIDs(ids []string) error {
	known := map[string]bool{}
	for _, id := range KnownRuleIDs() {
		known[id] = true
	}
	for _, id := range ids {
		if !known[id] {
			return fmt.Errorf("unknown detection rule id %q (known: %s)", id, strings.Join(KnownRuleIDs(), ", "))
		}
	}
	return nil
}

type Severity string

const (
	SevInfo   Severity = "info"
	SevLow    Severity = "low"
	SevMedium Severity = "medium"
	SevHigh   Severity = "high"
)

type Confidence string

const (
	ConfLow    Confidence = "low"
	ConfMedium Confidence = "medium"
	ConfHigh   Confidence = "high"
)

// Finding is one rule hit. It describes the WHY in fixed operator-facing
// language; it never quotes the matched text.
type Finding struct {
	RuleID     RuleID     `json:"rule_id"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	Reason     string     `json:"reason"`
}

// Input carries one bounded interaction for evaluation.
//
// Text must already be truncated by the caller to MaxInputBytes (the runtime
// passes redaction-friendly previews); TotalBytes is the ORIGINAL size of the
// interaction so RES-001 can fire on overflow even though the engine never
// sees the excess bytes.
type Input struct {
	Text       string
	TotalBytes int
}

// Options tunes an Engine. Zero-value fields mean defaults.
type Options struct {
	DisabledRules []string
	MaxInputBytes int // 0 selects DefaultMaxInputBytes
}

const DefaultMaxInputBytes = 8 << 10

// Hard ceiling independent of configuration: the engine refuses to scan more
// than this regardless of options, bounding worst-case regex work per call.
const hardMaxScanBytes = 64 << 10

// rule pairs compiled patterns with immutable metadata.
type rule struct {
	id         RuleID
	severity   Severity
	confidence Confidence
	reason     string
	match      func(in Input, lower string) bool
}

// Engine evaluates inputs against its active rules.
type Engine struct {
	rules    []rule
	maxInput int
}

// New builds an engine. Disabled rules are removed entirely rather than
// stubbed, keeping evaluation cost proportional to what remains.
func New(opts Options) *Engine {
	maxIn := opts.MaxInputBytes
	if maxIn <= 0 {
		maxIn = DefaultMaxInputBytes
	}
	if maxIn > hardMaxScanBytes {
		maxIn = hardMaxScanBytes
	}
	disabled := map[string]bool{}
	for _, id := range opts.DisabledRules {
		disabled[id] = true
	}
	var active []rule
	for _, r := range allRules(maxIn) {
		if !disabled[string(r.id)] {
			active = append(active, r)
		}
	}
	return &Engine{rules: active, maxInput: maxIn}
}

// MaxInputBytes reports the configured evaluation bound.
func (e *Engine) MaxInputBytes() int { return e.maxInput }

// Evaluate runs every active rule in registration order. Findings are stable:
// same input, same order, no deduplication needed because each rule fires at
// most once per call (patterns are existence checks, not counters).
func (e *Engine) Evaluate(in Input) []Finding {
	var out []Finding
	text := in.Text
	if len(text) > hardMaxScanBytes {
		text = text[:hardMaxScanBytes]
	}
	lower := strings.ToLower(text)
	for _, r := range e.rules {
		if r.match(Input{Text: text, TotalBytes: in.TotalBytes}, lower) {
			out = append(out, Finding{
				RuleID:     r.id,
				Severity:   r.severity,
				Confidence: r.confidence,
				Reason:     r.reason,
			})
		}
	}
	return out
}

var (
	// Direct instruction-override phrasing. Deliberately conservative: each
	// pattern requires imperative verbs plus instruction nouns so ordinary
	// prose ("read the instructions") does not trip it.
	directInjectionRe = regexp.MustCompile(
		`(?i)\b(ignore|disregard|override|forget|bypass)[^\n]{0,24}\b(all |any |your |the |previous |prior |above |earlier )*(instructions?|prompts?|guardrails?|constraints?|rules?|system message)` +
			`|[^\n]{0,16}\b(reveal|repeat|print|output|show|spell)[^\n]{0,20}(your )?(system )?(prompt|instructions?|initial (message|prompt)|hidden (prompt|instructions))`)
)

// hiddenPayloadRe detects characters used to smuggle instructions past visual
// inspection: the Unicode tag block (ASCII smuggling), zero-width and
// direction-control formatting characters, and ANSI escape sequences.
var hiddenPayloadRe = regexp.MustCompile(`\x1b\[[0-9;]{2,8}[A-Za-z]`)

func hasTagBlock(s string) bool {
	for _, r := range s {
		if r >= 0xE0000 && r <= 0xE007F {
			return true
		}
	}
	return false
}

func hasZeroWidthControls(s string) bool {
	const n = 3 // a lone ZWSP is noise; several are a channel
	count := 0
	for _, r := range s {
		switch {
		case r >= 0x200B && r <= 0x200F, // zero-width space..RLM
			r == 0x2060, // word joiner
			r == 0xFEFF: // BOM mid-text
			count++
			if count >= n {
				return true
			}
		}
	}
	return false
}

var (
	exfilTargetsRe = regexp.MustCompile(
		`(?i)\b(printenv|environ\b|\.ssh[/\\]|id_rsa|id_ed25519|authorized_keys|\.aws[/\\]|credentials(\.json|\.db)?\b|\.netrc|\.npmrc|\.docker/config\.json|/etc/(passwd|shadow)\b|wallet\.dat|\.git-credentials)` +
			`|\b(environment variable[s]?|api[_ ]?keys?|secret[s]?|passwords?|tokens?|private keys?)\b[^\n]{0,48}\b(send|post|upload|forward|exfiltrat\w*|paste|relay|webhook|curl|fetch)\b` +
			`|\b(send|post|upload|forward|exfiltrat\w*|relay)[^\n]{0,48}\b(environment variable[s]?|api[_ ]?keys?|secret[s]?|passwords?|tokens?|private keys?)\b`)

	escalationRe = regexp.MustCompile(
		`(?i)\b(call|use|invoke|run|execute)[^\n]{0,32}\b(admin|root|sudo|shell|exec|debug|maintenance|restricted|internal|privileged)[ _-]?(tool|command|function|mode|api|endpoint)s?\b` +
			`|"method"\s*:\s*"tools/call"|'method'\s*:\s*'tools/call'` +
			`|\btools/call\b[^\n]{0,40}"(aegis_|admin_|exec_|shell_)`)

	base64RunRe  = regexp.MustCompile(`[A-Za-z0-9+/]{96,}={0,2}`)
	hexRunRe     = regexp.MustCompile(`(?:[0-9a-fA-F]{2}){96,}`)
	doubleEncRe  = regexp.MustCompile(`(?:%25[0-9a-fA-F]{2}){3,}`)
	unicodeEscRe = regexp.MustCompile(`(?:\\u00(?:4[1-9a-fA-F]|5[0-9a-fA-F])){12,}`)
)

// excessiveInputThreshold returns the closure-captured bound as a match func.
func excessiveInputThreshold(max int) func(Input, string) bool {
	return func(in Input, _ string) bool { return in.TotalBytes > max }
}

func allRules(maxInput int) []rule {
	return []rule{
		{
			id:         RuleDirectInjection,
			severity:   SevHigh,
			confidence: ConfMedium,
			reason:     "instruction-override phrasing directed at an automated agent",
			match:      func(in Input, lower string) bool { return directInjectionRe.MatchString(lower) },
		},
		{
			id:         RuleHiddenPayload,
			severity:   SevHigh,
			confidence: ConfMedium,
			reason:     "hidden-channel characters present (unicode tag block, zero-width controls, or ANSI escapes)",
			match: func(in Input, _ string) bool {
				return hasTagBlock(in.Text) || hasZeroWidthControls(in.Text) || hiddenPayloadRe.MatchString(in.Text)
			},
		},
		{
			id:         RuleSecretExfil,
			severity:   SevHigh,
			confidence: ConfMedium,
			reason:     "request pattern consistent with credential/environment disclosure or exfiltration",
			match:      func(in Input, lower string) bool { return exfilTargetsRe.MatchString(lower) },
		},
		{
			id:         RuleToolEscalation,
			severity:   SevMedium,
			confidence: ConfLow,
			reason:     "phrasing steering toward privileged tool or command invocation",
			match:      func(in Input, lower string) bool { return escalationRe.MatchString(lower) },
		},
		{
			id:         RuleEncodedPayload,
			severity:   SevLow,
			confidence: ConfMedium,
			reason:     "large encoded blob or repeated double-encoding markers",
			match: func(in Input, _ string) bool {
				s := in.Text
				if base64RunRe.MatchString(s) || hexRunRe.MatchString(s) ||
					doubleEncRe.MatchString(s) || unicodeEscRe.MatchString(s) {
					return true
				}
				return false
			},
		},
		{
			id:         RuleExcessInput,
			severity:   SevInfo,
			confidence: ConfHigh,
			reason:     "interaction exceeded the detection evaluation bound",
			match:      excessiveInputThreshold(maxInput),
		},
	}
}
