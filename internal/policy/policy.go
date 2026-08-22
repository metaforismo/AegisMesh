// Package policy is the response gate: every byte a sensor sends back to an
// attacker must come from a validated static rule or from provider output that
// passed through this package's untrusted-output pipeline.
package policy

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/detect"
	"github.com/metaforismo/aegismesh/internal/llm"
	"github.com/metaforismo/aegismesh/internal/redact"
)

// Source records where a response came from, for the evidence trail.
type Source string

const (
	SourceStatic   Source = "static"
	SourceProvider Source = "provider"
)

// HTTPDecision is what the HTTP sensor should answer.
type HTTPDecision struct {
	Status  int
	Headers map[string]string
	Body    []byte
	RuleID  string
	From    Source

	// Detection carries the enforcement verdict for this interaction; always
	// non-nil when an Enforcer was provided to the gate (which Build
	// guarantees).
	Detection Decision
}

// TCPDecision is one line the TCP sensor should answer with.
type TCPDecision struct {
	Response  []byte
	RuleID    string
	From      Source
	Detection Decision
}

// HTTPGate resolves HTTP requests against compiled rules.
type HTTPGate struct {
	sensorID string
	rules    []compiledHTTPRule
	fallback *fallbackRunner
	persona  config.HTTPPersona
	enf      *Enforcer
}

type compiledHTTPRule struct {
	cfg  config.HTTPRule
	re   *regexp.Regexp
	body []byte
}

func NewHTTPGate(c config.Sensor, resolveBodyFile func(string) ([]byte, error), prov llm.Provider, enf *Enforcer) (*HTTPGate, error) {
	if enf == nil {
		return nil, fmt.Errorf("policy: http sensor %q: nil enforcer", c.ID)
	}
	if len(c.Rules) == 0 {
		return nil, fmt.Errorf("policy: http sensor %q has no rules", c.ID)
	}
	g := &HTTPGate{
		sensorID: c.ID,
		persona:  *c.Persona,
		enf:      enf,
	}
	for _, r := range c.Rules {
		re, err := regexp.Compile(r.PathRegex)
		if err != nil {
			return nil, fmt.Errorf("policy: http sensor %q rule %q: %v", c.ID, r.Name, err)
		}
		cr := compiledHTTPRule{cfg: r, re: re}
		if r.BodyFile != "" {
			b, err := resolveBodyFile(r.BodyFile)
			if err != nil {
				return nil, fmt.Errorf("policy: http sensor %q rule %q: %v", c.ID, r.Name, err)
			}
			cr.body = b
		} else {
			cr.body = []byte(r.Body)
		}
		g.rules = append(g.rules, cr)
	}
	if c.Fallback != nil && c.Fallback.Enabled {
		g.fallback = newFallback(prov, c.Fallback.SystemPrompt, c.Fallback.MaxReplyChars, c.ID)
	}
	return g, nil
}

// Resolve returns the decision for method+path. Product semantics, in order:
//
//  0. Detection runs first over the bounded interaction (method, path, body
//     prefix). refuse answers a generic 403 without consulting rules or the
//     provider; isolate/throttle keep serving but force static-only content
//     (provider fallback bypassed so flagged input never reaches an LLM).
//  1. The first rule whose regex matches the path AND whose method list
//     permits the method (or is empty, i.e. any-method) answers. A methods-
//     less catch-all rule therefore legitimately shadows the 405 and fallback
//     behaviors below — that is what "catch-all" means, and operators who
//     want method-specific replies must not install one over those paths.
//  2. Otherwise, if at least one rule matched the path but rejected the
//     method, answer 405 with an Allow header naming every configured
//     method for that path — a real origin server's behavior, which decoys
//     should imitate.
//  3. Otherwise (path matched nothing), use the LLM fallback when enabled
//     AND detection did not demand isolation.
//  4. Finally, a generic builtin 404.
//
// GET does not implicitly include HEAD; configure each method explicitly.
func (g *HTTPGate) Resolve(ctx context.Context, method, path string, body []byte) (HTTPDecision, error) {
	det := g.enf.Evaluate(g.sensorID, detect.Input{
		Text:       BoundedDetectInput(method+" "+path+" "+string(body), g.enf.EngineMaxInput()),
		TotalBytes: len(method) + len(path) + len(body),
	})
	static := func(status int, extra map[string]string, bodyText, ruleID string) HTTPDecision {
		hdrs := map[string]string{"Server": g.persona.ServerHeader}
		for k, v := range extra {
			hdrs[k] = v
		}
		return HTTPDecision{
			Status: status, Headers: hdrs, Body: []byte(bodyText),
			RuleID: ruleID, From: SourceStatic, Detection: det,
		}
	}

	pathOnly := path
	if i := strings.IndexByte(pathOnly, '?'); i >= 0 {
		pathOnly = pathOnly[:i]
	}
	if det.Action == ActionRefuse {
		// Generic refusal takes precedence over everything: no decoy persona
		// detail beyond the Server header, no provider call, nothing
		// attacker-supplied echoed back.
		return static(403, nil, "Request refused.\n", "policy:refused"), nil
	}
	var allow []string
	for _, r := range g.rules {
		if !r.re.MatchString(pathOnly) {
			continue
		}
		if len(r.cfg.Methods) > 0 && !containsFold(r.cfg.Methods, method) {
			allow = append(allow, r.cfg.Methods...)
			continue
		}
		return static(r.cfg.Status, r.cfg.Headers, string(r.body), ruleName(r.cfg.Name)), nil
	}
	if len(allow) > 0 { // path exists, wrong verb: answer like a real server would
		return static(405, map[string]string{"Allow": strings.Join(allow, ", ")}, "", "builtin:method-not-allowed"), nil
	}
	switch det.Action {
	case ActionIsolate, ActionThrottle:
		// Isolation keeps the surface alive with a neutral static page instead
		// of provider text: flagged input never reaches an LLM.
		return static(200, map[string]string{"Content-Type": "text/html; charset=utf-8"},
			"<html><body>OK</body></html>", "policy:isolated"), nil
	default:
		if g.fallback != nil {
			text, via, err := g.fallback.respond(ctx, method+" "+path+" "+string(body))
			if err == nil {
				return HTTPDecision{
					Status:    200,
					Headers:   map[string]string{"Server": g.persona.ServerHeader, "Content-Type": "text/html; charset=utf-8"},
					Body:      []byte(text),
					RuleID:    via,
					From:      SourceProvider,
					Detection: det,
				}, nil
			}
		}
	}
	// No rule and no (or failing) fallback: generic 404. Never leak internals.
	return static(404, nil, "", "builtin:not-found"), nil
}

// BoundedDetectInput truncates detector input to the engine's evaluation
// bound; TotalBytes carried separately lets RES-001 fire on overflow. Every
// sensor funnels its raw interaction through this before evaluation so the
// engine's work is bounded regardless of upstream caps.
func BoundedDetectInput(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max]
}

// TCPGate resolves TCP lines against compiled rules.
type TCPGate struct {
	sensorID string
	rules    []compiledTCPRule
	enf      *Enforcer
}

type compiledTCPRule struct {
	cfg config.TCPRule
	re  *regexp.Regexp
}

func NewTCPGate(c config.Sensor, enf *Enforcer) (*TCPGate, error) {
	if enf == nil {
		return nil, fmt.Errorf("policy: tcp sensor %q: nil enforcer", c.ID)
	}
	g := &TCPGate{sensorID: c.ID, enf: enf}
	for _, r := range c.TCPResponseRule {
		re, err := regexp.Compile(r.LineRegex)
		if err != nil {
			return nil, fmt.Errorf("policy: tcp sensor %q rule %q: %v", c.ID, r.Name, err)
		}
		g.rules = append(g.rules, compiledTCPRule{cfg: r, re: re})
	}
	return g, nil
}

// Resolve answers one line. Detection runs first: refuse sends a generic
// protocol error without consulting rules; isolate/throttle keep rule-based
// static responses (TCP rules are already static — only the provider path is
// forbidden, and TCP has none) with the action recorded for evidence.
func (g *TCPGate) Resolve(line string) TCPDecision {
	det := g.enf.Evaluate(g.sensorID, detect.Input{
		Text:       BoundedDetectInput(line, g.enf.EngineMaxInput()),
		TotalBytes: len(line),
	})
	if det.Action == ActionRefuse {
		return TCPDecision{
			Response:  []byte("-ERR request refused\r\n"),
			RuleID:    "policy:refused",
			From:      SourceStatic,
			Detection: det,
		}
	}
	for _, r := range g.rules {
		if r.re.MatchString(line) {
			resp := r.cfg.Response
			if !strings.HasSuffix(resp, "\n") {
				resp += "\n"
			}
			return TCPDecision{Response: []byte(resp), RuleID: ruleName(r.cfg.Name), From: SourceStatic, Detection: det}
		}
	}
	return TCPDecision{
		Response:  []byte("-ERR unknown command\n"),
		RuleID:    "builtin:unknown-command",
		From:      SourceStatic,
		Detection: det,
	}
}

// fallbackRunner funnels provider calls through the untrusted-output pipeline:
// input is scrubbed and bounded; output is scrubbed, bounded, and can only
// become response text.
type fallbackRunner struct {
	prov       llm.Provider
	prompt     string
	maxChars   int
	sensorName string
}

func newFallback(p llm.Provider, prompt string, maxChars int, sensorName string) *fallbackRunner {
	if maxChars <= 0 {
		maxChars = 2048
	}
	return &fallbackRunner{prov: p, prompt: prompt, maxChars: maxChars, sensorName: sensorName}
}

const maxFallbackInputBytes = 8 << 10

func (f *fallbackRunner) respond(ctx context.Context, userInput string) (string, string, error) {
	in := redact.Scrub(userInput)
	if len(in) > maxFallbackInputBytes {
		in = in[:maxFallbackInputBytes]
	}
	req := llm.Request{
		SystemPrompt: f.prompt,
		Messages:     []llm.Message{{Role: "user", Content: in}},
		MaxChars:     f.maxChars,
	}
	resp, err := f.prov.Complete(ctx, req)
	if err != nil {
		return "", "", fmt.Errorf("provider %s: %w", f.prov.Name(), err)
	}
	out := redact.Scrub(resp.Text)
	if len(out) > f.maxChars {
		out = out[:f.maxChars]
	}
	via := fmt.Sprintf("llm:%s/%s", resp.Provider, resp.Model)
	return out, via, nil
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

func ruleName(name string) string {
	if name == "" {
		return "unnamed-rule"
	}
	return name
}
