// Package llm defines the response-provider seam (ADR-0005) and ships a fully
// local deterministic provider so demos and tests need no network or API key.
//
// SECURITY INVARIANT: everything a Provider returns is untrusted data. Callers
// must route it through the same redaction and size caps as attacker input;
// it must never influence exec, paths, configuration, or enforcement.
package llm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Message is one turn of a decoy conversation.
type Message struct {
	Role    string // "system" | "user" | "assistant"
	Content string
}

// Request bounds what callers may send to any provider.
type Request struct {
	SystemPrompt string
	Messages     []Message
	MaxChars     int
}

// Response carries provider text plus metadata for the audit trail.
type Response struct {
	Text          string
	Provider      string
	Model         string
	LatencyMS     int64
	Deterministic bool
}

// Provider generates decoy response text.
//
// CONTEXT CONTRACT: the ctx argument governs blocking work only — network
// calls, retries, queueing. Implementations that perform no blocking work
// (e.g. Local, a pure function) must NOT consult ctx and must not fail merely
// because it is already cancelled; callers get an answer whenever one can be
// produced for free. Remote adapters honor cancellation and deadlines,
// returning ctx.Err() when interrupted.
type Provider interface {
	Name() string
	Complete(ctx context.Context, req Request) (Response, error)
}

// Local is the deterministic offline provider. It selects among canned
// persona-consistent replies using a hash of the conversation, so identical
// inputs always produce identical outputs — reproducible evidence, zero egress,
// no model to run.
type Local struct{}

var _ Provider = Local{}

func (Local) Name() string { return "local-deterministic" }

const maxInputMessages = 32

var cannedReplies = []string{
	"<div class=\"panel\"><h2>Build Queue</h2><table><tr><th>Job</th><th>Status</th></tr><tr><td>nightly-142</td><td>queued</td></tr><tr><td>release-98</td><td>running</td></tr></table><p class=\"muted\">Auto-refresh in 60s</p></div>",
	"<div class=\"notice\">Session expired. <a href=\"/login\">Sign in again</a> to continue.</div>",
	"<pre>cache: OK\nworkers: 4/4 alive\nqueue depth: 2\nlast deploy: 3d ago</pre>",
	"<div class=\"panel\"><h2>Maintenance</h2><p>Scheduled maintenance window opens Sunday 02:00 UTC. Some pages will be read-only.</p></div>",
	"<div class=\"error\">Permission denied for this operation. Contact an administrator if you believe this is a mistake.</div>",
	"<pre>dmesg tail:\n[ ok ] started periodic command scheduler\n[ warn] disk usage on /var at 71%\n[ info] ntp synchronized</pre>",
}

// Complete deterministically picks a reply. It is a pure function of its
// inputs: no network, no clock-derived randomness, no global state. The
// context is accepted for interface compatibility but nothing here can be
// interrupted because there is no I/O.
func (Local) Complete(_ context.Context, req Request) (Response, error) {
	start := time.Now()
	if len(req.Messages) > maxInputMessages {
		req.Messages = req.Messages[:maxInputMessages]
	}
	var sb strings.Builder
	sb.WriteString(req.SystemPrompt)
	for _, m := range req.Messages {
		sb.WriteByte(0)
		sb.WriteString(m.Role)
		sb.WriteByte(1)
		sb.WriteString(m.Content)
	}
	sum := sha256.Sum256([]byte(sb.String()))
	idx := int(binary.BigEndian.Uint16(sum[:2]) % uint16(len(cannedReplies))) //nolint:gosec // selection index, not security
	text := cannedReplies[idx]
	max := req.MaxChars
	if max <= 0 || max > 16384 {
		max = 2048
	}
	if len(text) > max {
		text = text[:max]
	}
	return Response{
		Text:          text,
		Provider:      "local-deterministic",
		Model:         "canned-v1",
		LatencyMS:     time.Since(start).Milliseconds(),
		Deterministic: true,
	}, nil
}

// ErrNoAPIKey keeps credentialed remote construction fail closed rather than
// silently falling back to local behavior.
var ErrNoAPIKey = fmt.Errorf("llm: remote provider requested but AEGISMESH_LLM_API_KEY is not set")
