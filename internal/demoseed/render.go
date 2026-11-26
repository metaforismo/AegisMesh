package demoseed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"sort"
	"strings"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/correlate"
	"github.com/metaforismo/aegismesh/internal/detect"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/llm"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/policy"
	"github.com/metaforismo/aegismesh/internal/redact"
)

// Result counts what Generate emitted.
type Result struct {
	// Profile is the generated profile name.
	Profile string `json:"profile"`
	// Events counts sensor observations (exactly Profile.Events).
	Events int `json:"events"`
	// Signals counts correlation signals derived by the correlation engine.
	Signals int `json:"signals"`
	// Sources counts distinct synthetic peer addresses.
	Sources int `json:"sources"`
	// Oldest and Newest bound the generated observation times.
	Oldest time.Time `json:"oldest"`
	Newest time.Time `json:"newest"`
}

// sensors resolves the demo's one sensor per kind.
type sensors struct {
	http, tcp, mcp, ssh config.Sensor
}

func demoSensors(cfg *config.Config) (sensors, error) {
	var out sensors
	found := map[string]bool{}
	for _, sensor := range cfg.Sensors {
		switch sensor.Kind {
		case config.SensorKindHTTP:
			out.http = sensor
		case config.SensorKindTCP:
			out.tcp = sensor
		case config.SensorKindMCP:
			out.mcp = sensor
		case config.SensorKindSSH:
			out.ssh = sensor
		default:
			continue
		}
		if found[sensor.Kind] {
			return sensors{}, fmt.Errorf("demoseed: more than one %s sensor", sensor.Kind)
		}
		found[sensor.Kind] = true
	}
	if len(found) != 4 {
		return sensors{}, errors.New("demoseed: the demo configuration must have exactly one http, tcp, mcp and ssh sensor")
	}
	return out, nil
}

// renderer converts planned steps into evidence with the live helpers.
type renderer struct {
	cfg     *config.Config
	sensors sensors
	enf     *policy.Enforcer
	http    *policy.HTTPGate
	tcp     *policy.TCPGate
	ids     *rand.Rand
	seq     uint64
	mcp     map[int]*mcpState
}

type mcpState struct {
	step  int
	tools []string
}

// Generate emits a profile's synthetic history in time order through emit,
// each correlation signal one millisecond after its triggering observation
// (as the live adapter appends it shortly after), ending at least two minutes
// before anchor. The same profile, anchor and configuration always produce
// byte-identical envelopes; counts do not depend on the anchor at all.
func Generate(profile Profile, cfg *config.Config, anchor time.Time, emit func(event.Envelope) error) (Result, error) {
	if cfg == nil || emit == nil {
		return Result{}, errors.New("demoseed: configuration and emit are required")
	}
	if profile.Events < 1 || profile.Span < time.Hour || profile.Templates < 1 {
		return Result{}, errors.New("demoseed: invalid profile")
	}
	found, err := demoSensors(cfg)
	if err != nil {
		return Result{}, err
	}
	detection := cfg.Detection
	// Volume throttling is a wall-clock live-traffic control. Generated history
	// is evaluated in a burst, so the per-minute escalation is disabled here to
	// keep recorded actions a deterministic function of the findings.
	detection.ThrottlePerMinute = math.MaxInt32
	enf := policy.NewEnforcer(detection, observe.NewRegistry(), cfg.Honeytokens...)
	httpGate, err := policy.NewHTTPGate(found.http, func(string) ([]byte, error) {
		return nil, errors.New("demoseed: body files are not used")
	}, llm.Local{}, enf)
	if err != nil {
		return Result{}, fmt.Errorf("demoseed: http gate: %w", err)
	}
	tcpGate, err := policy.NewTCPGate(found.tcp, enf)
	if err != nil {
		return Result{}, fmt.Errorf("demoseed: tcp gate: %w", err)
	}

	anchor = anchor.UTC()
	plan := &planner{rng: rand.New(rand.NewPCG(profile.Seed, 0x6165_6769_736d)), anchor: anchor, span: profile.Span}
	for _, token := range cfg.Honeytokens {
		plan.tokens = append(plan.tokens, token.Value)
	}
	plan.buildTemplates(profile.Templates)
	var steps []step
	for len(steps) < profile.Events {
		actor := plan.next()
		steps = append(steps, actor[:min(len(actor), profile.Events-len(steps))]...)
	}
	sort.SliceStable(steps, func(i, j int) bool {
		if !steps[i].at.Equal(steps[j].at) {
			return steps[i].at.Before(steps[j].at)
		}
		if steps[i].actor != steps[j].actor {
			return steps[i].actor < steps[j].actor
		}
		return steps[i].index < steps[j].index
	})

	r := &renderer{
		cfg: cfg, sensors: found, enf: enf, http: httpGate, tcp: tcpGate,
		ids: rand.New(rand.NewPCG(profile.Seed, 0x6964_7300)), mcp: map[int]*mcpState{},
	}
	corrOpts := correlate.Options{
		Window:              time.Duration(cfg.Correlation.WindowSeconds) * time.Second,
		AutomationThreshold: cfg.Correlation.AutomationThreshold,
		CredentialThreshold: cfg.Correlation.CredentialThreshold,
		PerSourceEvents:     cfg.Correlation.PerSourceEvents,
		MaxSources:          cfg.Correlation.MaxSources,
		Now:                 func() time.Time { return anchor },
	}
	for _, id := range cfg.Correlation.DisabledRules {
		corrOpts.DisabledRules = append(corrOpts.DisabledRules, correlate.RuleID(id))
	}
	engine := correlate.New(corrOpts)
	correlationOn := cfg.Correlation.IsEnabled()

	out := Result{Profile: profile.Name}
	sources := map[string]bool{}
	for _, s := range steps {
		envelope, auth, err := r.render(s)
		if err != nil {
			return Result{}, err
		}
		if err := emit(envelope); err != nil {
			return Result{}, err
		}
		out.Events++
		sources[s.source] = true
		if out.Oldest.IsZero() {
			out.Oldest = envelope.Time
		}
		out.Newest = envelope.Time
		if !correlationOn {
			continue
		}
		for _, signal := range engine.Ingest(correlateEvent(envelope, s, auth)) {
			signalEnvelope, err := r.signal(signal)
			if err != nil {
				return Result{}, err
			}
			if err := emit(signalEnvelope); err != nil {
				return Result{}, err
			}
			out.Signals++
		}
	}
	out.Sources = len(sources)
	return out, nil
}

func (r *renderer) envelope(at time.Time, ref event.SensorRef, class string, observation any, rules []string) (event.Envelope, error) {
	raw, err := json.Marshal(observation)
	if err != nil {
		return event.Envelope{}, fmt.Errorf("demoseed: encode observation: %w", err)
	}
	var id [16]byte
	for i := 0; i < len(id); i += 8 {
		value := r.ids.Uint64()
		for j := range 8 {
			id[i+j] = byte(value >> (8 * j))
		}
	}
	r.seq++
	envelope := event.Envelope{
		Schema:         event.SchemaV1,
		ID:             hex.EncodeToString(id[:]),
		Time:           at.UTC(),
		Seq:            r.seq,
		Instance:       r.cfg.Runtime.InstanceName,
		Sensor:         ref,
		Classification: class,
		Redaction:      event.RedactionRecord{Rules: rules},
		Integrity:      event.Integrity{PayloadSHA256: event.SHA256Hex(raw), Algorithm: "sha256"},
		Observation:    raw,
	}
	return envelope, envelope.Validate()
}

func ref(sensor config.Sensor) event.SensorRef {
	return event.SensorRef{ID: sensor.ID, Kind: sensor.Kind, Listen: sensor.Listen}
}

// detection mirrors the sensors' evidence block: absent without findings.
type detection struct {
	Action   string           `json:"action"`
	Findings []detect.Finding `json:"findings,omitempty"`
}

func detectionOf(decision policy.Decision) *detection {
	if len(decision.Findings) == 0 {
		return nil
	}
	return &detection{Action: string(decision.Action), Findings: decision.Findings}
}

// Observation shapes repeat the sensors' field names and order, with the
// synthetic marker appended. The marker is set only by this package.
type httpObservation struct {
	Method            string            `json:"method"`
	Path              string            `json:"path"`
	QueryRedacted     bool              `json:"query_redacted"`
	QueryLength       int               `json:"query_length,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
	Proto             string            `json:"proto"`
	UserAgent         string            `json:"user_agent,omitempty"`
	RemoteHost        string            `json:"remote_host"`
	BodyCapturedBytes int               `json:"body_captured_bytes"`
	BodyTruncated     bool              `json:"body_truncated,omitempty"`
	BodyPreview       string            `json:"body_preview,omitempty"`
	BodySHA256        string            `json:"body_sha256"`
	DurationMS        int64             `json:"duration_ms"`
	Response          struct {
		RuleID string `json:"rule_id"`
		Via    string `json:"via"`
		Status int    `json:"status"`
	} `json:"response"`
	Detection *detection `json:"detection,omitempty"`
	Synthetic bool       `json:"synthetic"`
}

type tcpObservation struct {
	LinesExchanged    int    `json:"lines_exchanged"`
	BytesTotal        int    `json:"bytes_total"`
	LastLineLen       int    `json:"last_line_len"`
	LastLineSHA256    string `json:"last_line_sha256"`
	LastLinePreview   string `json:"last_line_preview,omitempty"`
	LastLineTruncated bool   `json:"last_line_truncated,omitempty"`
	RemoteHost        string `json:"remote_host"`
	Response          struct {
		RuleID       string `json:"rule_id"`
		Via          string `json:"via"`
		ReplyPreview string `json:"reply_preview,omitempty"`
	} `json:"response"`
	Detection *detection `json:"detection,omitempty"`
	Synthetic bool       `json:"synthetic"`
}

type mcpObservation struct {
	Step          int      `json:"step,omitempty"`
	ToolSequence  []string `json:"tool_sequence,omitempty"`
	Method        string   `json:"method"`
	ToolName      string   `json:"tool_name,omitempty"`
	ArgsLength    int      `json:"args_length,omitempty"`
	ArgsTruncated bool     `json:"args_truncated,omitempty"`
	ArgsPreview   string   `json:"args_preview,omitempty"`
	ArgsSHA256    string   `json:"args_sha256,omitempty"`
	RemoteHost    string   `json:"remote_host,omitempty"`
	Response      struct {
		RuleID   string `json:"rule_id,omitempty"`
		Rejected bool   `json:"rejected,omitempty"`
		Status   int    `json:"status,omitempty"`
	} `json:"response"`
	Detection *detection `json:"detection,omitempty"`
	Synthetic bool       `json:"synthetic"`
}

type sshObservation struct {
	Detection            *detection `json:"detection,omitempty"`
	Outcome              string     `json:"outcome"`
	Authenticated        bool       `json:"authenticated"`
	AuthMethod           string     `json:"auth_method,omitempty"`
	LastAuthMethod       string     `json:"last_auth_method,omitempty"`
	AuthAttempts         int        `json:"auth_attempts,omitempty"`
	AuthFailures         int        `json:"auth_failures,omitempty"`
	UsernameBytes        int        `json:"username_bytes,omitempty"`
	PasswordBytes        int        `json:"password_bytes,omitempty"`
	ClientVersionPreview string     `json:"client_version_preview,omitempty"`
	RemoteHost           string     `json:"remote_host,omitempty"`
	DurationMS           int64      `json:"duration_ms"`
	Synthetic            bool       `json:"synthetic"`
}

type signalObservation struct {
	RuleID         string   `json:"rule_id"`
	Summary        string   `json:"summary"`
	SourceKey      string   `json:"source_key"`
	SourceEventIDs []string `json:"source_event_ids"`
	Truncated      bool     `json:"truncated"`
	Synthetic      bool     `json:"synthetic"`
}

// render returns the envelope and the memory-only credential digests the
// correlation engine uses for distinctness; digests are never serialized.
func (r *renderer) render(s step) (event.Envelope, []string, error) {
	switch s.kind {
	case "http":
		return r.renderHTTP(s)
	case "tcp":
		envelope, err := r.renderTCP(s)
		return envelope, nil, err
	case "mcp":
		envelope, err := r.renderMCP(s)
		return envelope, nil, err
	case "ssh":
		return r.renderSSH(s)
	}
	return event.Envelope{}, nil, fmt.Errorf("demoseed: unknown step kind %q", s.kind)
}

func (r *renderer) renderHTTP(s step) (event.Envelope, []string, error) {
	type header struct{ name, value string }
	headers := []header{{"User-Agent", s.userAgent}, {"Accept", "*/*"}}
	if s.body != "" {
		headers = append(headers, header{"Content-Type", "application/json"})
	}
	if s.authorization != "" {
		headers = append(headers, header{"Authorization", s.authorization})
	}
	if s.apiKey != "" {
		headers = append(headers, header{"X-Api-Key", s.apiKey})
	}
	selected := map[string][]string{"host": {"127.0.0.1"}}
	for _, h := range headers {
		selected[strings.ToLower(h.name)] = []string{h.value}
	}
	decision, err := r.http.Resolve(context.Background(), s.method, s.path, []byte(s.body), selected)
	if err != nil {
		return event.Envelope{}, nil, fmt.Errorf("demoseed: http decision: %w", err)
	}

	policyHeaders := redact.DefaultHeaderPolicy()
	obs := httpObservation{
		Method: r.enf.Scrub(s.method), Path: r.enf.Scrub(s.path), Proto: "HTTP/1.1",
		Headers: map[string]string{}, RemoteHost: s.source, BodyCapturedBytes: len(s.body),
		DurationMS: int64(len(s.path) % 3), Detection: detectionOf(decision.Detection), Synthetic: true,
	}
	for _, h := range headers {
		value := h.value
		if policyHeaders.KeepValue[strings.ToLower(h.name)] {
			value = r.enf.Scrub(value)
		}
		obs.Headers[r.enf.Scrub(h.name)] = policyHeaders.Header(h.name, value)
	}
	obs.UserAgent = policyHeaders.Header("User-Agent", r.enf.Scrub(s.userAgent))
	if len(obs.UserAgent) > 160 {
		obs.UserAgent = obs.UserAgent[:160]
	}
	var previewTruncated bool
	obs.BodyPreview, previewTruncated = redact.Preview([]byte(r.enf.Scrub(s.body)), redact.MaxPreviewBytes)
	obs.BodyTruncated = previewTruncated
	sum := sha256.Sum256([]byte(s.body))
	obs.BodySHA256 = hex.EncodeToString(sum[:])
	obs.Response.RuleID, obs.Response.Via, obs.Response.Status = decision.RuleID, string(decision.From), decision.Status

	rules := []string{"header_values_policy", "honeytoken_scrub"}
	if obs.BodyPreview != "" {
		rules = append(rules, "credential_scrub")
	}
	if obs.BodyTruncated {
		rules = append(rules, "preview_truncated")
	}
	envelope, err := r.envelope(s.at, ref(r.sensors.http), event.ClassificationInteraction, obs, rules)
	return envelope, redact.HTTPAuthAttempts(selected), err
}

func (r *renderer) renderTCP(s step) (event.Envelope, error) {
	var decision policy.TCPDecision
	bytes := 0
	for _, line := range s.lines {
		decision = r.tcp.Resolve(line)
		bytes += len(line) + 1
	}
	last := s.lines[len(s.lines)-1]
	obs := tcpObservation{
		LinesExchanged: len(s.lines), BytesTotal: bytes, LastLineLen: len(last),
		RemoteHost: s.source, Detection: detectionOf(decision.Detection), Synthetic: true,
	}
	sum := sha256.Sum256([]byte(last))
	obs.LastLineSHA256 = hex.EncodeToString(sum[:])
	obs.LastLinePreview, obs.LastLineTruncated = redact.Preview([]byte(r.enf.Scrub(last)), redact.MaxPreviewBytes)
	obs.Response.RuleID, obs.Response.Via = decision.RuleID, string(decision.From)
	obs.Response.ReplyPreview, _ = redact.Preview([]byte(r.enf.Scrub(string(decision.Response))), 128)
	rules := []string{"credential_scrub", "honeytoken_scrub"}
	if obs.LastLineTruncated {
		rules = append(rules, "preview_truncated")
	}
	return r.envelope(s.at, ref(r.sensors.tcp), event.ClassificationInteraction, obs, rules)
}

func (r *renderer) renderMCP(s step) (event.Envelope, error) {
	state := r.mcp[s.actor]
	if state == nil {
		state = &mcpState{}
		r.mcp[s.actor] = state
	}
	state.step++
	if s.rpc == "tools/call" && len(state.tools) < 32 {
		state.tools = append(state.tools, r.enf.Scrub(s.tool))
	}
	params := ""
	if s.rpc == "tools/call" {
		params = fmt.Sprintf(`{"name":%q,"arguments":%s}`, s.tool, s.args)
	}
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":%q`, state.step, s.rpc)
	if params != "" {
		body += `,"params":` + params
	}
	body += "}"
	environment := r.sensors.mcp.Environment
	environmental := false
	if environment != nil {
		for _, name := range config.MCPEnvironmentTools() {
			environmental = environmental || s.tool == name
		}
	}
	secret := environmental && (s.tool == "get_env" || s.tool == "read_file" && strings.Contains(s.args, ".env"))
	decision := r.enf.Evaluate(r.sensors.mcp.ID, detect.Input{
		MCPSecretRead: secret,
		MCPDepth:      environment != nil && state.step >= environment.DepthThreshold,
		Text:          policy.BoundedDetectInput(s.rpc+" "+params, r.enf.EngineMaxInput()),
		TotalBytes:    len(s.rpc) + len(params),
		Protocol:      "mcp", Method: "POST", Path: r.sensors.mcp.MCPPath,
		RawParts: []string{"POST", r.sensors.mcp.MCPPath, "127.0.0.1", body, "Content-Type", "application/json"},
		Headers:  map[string][]string{"content-type": {"application/json"}, "host": {"127.0.0.1"}},
	})
	obs := mcpObservation{
		Step: state.step, ToolSequence: append([]string(nil), state.tools...), RemoteHost: s.source,
		Detection: detectionOf(decision), Synthetic: true,
	}
	if environment == nil {
		obs.Step, obs.ToolSequence = 0, nil
	}
	if s.rpc != "tools/call" || decision.Action == policy.ActionRefuse {
		obs.Method = r.enf.Scrub(s.rpc)
		return r.envelope(s.at, ref(r.sensors.mcp), event.ClassificationInteraction, obs, []string{"honeytoken_scrub"})
	}
	obs.Method, obs.ToolName, obs.ArgsLength = "tools/call", r.enf.Scrub(s.tool), len(s.args)
	obs.ArgsPreview, obs.ArgsTruncated = redact.Preview([]byte(r.enf.Scrub(s.args)), redact.MaxPreviewBytes)
	sum := sha256.Sum256([]byte(s.args))
	obs.ArgsSHA256 = hex.EncodeToString(sum[:])
	switch {
	case environmental:
		obs.Response.RuleID = "environment"
	case r.configuredTool(s.tool):
		obs.Response.RuleID = s.tool
	default:
		obs.Response.RuleID, obs.Response.Rejected = "unknown-tool", true
	}
	rules := []string{"credential_scrub", "honeytoken_scrub"}
	if obs.ArgsTruncated {
		rules = append(rules, "preview_truncated")
	}
	return r.envelope(s.at, ref(r.sensors.mcp), event.ClassificationCanaryHit, obs, rules)
}

func (r *renderer) configuredTool(name string) bool {
	for _, tool := range r.sensors.mcp.Tools {
		if tool.Name == name {
			return true
		}
	}
	return false
}

func (r *renderer) renderSSH(s step) (event.Envelope, []string, error) {
	var decision *policy.Decision
	digests := []string{}
	for i, user := range s.users {
		password := s.passwords[i]
		d := r.enf.Evaluate(r.sensors.ssh.ID, detect.Input{RawParts: []string{user, password}, Headers: map[string][]string{"x-api-key": {password}}})
		digests = append(digests, redact.AuthDigest("password", user, password))
		if decision == nil {
			decision = &d
			continue
		}
		for _, finding := range d.Findings {
			seen := false
			for _, old := range decision.Findings {
				seen = seen || old == finding
			}
			if !seen {
				decision.Findings = append(decision.Findings, finding)
			}
		}
	}
	obs := sshObservation{
		Outcome: "authentication_failed", AuthMethod: "password", LastAuthMethod: "password",
		AuthAttempts: len(s.users), AuthFailures: len(s.users),
		UsernameBytes: len(s.users[len(s.users)-1]), PasswordBytes: len(s.passwords[len(s.passwords)-1]),
		RemoteHost: s.source, DurationMS: int64(40 * len(s.users)), Synthetic: true,
	}
	if decision != nil {
		obs.Detection = detectionOf(*decision)
	}
	obs.ClientVersionPreview, _ = redact.Preview([]byte(r.enf.Scrub(s.clientVersion)), 255)
	rules := []string{"honeytoken_scrub", "username_content_dropped", "credential_content_dropped", "request_payload_dropped", "channel_payload_dropped"}
	envelope, err := r.envelope(s.at, ref(r.sensors.ssh), event.ClassificationInteraction, obs, rules)
	return envelope, digests, err
}

// correlateEvent maps generated evidence onto the engine's view exactly as the
// runtime adapter maps live evidence.
func correlateEvent(envelope event.Envelope, s step, auth []string) correlate.Event {
	var probe struct {
		ToolName  string `json:"tool_name"`
		Detection *struct {
			Findings []struct {
				RuleID   string          `json:"rule_id"`
				AIFamily detect.AIFamily `json:"ai_family,omitempty"`
			} `json:"findings"`
		} `json:"detection"`
	}
	_ = json.Unmarshal(envelope.Observation, &probe)
	out := correlate.Event{
		ID: envelope.ID, Time: envelope.Time, SourceKey: s.source, AuthAttempts: auth,
		SensorID: envelope.Sensor.ID, SensorKind: envelope.Sensor.Kind,
		Classification: envelope.Classification, ToolName: probe.ToolName,
	}
	if probe.Detection != nil {
		for _, finding := range probe.Detection.Findings {
			if finding.RuleID == "LLM-001" {
				out.AIFamily = finding.AIFamily
			}
			if finding.RuleID != "" {
				out.FindingIDs = append(out.FindingIDs, finding.RuleID)
			}
		}
	}
	return out
}

// signal persists a fired correlation signal the way the runtime adapter does,
// one millisecond after its triggering observation.
func (r *renderer) signal(signal correlate.Signal) (event.Envelope, error) {
	ids := signal.SourceEventIDs
	truncated := len(ids) > 64
	if truncated {
		ids = ids[len(ids)-64:]
	}
	obs := signalObservation{
		RuleID: string(signal.RuleID), Summary: signal.Summary, SourceKey: signal.SourceKey,
		SourceEventIDs: ids, Truncated: truncated, Synthetic: true,
	}
	return r.envelope(signal.Time.Add(time.Millisecond), event.SensorRef{ID: "correlate", Kind: "correlation"}, event.ClassificationCorrelationSignal, obs, nil)
}
