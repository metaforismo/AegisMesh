// Package mcpsensor exposes decoy MCP (Model Context Protocol) tools over the
// streamable-HTTP JSON-RPC transport. The canary contract: honest agents never
// call these tools; every invocation is recorded as a high-signal event.
//
// Protocol surface implemented: initialize, ping, tools/list, tools/call.
// Requests are single JSON objects per POST (no SSE stream needed for decoy
// semantics); responses are application/json per the streamable transport's
// "server MAY return application/json" allowance.
package mcpsensor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"

	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/detect"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/policy"
	"github.com/metaforismo/aegismesh/internal/redact"
	"github.com/metaforismo/aegismesh/internal/sensor"
)

// JSON-RPC 2.0 wire types.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e rpcError) Marshalable() bool { return e.Code != 0 }

const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	// codeServerRefused sits in the JSON-RPC server-error range (-32000..-32099).
	codeServerRefused = -32000
)

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type toolInfo struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

type resourceInfo struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mimeType,omitempty"`
}

type promptInfo struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Arguments   []promptArgInfo `json:"arguments,omitempty"`
}

type promptArgInfo struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

func orString(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

type Sensor struct {
	id  string
	cfg config.Sensor
	enf *policy.Enforcer
	srv *http.Server

	mu sync.Mutex // guards ln: Start, Addr, and Close may run on any goroutine
	ln net.Listener

	done chan error
	once sync.Once
	log  *slog.Logger
}

func New(c config.Sensor, enf *policy.Enforcer) (*Sensor, error) {
	if c.ID == "" {
		return nil, fmt.Errorf("mcpsensor: empty id")
	}
	if enf == nil {
		return nil, fmt.Errorf("mcpsensor %s: nil enforcer", c.ID)
	}
	if len(c.Tools) == 0 {
		return nil, fmt.Errorf("mcpsensor %s: no canary tools configured", c.ID)
	}
	return &Sensor{id: c.ID, cfg: c, enf: enf, done: make(chan error, 1)}, nil
}

func (s *Sensor) ID() string   { return s.id }
func (s *Sensor) Kind() string { return config.SensorKindMCP }

// listener returns the bound listener under the lock; nil before Start.
func (s *Sensor) listener() net.Listener {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ln
}

// Addr reports the bound address once Start has succeeded.
func (s *Sensor) Addr() string {
	ln := s.listener()
	if ln == nil {
		return ""
	}
	return ln.Addr().String()
}
func (s *Sensor) Done() <-chan error {
	return s.done
}

func (s *Sensor) Start(ctx context.Context, d sensor.Deps) error {
	if err := sensor.ValidateDeps(d); err != nil {
		return err
	}
	s.log = d.Log

	eventsTotal := d.Meter.Counter(
		"aegismesh_sensor_mcp_canary_invocations_total",
		"MCP canary tool invocations observed")
	lists := d.Meter.Counter(
		"aegismesh_sensor_mcp_tools_listed_total",
		"tools/list requests answered")
	reads := d.Meter.Counter(
		"aegismesh_sensor_mcp_resources_read_total",
		"resources/read requests answered")
	prompts := d.Meter.Counter(
		"aegismesh_sensor_mcp_prompts_fetched_total",
		"prompts/get requests answered")

	h := &handler{
		ref:      event.SensorRef{ID: s.cfg.ID, Kind: s.Kind(), Listen: s.cfg.Listen},
		cfg:      &s.cfg,
		enf:      s.enf,
		bus:      d.Bus,
		seq:      d.Seq,
		instance: d.Instance,
		log:      d.Log,
		events:   eventsTotal,
		lists:    lists,
		reads:    reads,
		prompts:  prompts,
	}
	mux := http.NewServeMux()
	path := s.cfg.MCPPath
	if path == "" {
		path = "/mcp" // defensive default; config validation also enforces this
	}
	mux.Handle(path, h)

	s.srv = &http.Server{ //nolint:gosec // explicit timeouts below
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("mcpsensor %s: bind %s: %v", s.id, s.cfg.Listen, err)
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			d.Log.Error("mcp sensor failed", "sensor", s.id, "err", err)
			select {
			case s.done <- err:
			default:
			}
		}
	}()
	d.Log.Info("mcp sensor listening", "sensor", s.id, "addr", ln.Addr().String(), "path", s.cfg.MCPPath)
	return nil
}

func (s *Sensor) Close(ctx context.Context) error {
	var err error
	s.once.Do(func() {
		if s.srv != nil {
			err = s.srv.Shutdown(ctx)
		}
		close(s.done)
	})
	return err
}

type handler struct {
	ref      event.SensorRef
	cfg      *config.Sensor
	enf      *policy.Enforcer
	bus      *event.Bus
	seq      *event.Sequencer
	instance string
	log      *slog.Logger
	events   observe.Counter
	lists    observe.Counter
	reads    observe.Counter
	prompts  observe.Counter
}

const maxMessageBytes = 256 << 10

// methodRe constrains JSON-RPC method names to the shapes this protocol uses:
// ASCII tokens with slash-separated segments (e.g. "tools/call",
// "notifications/initialized"). Anything outside the shape fails envelope
// validation (-32600) rather than method-not-found, because it is not a
// plausible MCP method at all.
var methodRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9/_-]{0,63}$`)

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Media-type gate: a present Content-Type must be application/json.
	// Absent is tolerated for minimal clients; anything else declared is a
	// hard 415 before we spend bytes reading the body.
	if ct := strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]); ct != "" && ct != "application/json" {
		http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxMessageBytes))
	if err != nil || len(body) >= maxMessageBytes {
		writeRPC(w, nil, &rpcError{Code: codeParseError, Message: "message too large or unreadable"})
		return
	}

	// Batches: JSON arrays are valid JSON-RPC but deliberately unsupported by
	// this decoy. Reject as a single error object per the spec's allowance,
	// never by processing batch contents.
	if trimmed := bytes.TrimSpace(body); len(trimmed) > 0 && trimmed[0] == '[' {
		writeRPC(w, nil, &rpcError{Code: codeInvalidRequest, Message: "batch requests are not supported"})
		return
	}

	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeRPC(w, nil, &rpcError{Code: codeParseError, Message: "parse error"})
		return
	}
	// Envelope strictness: version pinned, method shaped, id typed.
	if req.JSONRPC != "2.0" {
		writeRPC(w, nil, &rpcError{Code: codeInvalidRequest, Message: `jsonrpc must be exactly "2.0"`})
		return
	}
	if !methodRe.MatchString(req.Method) {
		writeRPC(w, nil, &rpcError{Code: codeInvalidRequest, Message: "malformed method"})
		return
	}
	isNotification := len(req.ID) == 0
	if !isNotification && !validRequestID(req.ID) {
		writeRPC(w, nil, &rpcError{Code: codeInvalidRequest, Message: "id must be a string or integer"})
		return
	}

	// Detection runs before any method dispatch. Input is the bounded raw
	// message text; findings shape both the response (refuse) and evidence.
	det := h.enf.Evaluate(h.ref.ID, detect.Input{
		Text:       policy.BoundedDetectInput(req.Method+" "+string(req.Params), h.enf.EngineMaxInput()),
		TotalBytes: len(req.Method) + len(req.Params),
	})
	w.Header().Set("X-AegisMesh-Action", string(det.Action))

	if det.Action == policy.ActionRefuse {
		h.emitWithClass(req.Method, event.ClassificationInteraction, &det)
		if isNotification {
			// Notifications never get a response body, even on refusal.
			w.WriteHeader(http.StatusAccepted)
			return
		}
		writeRPC(w, &rpcResponse{JSONRPC: "2.0", ID: req.ID},
			&rpcError{Code: codeServerRefused, Message: "request refused"})
		return
	}

	switch req.Method {
	case "initialize":
		h.emitWithClass("initialize", event.ClassificationInteraction, &det)
		caps := map[string]any{"tools": map[string]any{}}
		if len(h.cfg.Resources) > 0 {
			caps["resources"] = map[string]any{}
		}
		if len(h.cfg.Prompts) > 0 {
			caps["prompts"] = map[string]any{}
		}
		result, _ := json.Marshal(map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    caps,
			"serverInfo": map[string]string{
				"name":    h.cfg.ServerName,
				"version": h.cfg.ServerVer,
			},
			"instructions": truncateStr(h.cfg.Instructions, 1024),
		})
		writeRPC(w, &rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}, nil)

	case "ping":
		h.emitWithClass("ping", event.ClassificationInteraction, &det)
		writeRPC(w, &rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(`{}`)}, nil)

	case "tools/list":
		h.lists.Inc()
		tools := make([]toolInfo, 0, len(h.cfg.Tools))
		for _, t := range h.cfg.Tools {
			tinfo := toolInfo{Name: t.Name, Description: t.Description}
			if len(t.InputSchema) > 0 {
				tinfo.InputSchema = json.RawMessage(t.InputSchema)
			}
			tools = append(tools, tinfo)
		}
		result, _ := json.Marshal(map[string]any{"tools": tools})
		h.emitWithClass("tools/list", event.ClassificationInteraction, &det)
		writeRPC(w, &rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}, nil)

	case "tools/call":
		var p callParams
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &p); err != nil {
				writeRPC(w, &rpcResponse{JSONRPC: "2.0", ID: req.ID},
					&rpcError{Code: codeInvalidParams, Message: "invalid params"})
				return
			}
		}
		tool, ok := h.toolByName(p.Name)
		if !ok {
			h.emitCall(p.Name, p.Arguments, "unknown-tool", true, &det, sensor.PeerHost(r.RemoteAddr))
			writeRPC(w, &rpcResponse{JSONRPC: "2.0", ID: req.ID},
				&rpcError{Code: codeInvalidParams, Message: "unknown tool"})
			return
		}
		// CANARY HIT: an agent invoked a restricted tool. Record it as the
		// highest-signal observation this sensor produces, then answer with the
		// configured canned synthetic result. Nothing here is ever executed.
		h.events.Inc()
		h.emitCall(tool.Name, p.Arguments, tool.Name, false, &det, sensor.PeerHost(r.RemoteAddr))
		writeRPC(w, &rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  json.RawMessage(tool.ResultJSON),
		}, nil)

	case "resources/list":
		items := make([]resourceInfo, 0, len(h.cfg.Resources))
		for _, res := range h.cfg.Resources {
			items = append(items, resourceInfo{
				URI: res.URI, Name: res.Name,
				Description: truncateStr(res.Description, 2048), MIMEType: res.MIMEType,
			})
		}
		result, _ := json.Marshal(map[string]any{"resources": items})
		h.emitWithClass("resources/list", event.ClassificationInteraction, &det)
		writeRPC(w, &rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}, nil)

	case "resources/read":
		var p struct {
			URI string `json:"uri"`
		}
		if len(req.Params) == 0 || json.Unmarshal(req.Params, &p) != nil || p.URI == "" {
			writeRPC(w, &rpcResponse{JSONRPC: "2.0", ID: req.ID},
				&rpcError{Code: codeInvalidParams, Message: "uri required"})
			return
		}
		res, ok := h.resourceByURI(p.URI)
		h.reads.Inc()
		if !ok {
			h.emitWithClass("resources/read", event.ClassificationInteraction, &det)
			writeRPC(w, &rpcResponse{JSONRPC: "2.0", ID: req.ID},
				&rpcError{Code: codeInvalidParams, Message: "unknown resource"})
			return
		}
		content, _ := json.Marshal(map[string]any{
			"contents": []map[string]any{{
				"uri":      res.URI,
				"mimeType": orString(res.MIMEType, "text/plain"),
				"text":     res.Text,
			}},
		})
		h.emitWithClass("resources/read", event.ClassificationInteraction, &det)
		writeRPC(w, &rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: content}, nil)

	case "prompts/list":
		items := make([]promptInfo, 0, len(h.cfg.Prompts))
		for _, pr := range h.cfg.Prompts {
			args := make([]promptArgInfo, 0, len(pr.Arguments))
			for _, a := range pr.Arguments {
				args = append(args, promptArgInfo{Name: a.Name, Description: a.Description, Required: a.Required})
			}
			items = append(items, promptInfo{Name: pr.Name, Description: pr.Description, Arguments: args})
		}
		result, _ := json.Marshal(map[string]any{"prompts": items})
		h.emitWithClass("prompts/list", event.ClassificationInteraction, &det)
		writeRPC(w, &rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}, nil)

	case "prompts/get":
		out, rpcErr := h.renderPrompt(req.Params)
		h.prompts.Inc()
		h.emitWithClass("prompts/get", event.ClassificationInteraction, &det)
		if rpcErr != nil {
			writeRPC(w, &rpcResponse{JSONRPC: "2.0", ID: req.ID}, rpcErr)
			return
		}
		writeRPC(w, &rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: out}, nil)

	default:
		if isNotification {
			// Unknown notifications are accepted silently per JSON-RPC 2.0;
			// the streamable transport answers 202 with no body.
			h.emitWithClass(req.Method, event.ClassificationInteraction, &det)
			w.WriteHeader(http.StatusAccepted)
			return
		}
		h.emitWithClass(req.Method, event.ClassificationInteraction, &det)
		writeRPC(w, &rpcResponse{JSONRPC: "2.0", ID: req.ID},
			&rpcError{Code: codeMethodNotFound, Message: "method not found"})
	}
}

// validRequestID accepts only string and integer ids per JSON-RPC 2.0; the
// fractional/null/bool/object/array forms are envelope errors here.
func validRequestID(raw json.RawMessage) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return false
	}
	switch t := v.(type) {
	case string:
		return true
	case json.Number:
		_, err := t.Int64()
		return err == nil
	default:
		return false
	}
}

func (h *handler) resourceByURI(uri string) (config.MCPResource, bool) {
	for _, r := range h.cfg.Resources {
		if r.URI == uri {
			return r, true
		}
	}
	return config.MCPResource{}, false
}

// renderPrompt substitutes {argument_name} occurrences verbatim — there is no
// templating language, no evaluation, and the substituted text is bounded so a
// flood of argument values cannot balloon the response.
func (h *handler) renderPrompt(params json.RawMessage) (json.RawMessage, *rpcError) {
	var p struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments,omitempty"`
	}
	if len(params) == 0 || json.Unmarshal(params, &p) != nil {
		return nil, &rpcError{Code: codeInvalidParams, Message: "invalid params"}
	}
	var found *config.MCPPrompt
	for i := range h.cfg.Prompts {
		if h.cfg.Prompts[i].Name == p.Name {
			found = &h.cfg.Prompts[i]
			break
		}
	}
	if found == nil {
		return nil, &rpcError{Code: codeInvalidParams, Message: "unknown prompt"}
	}
	msgs := make([]map[string]any, 0, len(found.Messages))
	total := 0
	for _, m := range found.Messages {
		text := m
		for _, a := range found.Arguments {
			val, provided := p.Arguments[a.Name]
			if a.Required && !provided {
				return nil, &rpcError{Code: codeInvalidParams, Message: "missing required argument " + a.Name}
			}
			if provided {
				text = strings.ReplaceAll(text, "{"+a.Name+"}", val)
			}
		}
		if total+len(text) > config.MaxMCPResultBytes {
			break
		}
		text = truncateStr(text, config.MaxMCPResultBytes-total)
		total += len(text)
		msgs = append(msgs, map[string]any{
			"role":    "user",
			"content": map[string]any{"type": "text", "text": text},
		})
	}
	out, err := json.Marshal(map[string]any{"messages": msgs})
	if err != nil {
		return nil, &rpcError{Code: codeInvalidParams, Message: "render failed"}
	}
	return out, nil
}

type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

func (h *handler) toolByName(name string) (config.MCPTool, bool) {
	for _, t := range h.cfg.Tools {
		if t.Name == name {
			return t, true
		}
	}
	return config.MCPTool{}, false
}

// writeRPC emits a JSON-RPC 2.0 response. Errors always render as a complete
// error object with a null id when none is known — never as an empty body.
func writeRPC(w http.ResponseWriter, resp *rpcResponse, rpcErr *rpcError) {
	out := &rpcResponse{JSONRPC: "2.0"}
	if resp != nil {
		out.ID = resp.ID
		out.Result = resp.Result
	}
	if rpcErr != nil {
		out.Error = rpcErr
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(out)
}

// emit records an MCP-level observation. Only tools/call is a canary hit;
// listing or initializing against the endpoint is a plain interaction.
func (h *handler) emitWithClass(method string, class string, det *policy.Decision) {
	obs := observation{Method: method, Detection: newDetectionInfo(det)}
	raw, err := json.Marshal(obs)
	if err != nil {
		return
	}
	env, err := event.New(h.seq, h.instance, h.ref, class, raw, nil)
	if err != nil {
		return
	}
	h.bus.Submit(env)
}

func (h *handler) emitCall(tool string, args json.RawMessage, ruleID string, rejected bool, det *policy.Decision, remoteHost string) {
	argsPreview, truncated := "", false
	argLen := 0
	if len(args) > 0 {
		argLen = len(args)
		argsPreview, truncated = redact.Preview(args, redact.MaxPreviewBytes)
	}
	sum := sha256.Sum256(args)

	obs := observation{
		Method:        "tools/call",
		ToolName:      tool,
		ArgsLength:    argLen,
		ArgsTruncated: truncated,
		ArgsPreview:   argsPreview,
		ArgsSHA256:    hex.EncodeToString(sum[:]),
		RemoteHost:    remoteHost,
		Response: responseInfo{
			RuleID:   ruleID,
			Rejected: rejected,
		},
		Detection: newDetectionInfo(det),
	}
	raw, err := json.Marshal(obs)
	if err != nil {
		return
	}
	rules := []string{"credential_scrub"}
	if truncated {
		rules = append(rules, "preview_truncated")
	}
	env, err := event.New(h.seq, h.instance, h.ref, event.ClassificationCanaryHit, raw, rules)
	if err != nil {
		h.log.Error("event construction failed", "err", err)
		return
	}
	h.bus.Submit(env)
}

type observation struct {
	Method        string         `json:"method"`
	ToolName      string         `json:"tool_name,omitempty"`
	ArgsLength    int            `json:"args_length,omitempty"`
	ArgsTruncated bool           `json:"args_truncated,omitempty"`
	ArgsPreview   string         `json:"args_preview,omitempty"`
	ArgsSHA256    string         `json:"args_sha256,omitempty"`
	RemoteHost    string         `json:"remote_host,omitempty"`
	Response      responseInfo   `json:"response"`
	Detection     *detectionInfo `json:"detection,omitempty"`
}

// detectionInfo carries the enforcement verdict into evidence. Findings are
// static rule-authored text — safe to store verbatim.
type detectionInfo struct {
	Action   string           `json:"action"`
	Findings []detect.Finding `json:"findings,omitempty"`
}

func newDetectionInfo(det *policy.Decision) *detectionInfo {
	if det == nil {
		return nil
	}
	return &detectionInfo{Action: string(det.Action), Findings: det.Findings}
}

type responseInfo struct {
	RuleID   string `json:"rule_id,omitempty"`
	Rejected bool   `json:"rejected,omitempty"`
	Status   int    `json:"status,omitempty"`
}

// truncateStr truncates on rune boundaries so the echoed instructions field
// never contains a split UTF-8 sequence.
func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := s[:n]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut
}
