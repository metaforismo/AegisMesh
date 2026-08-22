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

	"sync"
	"time"
	"unicode/utf8"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
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

type Sensor struct {
	id  string
	cfg config.Sensor
	srv *http.Server

	mu sync.Mutex // guards ln: Start, Addr, and Close may run on any goroutine
	ln net.Listener

	done chan error
	once sync.Once
	log  *slog.Logger
}

func New(c config.Sensor) (*Sensor, error) {
	if c.ID == "" {
		return nil, fmt.Errorf("mcpsensor: empty id")
	}
	if len(c.Tools) == 0 {
		return nil, fmt.Errorf("mcpsensor %s: no canary tools configured", c.ID)
	}
	return &Sensor{id: c.ID, cfg: c, done: make(chan error, 1)}, nil
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

	h := &handler{
		ref:      event.SensorRef{ID: s.cfg.ID, Kind: s.Kind(), Listen: s.cfg.Listen},
		cfg:      &s.cfg,
		bus:      d.Bus,
		seq:      d.Seq,
		instance: d.Instance,
		log:      d.Log,
		events:   eventsTotal,
		lists:    lists,
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
	bus      *event.Bus
	seq      *event.Sequencer
	instance string
	log      *slog.Logger
	events   observe.Counter
	lists    observe.Counter
}

const maxMessageBytes = 256 << 10

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxMessageBytes))
	if err != nil || len(body) >= maxMessageBytes {
		writeRPC(w, nil, &rpcError{Code: codeParseError, Message: "message too large or unreadable"})
		return
	}

	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeRPC(w, nil, &rpcError{Code: codeParseError, Message: "parse error"})
		return
	}

	switch req.Method {
	case "initialize":
		h.emit("initialize")
		result, _ := json.Marshal(map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo": map[string]string{
				"name":    h.cfg.ServerName,
				"version": h.cfg.ServerVer,
			},
			"instructions": truncateStr(h.cfg.Instructions, 1024),
		})
		writeRPC(w, &rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}, nil)

	case "notifications/initialized":
		// JSON-RPC notification: no id, no response body. The streamable
		// transport allows 202 Accepted with an empty body.
		w.WriteHeader(http.StatusAccepted)

	case "ping":
		h.emit("ping")
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
		h.emit("tools/list")
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
			h.emitCall(p.Name, p.Arguments, "unknown-tool", true, sensor.PeerHost(r.RemoteAddr))
			writeRPC(w, &rpcResponse{JSONRPC: "2.0", ID: req.ID},
				&rpcError{Code: codeInvalidParams, Message: "unknown tool"})
			return
		}
		// CANARY HIT: an agent invoked a restricted tool. Record it as the
		// highest-signal observation this sensor produces, then answer with the
		// configured canned synthetic result. Nothing here is ever executed.
		h.events.Inc()
		h.emitCall(tool.Name, p.Arguments, tool.Name, false, sensor.PeerHost(r.RemoteAddr))
		writeRPC(w, &rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  json.RawMessage(tool.ResultJSON),
		}, nil)

	default:
		h.emit(req.Method)
		writeRPC(w, &rpcResponse{JSONRPC: "2.0", ID: req.ID},
			&rpcError{Code: codeMethodNotFound, Message: "method not found"})
	}
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
func (h *handler) emit(method string) {
	h.emitWithClass(method, event.ClassificationInteraction)
}

func (h *handler) emitWithClass(method string, class string) {
	obs := observation{Method: method}
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

func (h *handler) emitCall(tool string, args json.RawMessage, ruleID string, rejected bool, remoteHost string) {
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
	Method        string       `json:"method"`
	ToolName      string       `json:"tool_name,omitempty"`
	ArgsLength    int          `json:"args_length,omitempty"`
	ArgsTruncated bool         `json:"args_truncated,omitempty"`
	ArgsPreview   string       `json:"args_preview,omitempty"`
	ArgsSHA256    string       `json:"args_sha256,omitempty"`
	RemoteHost    string       `json:"remote_host,omitempty"`
	Response      responseInfo `json:"response"`
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
