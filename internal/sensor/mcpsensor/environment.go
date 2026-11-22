package mcpsensor

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/strictjson"
)

type workspaceView struct {
	files   map[string]config.MCPEntry
	env     map[string]config.MCPEntry
	queries map[string]string
	names   []string
}

func compileEnvironment(cfg *config.MCPEnvironment) *workspaceView {
	if cfg == nil {
		return nil
	}
	out := &workspaceView{
		files:   map[string]config.MCPEntry{},
		env:     map[string]config.MCPEntry{},
		queries: map[string]string{},
		names:   []string{},
	}
	for _, entry := range cfg.Files {
		out.files[entry.Name] = entry
		out.names = append(out.names, entry.Name)
	}
	for _, entry := range cfg.Env {
		out.env[entry.Name] = entry
	}
	for key, value := range cfg.Queries {
		out.queries[key] = value
	}
	sort.Strings(out.names)
	return out
}

// Connection state has no peer-supplied identifier, global table or idle retention.
type connectionKey struct{}
type exploration struct {
	mu    sync.Mutex
	step  int
	tools []string
}

func explorationContext(ctx context.Context, _ net.Conn) context.Context {
	return context.WithValue(ctx, connectionKey{}, &exploration{})
}

func (h *handler) advance(r *http.Request, req rpcRequest) bool {
	if h.cfg.Environment == nil {
		return true
	}
	state, _ := r.Context().Value(connectionKey{}).(*exploration)
	if state == nil {
		state = &exploration{}
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.step >= 256 {
		return false
	}
	state.step++
	if req.Method == "tools/call" {
		var p callParams
		if json.Unmarshal(req.Params, &p) == nil && len(state.tools) < 32 {
			state.tools = append(state.tools, truncateStr(h.enf.Scrub(p.Name), 128))
		}
	}
	h.step = state.step
	h.sequence = append([]string{}, state.tools...)
	return true
}

func environmentTools() []toolInfo {
	out := []toolInfo{}
	for _, name := range config.MCPEnvironmentTools() {
		properties := map[string]any{}
		key := ""
		switch name {
		case "read_file":
			key = "path"
		case "get_env":
			key = "name"
		case "search":
			key = "query"
		case "run_query":
			key = "query"
		}
		required := []string{}
		if key != "" {
			properties[key] = map[string]string{"type": "string"}
			required = append(required, key)
		}
		schema, _ := json.Marshal(map[string]any{"type": "object", "properties": properties, "required": required, "additionalProperties": false})
		out = append(out, toolInfo{
			Name:        name,
			Description: "Workspace " + strings.ReplaceAll(name, "_", " "),
			InputSchema: schema,
		})
	}
	return out
}

// environmentResult only selects declared data. Paths and SQL are never interpreted.
func environmentResult(e *workspaceView, params json.RawMessage) (json.RawMessage, bool, bool, bool) {
	var p callParams
	if len(params) > maxMessageBytes || !strictjson.ValidObject(params) || json.Unmarshal(params, &p) != nil {
		return nil, false, false, false
	}
	write := writeShaped(p.Name)
	if !config.IsMCPEnvironmentTool(p.Name) {
		return nil, false, false, write
	}
	var args map[string]string
	if len(p.Arguments) > 0 && (!strictjson.ValidObject(p.Arguments) || json.Unmarshal(p.Arguments, &args) != nil) {
		return toolText("Invalid arguments", true), true, false, write
	}
	value := "Not found"
	secret := false
	key := ""
	switch p.Name {
	case "read_file":
		key = "path"
	case "get_env":
		key = "name"
	case "search", "run_query":
		key = "query"
	}
	if key == "" && len(args) != 0 || key != "" && (len(args) != 1 || len(args[key]) == 0 || len(args[key]) > 128) {
		return toolText("Not found", true), true, false, write
	}
	switch p.Name {
	case "list_files":
		value = strings.Join(e.names, "\n")
	case "read_file", "get_env":
		entries := e.files
		if p.Name == "get_env" {
			entries = e.env
		}
		if f, ok := entries[args[key]]; ok {
			value = f.Content
			secret = f.TokenID != ""
		}
	case "search":
		names := []string{}
		for _, name := range e.names {
			f := e.files[name]
			if strings.Contains(f.Name, args[key]) || strings.Contains(f.Content, args[key]) {
				names = append(names, f.Name)
			}
		}
		sort.Strings(names)
		if len(names) > 0 {
			value = strings.Join(names, "\n")
		}
	case "run_query":
		if v, ok := e.queries[args[key]]; ok {
			value = v
		}
	}
	return toolText(value, value == "Not found"), true, secret, write
}

func toolText(text string, failed bool) json.RawMessage {
	body, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": text}}, "isError": failed})
	if len(body) > config.MaxMCPResultBytes {
		return json.RawMessage(`{"content":[{"type":"text","text":"Result unavailable"}],"isError":true}`)
	}
	return body
}

func writeShaped(name string) bool {
	if len(name) > 128 {
		return false
	}
	parts := strings.FieldsFunc(strings.ToLower(name), func(r rune) bool { return r == '_' || r == '-' || r == '.' || r == ':' })
	for _, part := range parts {
		switch part {
		case "write", "exec", "execute", "shell", "delete", "remove", "update", "insert", "create", "run_command":
			return true
		}
	}
	return name == "run_command"
}
