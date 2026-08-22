// Package beelzebub implements a clean-room importer for the publicly
// documented Beelzebub configuration shapes. It parses generic YAML/JSON
// documents (never their code or structs), translates what has an AegisMesh
// equivalent, and reports every unsupported field precisely.
//
// Guarantees: sources are only ever read; dry-run is the default; emitted
// configs never silently relax safety flags (privileged ports and public binds
// are reported, not enabled).
package beelzebub

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var errImport = errors.New("migrate/beelzebub")

// FieldNote records one field-level translation outcome.
type FieldNote struct {
	Path   string `json:"path"`
	Reason string `json:"reason,omitempty"`
	Note   string `json:"note,omitempty"`
}

// Result describes what happened to one source document.
type Result struct {
	Source       string         `json:"source_file"`
	Detected     string         `json:"detected"` // core|http|tcp|mcp|ssh|telnet|unknown
	Mapped       []string       `json:"mapped_fields,omitempty"`
	Unsupported  []FieldNote    `json:"unsupported_fields,omitempty"`
	Approximated []FieldNote    `json:"approximated_fields,omitempty"`
	Notes        []string       `json:"notes,omitempty"`
	Sensor       map[string]any `json:"-"` // translated sensor doc, nil when none
}

const defaultLoopbackHost = "127.0.0.1"

// ImportFile translates one raw config document.
func ImportFile(sourceName string, raw []byte) (*Result, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", errImport, filepath.Base(sourceName), err)
	}
	if len(doc) == 0 {
		return &Result{Source: filepath.Base(sourceName), Detected: "unknown"}, nil
	}
	base := filepath.Base(sourceName)
	// Safety gate before any translation: credential material in a source
	// document must never survive into an emitted AegisMesh config (which is
	// meant for VCS). Inline material refuses the import loudly; references
	// are reported as unsupported and never carried over. Values are never
	// echoed either way.
	credNotes, err := scanCredentialMaterial("$", doc)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", errImport, base, err)
	}
	var r *Result
	if _, ok := doc["core"]; ok {
		r = importCore(base, doc)
	} else {
		r, err = importService(base, doc)
		if err != nil {
			return nil, err
		}
	}
	r.Unsupported = append(r.Unsupported, credNotes...)
	return r, nil
}

// credentialKeyRe matches key names that conventionally hold secrets across
// the documented Beelzebub configuration shapes and generic YAML practice.
var credentialKeyRe = regexp.MustCompile(`(?i)(api[_-]?key|secret|password|passwd|token|access[_-]?key|private[_-]?key|bearer)`)

// placeholderRe marks values that are obviously not real credentials
// (documentation examples, templating stubs).
var placeholderRe = regexp.MustCompile(`(?i)(example|changeme|placeholder|xxxxx|<|\$\{|insert |your[_-]?)`)

// scanCredentialMaterial walks top-level blocks and one nested level. A
// credential-shaped KEY with a non-empty string value yields:
//   - a hard refusal (error) when the value looks like inline secret MATERIAL
//     (PEM header or a long blob without path separators) — the import stops;
//   - an unsupported-field note when it looks like a reference (file path,
//     placeholder) — nothing is carried over, the outcome is reported.
//
// Values never appear in any output.
func scanCredentialMaterial(path string, doc map[string]any) ([]FieldNote, error) {
	var notes []FieldNote
	for _, k := range keys(doc) {
		where := path + "." + k
		switch tv := doc[k].(type) {
		case string:
			trimmed := strings.TrimSpace(tv)
			if trimmed == "" || !credentialKeyRe.MatchString(k) || placeholderRe.MatchString(tv) {
				continue
			}
			inlineMaterial := strings.Contains(tv, "PRIVATE KEY-----") ||
				(len(trimmed) > 64 && !strings.ContainsAny(trimmed, "/\\."))
			if inlineMaterial {
				return nil, fmt.Errorf("refusing to import: credential material detected at %s — redact the source file first (values are never echoed)", where)
			}
			notes = append(notes, FieldNote{
				Path:   where,
				Reason: "credential reference detected; AegisMesh never carries credentials over — configure providers via api_key_env/api_key_file instead",
			})
		case map[string]any:
			sub, err := scanCredentialMaterial(where, tv)
			if err != nil {
				return nil, err
			}
			notes = append(notes, sub...)
		}
	}
	return notes, nil
}

func importCore(name string, doc map[string]any) *Result {
	r := &Result{Source: name, Detected: "core"}
	core, _ := doc["core"].(map[string]any)
	for _, k := range keys(core) {
		switch k {
		case "logging":
			r.Mapped = append(r.Mapped, "core.logging")
			r.Unsupported = append(r.Unsupported, FieldNote{
				Path:   "core.logging",
				Reason: "AegisMesh logging is configured via top-level logging.level/format; values are not carried over",
				Note:   "default json/info",
			})
		case "tracings":
			r.Unsupported = append(r.Unsupported, FieldNote{
				Path:   "core.tracings",
				Reason: "message-queue tracing has no equivalent yet; evidence goes to the local JSONL store and /metrics",
			})
		case "prometheus":
			r.Mapped = append(r.Mapped, "core.prometheus")
			r.Unsupported = append(r.Unsupported, FieldNote{
				Path:   "core.prometheus",
				Reason: "AegisMesh serves metrics on its own loopback admin listener; set admin.listen to your preferred port",
			})
		default:
			r.Unsupported = append(r.Unsupported, FieldNote{Path: "core." + k, Reason: "unknown core setting"})
		}
	}
	if len(r.Mapped) == 0 && len(r.Unsupported) == 0 {
		r.Unsupported = append(r.Unsupported, FieldNote{Path: "core", Reason: "empty or unrecognized"})
	}
	return r
}

func importService(name string, doc map[string]any) (*Result, error) {
	proto, _ := doc["protocol"].(string)
	r := &Result{Source: name, Detected: strings.ToLower(proto)}

	switch r.Detected {
	case "http":
		importHTTP(doc, r)
		return r, nil
	case "tcp":
		importTCP(doc, r)
		return r, nil
	case "mcp":
		importMCP(doc, r)
		return r, nil
	case "ssh", "telnet":
		// Entire protocol out of scope for this release's importer.
		for _, k := range keys(doc) {
			r.Unsupported = append(r.Unsupported, FieldNote{
				Path:   k,
				Reason: fmt.Sprintf("protocol %s is not supported by this importer release; AegisMesh roadmap item R1 covers SSH decoys", proto),
			})
		}
		return r, nil
	default:
		r.Detected = "unknown"
		return r, nil
	}
}

func commonServiceFields(doc map[string]any, r *Result, sensor map[string]any) bool {
	sensor["id"] = derivedID(r.Source)
	listen, notes := translateAddress(str(doc["address"]))
	sensor["listen"] = listen
	r.Mapped = append(r.Mapped, "address -> sensors[0].listen="+listen)
	if d := str(doc["description"]); d != "" {
		r.Notes = append(r.Notes, "description "+strconv.Quote(d)+" kept as note only; AegisMesh v1alpha1 has no description field")
	}
	r.Notes = append(r.Notes, notes...)
	if !usableListen(listen) {
		// An address we cannot turn into a bindable host:port must never
		// reach an emitted config that would fail strict validation.
		delete(sensor, "listen")
		r.Unsupported = append(r.Unsupported, FieldNote{
			Path:   "address",
			Reason: fmt.Sprintf("cannot derive a valid host:port from %q; fix the address manually before importing", str(doc["address"])),
		})
		return false
	}
	return true
}

// usableListen reports whether listen is a plausible bind target: parseable
// host:port with a numeric port. Final authority remains config validation.
func usableListen(listen string) bool {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	_, err = strconv.Atoi(port)
	return err == nil
}

func importHTTP(doc map[string]any, r *Result) {
	sensor := map[string]any{"kind": "http"}
	listenOK := commonServiceFields(doc, r, sensor)

	cmds, _ := doc["commands"].([]any)
	rules := make([]map[string]any, 0, len(cmds))
	for i, cAny := range cmds {
		c, ok := cAny.(map[string]any)
		if !ok {
			r.Unsupported = append(r.Unsupported, FieldNote{Path: fmt.Sprintf("commands[%d]", i), Reason: "not a mapping"})
			continue
		}
		p := func(f string) string { return fmt.Sprintf("commands[%d].%s", i, f) }
		re := str(c["regex"])
		if re == "" {
			r.Unsupported = append(r.Unsupported, FieldNote{Path: p("regex"), Reason: "missing regex"})
			continue
		}
		if plug := str(c["plugin"]); plug != "" {
			r.Unsupported = append(r.Unsupported, FieldNote{
				Path:   p("plugin"),
				Reason: fmt.Sprintf("plugin %q cannot be imported; in-process plugins have no equivalent by design", plug),
				Note:   "consider an llm fallback block instead",
			})
			continue
		}
		rule := map[string]any{"name": fmt.Sprintf("imported-%d", i), "path_regex": re}
		r.Mapped = append(r.Mapped, p("regex"))
		if m := strList(c["methods"]); len(m) > 0 {
			rule["methods"] = m
			r.Mapped = append(r.Mapped, p("methods"))
		}
		status := intOr(c["statusCode"], 200)
		rule["status"] = status
		r.Mapped = append(r.Mapped, p("statusCode"))
		if h := str(c["handler"]); h != "" {
			if len(h) > 64<<10 {
				r.Unsupported = append(r.Unsupported, FieldNote{Path: p("handler"), Reason: "handler exceeds AegisMesh inline-body cap (64KiB)"})
			} else {
				rule["body"] = h
				r.Mapped = append(r.Mapped, p("handler"))
			}
		}
		if hdrs := parseHeaders(c["headers"], p("headers"), r); hdrs != nil {
			rule["headers"] = hdrs
		}
		rules = append(rules, rule)
	}
	if fb := str(doc["fallbackCommand"]); fb != "" {
		r.Unsupported = append(r.Unsupported, FieldNote{
			Path:   "fallbackCommand",
			Reason: "fallback handlers are plugin-based upstream; use llm.fallback in AegisMesh",
		})
	}
	for _, k := range []string{"tls", "certFile", "keyFile"} {
		if _, ok := doc[k]; ok {
			r.Unsupported = append(r.Unsupported, FieldNote{Path: k, Reason: "TLS termination is not part of decoy listeners in this release"})
		}
	}
	if len(rules) > 0 && listenOK {
		sensor["rules"] = rules
		r.Sensor = sensor
	}
}

func importTCP(doc map[string]any, r *Result) {
	sensor := map[string]any{"kind": "tcp"}
	listenOK := commonServiceFields(doc, r, sensor)

	if b := str(doc["banner"]); b != "" {
		if len(b) <= 4<<10 {
			sensor["banner"] = b
			r.Mapped = append(r.Mapped, "banner")
		} else {
			r.Unsupported = append(r.Unsupported, FieldNote{Path: "banner", Reason: "exceeds 4KiB cap"})
		}
	}
	cmds, _ := doc["commands"].([]any)
	rules := make([]map[string]any, 0, len(cmds))
	for i, cAny := range cmds {
		c, ok := cAny.(map[string]any)
		if !ok {
			continue
		}
		p := func(f string) string { return fmt.Sprintf("commands[%d].%s", i, f) }
		if plug := str(c["plugin"]); plug != "" {
			r.Unsupported = append(r.Unsupported, FieldNote{Path: p("plugin"), Reason: "plugins cannot be imported"})
			continue
		}
		re := str(c["regex"])
		handler := str(c["handler"])
		if re == "" || handler == "" {
			r.Unsupported = append(r.Unsupported, FieldNote{Path: fmt.Sprintf("commands[%d]", i), Reason: "needs both regex and handler"})
			continue
		}
		rules = append(rules, map[string]any{
			"name":       fmt.Sprintf("imported-%d", i),
			"line_regex": re,
			"response":   handler,
		})
		r.Mapped = append(r.Mapped, p("regex"), p("handler"))
	}
	if secs := intOr(doc["deadlineTimeoutSeconds"], 0); secs > 0 {
		idle := secs
		if idle > 3600 {
			idle = 3600
		}
		sensor["session"] = map[string]any{"idle_timeout_seconds": idle}
		r.Mapped = append(r.Mapped, "deadlineTimeoutSeconds -> session.idle_timeout_seconds")
	}
	if sn := str(doc["serverName"]); sn != "" {
		r.Notes = append(r.Notes,
			"serverName "+strconv.Quote(sn)+": AegisMesh tcp sensors expose persona via banner only")
	}
	if pr := str(doc["passwordRegex"]); pr != "" {
		r.Unsupported = append(r.Unsupported, FieldNote{
			Path:   "passwordRegex",
			Reason: "credential-guessing flows belong to the SSH decoy family (roadmap); TCP decoys never accept secrets",
		})
	}
	if listenOK && (len(rules) > 0 || sensor["banner"] != nil) {
		if len(rules) > 0 {
			sensor["tcp_rules"] = rules
		}
		r.Sensor = sensor
	}
}

func importMCP(doc map[string]any, r *Result) {
	sensor := map[string]any{"kind": "mcp"}
	listenOK := commonServiceFields(doc, r, sensor)

	sensor["path"] = "/mcp"
	if sn := str(doc["serverName"]); sn != "" {
		sensor["server_name"] = sn
		r.Mapped = append(r.Mapped, "serverName -> server_name")
	}

	toolsDoc, _ := doc["tools"].([]any)
	tools := make([]map[string]any, 0, len(toolsDoc))
	for i, tAny := range toolsDoc {
		t, ok := tAny.(map[string]any)
		if !ok {
			r.Unsupported = append(r.Unsupported, FieldNote{Path: fmt.Sprintf("tools[%d]", i), Reason: "not a mapping"})
			continue
		}
		p := func(f string) string { return fmt.Sprintf("tools[%d].%s", i, f) }
		name := str(t["name"])
		desc := str(t["description"])
		handler := str(t["handler"])
		if name == "" || handler == "" {
			r.Unsupported = append(r.Unsupported, FieldNote{Path: fmt.Sprintf("tools[%d]", i), Reason: "needs name and handler"})
			continue
		}
		if !json.Valid([]byte(handler)) {
			r.Unsupported = append(r.Unsupported, FieldNote{Path: p("handler"), Reason: "handler is not valid JSON; AegisMesh canary results must be JSON"})
			continue
		}
		if len(handler) > 16<<10 {
			r.Unsupported = append(r.Unsupported, FieldNote{Path: p("handler"), Reason: "handler exceeds 16KiB result cap"})
			continue
		}
		tool := map[string]any{"name": name, "description": desc, "result_json": handler}
		r.Mapped = append(r.Mapped, p("name"), p("description"), p("handler"))
		if params, ok := t["params"].([]any); ok && len(params) > 0 {
			props := map[string]any{}
			names := make([]string, 0, len(params))
			for j, paAny := range params {
				pa, _ := paAny.(map[string]any)
				pn := str(pa["name"])
				if pn == "" {
					r.Unsupported = append(r.Unsupported, FieldNote{Path: fmt.Sprintf("tools[%d].params[%d]", i, j), Reason: "missing param name"})
					continue
				}
				names = append(names, pn)
				props[pn] = map[string]any{"type": "string"}
			}
			if len(props) > 0 {
				schema := map[string]any{"type": "object", "properties": props}
				if len(names) > 0 {
					sort.Strings(names)
					schema["required"] = names
				}
				b, _ := json.Marshal(schema)
				tool["input_schema"] = string(b)
				r.Notes = append(r.Notes,
					fmt.Sprintf("tools[%d].params approximated as a minimal JSON schema; per-param descriptions were dropped — review before trusting", i))
			}
		}
		tools = append(tools, tool)
	}
	if len(tools) > 0 && listenOK {
		sensor["tools"] = tools
		r.Sensor = sensor
	}
}

// translateAddress converts ":8081"-style addresses to explicit loopback
// binds, reports privileged ports and non-loopback binds by naming the exact
// security opt-in the operator would need — it never enables them.
func translateAddress(addr string) (string, []string) {
	a := strings.TrimSpace(addr)
	var notes []string
	if a == "" {
		return "", notes
	}
	host, port, found := strings.Cut(a, ":")
	switch {
	case !found:
		notes = append(notes, "address had no port; left unchanged for manual fix")
		return a, notes
	case host == "":
		host = defaultLoopbackHost
	}
	if p, err := strconv.Atoi(port); err == nil && p < 1024 {
		notes = append(notes, fmt.Sprintf(
			"privileged port %d detected: the generated config will fail validation until you deliberately set security.allow_privileged_ports=true (or pick a port >=1024)", p))
	}
	switch host {
	case "", defaultLoopbackHost, "localhost", "::1":
	default:
		notes = append(notes, fmt.Sprintf(
			"source bound %q: migrated configs keep this host verbatim, but validation rejects non-loopback binds until you deliberately set security.allow_public_bind=true", host+":"+port))
	}
	return host + ":" + port, notes
}

func parseHeaders(v any, path string, r *Result) map[string]string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := map[string]string{}
	for i, eAny := range list {
		e, _ := eAny.(string)
		k, val, found := strings.Cut(e, ":")
		k, val = strings.TrimSpace(k), strings.TrimSpace(val)
		if !found || k == "" || val == "" {
			r.Unsupported = append(r.Unsupported, FieldNote{Path: fmt.Sprintf("%s[%d]", path, i), Reason: "expected 'Key: Value' form"})
			continue
		}
		out[k] = val
	}
	if len(out) == 0 {
		return nil
	}
	r.Mapped = append(r.Mapped, path)
	return out
}

func derivedID(source string) string {
	base := strings.TrimSuffix(filepath.Base(source), filepath.Ext(source))
	base = strings.ToLower(base)
	var sb strings.Builder
	lastDash := false
	for _, rn := range base {
		c := byte(rn)
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		if !ok && !lastDash {
			sb.WriteByte('-')
			lastDash = true
			continue
		}
		if ok {
			sb.WriteByte(c)
			lastDash = false
		}
	}
	out := strings.Trim(sb.String(), "-")
	if len(out) < 4 {
		return "imported-sensor"
	}
	if len(out) > 60 {
		out = out[:60]
	}
	return "beelzebub-" + out
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func intOr(v any, def int) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	default:
		return def
	}
}

func strList(v any) []string {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(l))
	for _, e := range l {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func keys(m map[string]any) []string {
	if m == nil {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
