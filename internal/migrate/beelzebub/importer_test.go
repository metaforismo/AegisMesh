package beelzebub

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/config"
)

func importYAML(t *testing.T, doc string) *Result {
	t.Helper()
	r, err := ImportFile("svc.yaml", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func hasPath(notes []FieldNote, path string) bool {
	for _, n := range notes {
		if n.Path == path {
			return true
		}
	}
	return false
}

const httpDoc = `
protocol: http
address: ":8080"
description: admin panel decoy
commands:
  - regex: "^/admin/login$"
    methods: ["GET", "POST"]
    statusCode: 401
    handler: "<html>login</html>"
    headers:
      - "Content-Type: text/html"
      - "X-Bad-Entry"
      - "nocolon"
  - regex: "^/plugin$"
    plugin: dummy-v1
fallbackCommand: default-cmd
tls:
  enabled: true
certFile: /etc/cert.pem
`

func TestImportHTTPService(t *testing.T) {
	r := importYAML(t, httpDoc)
	if r.Detected != "http" || r.Source != "svc.yaml" {
		t.Fatalf("detect wrong: %+v", r)
	}
	if r.Sensor == nil {
		t.Fatal("sensor must be produced")
	}
	if got := r.Sensor["listen"]; got != "127.0.0.1:8080" {
		t.Fatalf("listen = %v, want explicit loopback", got)
	}
	rules, ok := r.Sensor["rules"].([]map[string]any)
	if !ok || len(rules) != 1 {
		t.Fatalf("want exactly 1 imported rule (plugin skipped), got %+v", rules)
	}
	rule := rules[0]
	if rule["path_regex"] != "^/admin/login$" || rule["status"] != 401 {
		t.Fatalf("rule mapping wrong: %+v", rule)
	}
	methods, _ := rule["methods"].([]string)
	if len(methods) != 2 {
		t.Fatalf("methods wrong: %v", methods)
	}
	hdrs, _ := rule["headers"].(map[string]string)
	if hdrs == nil || hdrs["Content-Type"] != "text/html" {
		t.Fatalf("headers wrong: %v", hdrs)
	}
	if !hasPath(r.Unsupported, "commands[1].plugin") {
		t.Fatalf("plugin command must be reported unsupported: %+v", r.Unsupported)
	}
	if !hasPath(r.Unsupported, "fallbackCommand") || !hasPath(r.Unsupported, "tls") || !hasPath(r.Unsupported, "certFile") {
		t.Fatalf("fallback/TLS fields must be reported: %+v", r.Unsupported)
	}
	foundBadHeader := false
	for _, n := range r.Unsupported {
		if strings.HasPrefix(n.Path, "commands[0].headers[") {
			foundBadHeader = true
		}
	}
	if !foundBadHeader {
		t.Fatalf("malformed header entries must be reported: %+v", r.Unsupported)
	}
	if len(r.Notes) == 0 || !strings.Contains(strings.Join(r.Notes, "\n"), "admin panel decoy") {
		t.Fatalf("description must be preserved as a note: %+v", r.Notes)
	}
}

func TestImportTCPService(t *testing.T) {
	doc := `
protocol: tcp
address: "0.0.0.0:6399"
banner: "build-cache ready"
deadlineTimeoutSeconds: 7200
serverName: cache-ftp
passwordRegex: "^(.*)$"
commands:
  - regex: "^PING$"
    handler: "+OK PONG"
  - regex: "^USER .*"
    plugin: ssh-simulator
`
	r := importYAML(t, doc)
	if r.Detected != "tcp" || r.Sensor == nil {
		t.Fatalf("tcp detection/mapping failed: %+v", r)
	}
	if r.Sensor["banner"] != "build-cache ready" {
		t.Fatalf("banner missing: %+v", r.Sensor)
	}
	sess, ok := r.Sensor["session"].(map[string]any)
	if !ok || sess["idle_timeout_seconds"] != 3600 {
		t.Fatalf("session idle cap (7200 -> 3600) wrong: %+v", sess)
	}
	trules, ok := r.Sensor["tcp_rules"].([]map[string]any)
	if !ok || len(trules) != 1 || trules[0]["line_regex"] != "^PING$" {
		t.Fatalf("tcp rules wrong: %+v", trules)
	}
	if !hasPath(r.Unsupported, "passwordRegex") || !hasPath(r.Unsupported, "commands[1].plugin") {
		t.Fatalf("unsupported notes missing: %+v", r.Unsupported)
	}
	// The source's public bind must surface to the operator by exact opt-in
	// name, while the emitted listen stays verbatim.
	if got := r.Sensor["listen"]; got != "0.0.0.0:6399" {
		t.Fatalf("explicit source host must be preserved, got %v", got)
	}
	foundPublicNote := false
	for _, n := range r.Notes {
		if strings.Contains(n, "allow_public_bind") {
			foundPublicNote = true
		}
	}
	if !foundPublicNote {
		t.Fatalf("public bind in source must be reported: %+v", r.Notes)
	}
}

func TestImportMCPService(t *testing.T) {
	doc := `
protocol: mcp
address: ":9090"
serverName: build-cache-mcp
tools:
  - name: read_build_log
    description: read CI logs
    params:
      - name: run_id
      - name: token
    handler: '{"content":[{"type":"text","text":"ok"}]}'
  - name: broken
    description: not json
    handler: "not-json{"
  - name: no_handler
    description: incomplete
`
	r := importYAML(t, doc)
	if r.Detected != "mcp" || r.Sensor == nil {
		t.Fatalf("mcp detection failed: %+v", r)
	}
	if r.Sensor["server_name"] != "build-cache-mcp" || r.Sensor["path"] != "/mcp" {
		t.Fatalf("mcp common fields wrong: %+v", r.Sensor)
	}
	tools, ok := r.Sensor["tools"].([]map[string]any)
	if !ok || len(tools) != 1 {
		t.Fatalf("only the fully-described tool may be imported, got %+v", tools)
	}
	tool := tools[0]
	if tool["name"] != "read_build_log" {
		t.Fatalf("tool name wrong: %+v", tool)
	}
	schema, _ := tool["input_schema"].(string)
	if !strings.Contains(schema, `"run_id"`) || !strings.Contains(schema, `"required"`) {
		t.Fatalf("params schema approximation missing: %q", schema)
	}
	if !hasPath(r.Unsupported, "tools[1].handler") || !hasPath(r.Unsupported, "tools[2]") {
		t.Fatalf("broken tools must be reported precisely: %+v", r.Unsupported)
	}
	approxNote := false
	for _, n := range r.Notes {
		if strings.Contains(n, "approximated") {
			approxNote = true
		}
	}
	if !approxNote {
		t.Fatalf("param approximation must be flagged for review: %+v", r.Notes)
	}
}

func TestImportSSHTelnetAndCoreUnsupported(t *testing.T) {
	r := importYAML(t, "protocol: ssh\naddress: \":22\"\n")
	if r.Detected != "ssh" || r.Sensor != nil {
		t.Fatalf("ssh must produce no sensor: %+v", r)
	}
	if len(r.Unsupported) == 0 {
		t.Fatal("ssh document must report every field as unsupported")
	}

	rc := importYAML(t, "core:\n  logging:\n    level: debug\n  tracings: []\n  prometheus: {}\n")
	if rc.Detected != "core" {
		t.Fatalf("core detect wrong: %+v", rc)
	}
	for _, want := range []string{"core.logging", "core.tracings", "core.prometheus"} {
		if !hasPath(rc.Unsupported, want) {
			t.Errorf("core field %s must be reported", want)
		}
	}

	ru := importYAML(t, "protocol: gopher\naddress: \":70\"\n")
	if ru.Detected != "unknown" || ru.Sensor != nil {
		t.Fatalf("unknown protocol handling wrong: %+v", ru)
	}

	re, err := ImportFile("bad.yaml", []byte("\t: :\n  - broken"))
	if err == nil {
		t.Fatalf("invalid YAML should error, got %+v", re)
	}

	rd, err := ImportFile("empty.yaml", []byte("# nothing\n"))
	if err != nil || rd.Detected != "unknown" {
		t.Fatalf("empty doc: %+v err=%v", rd, err)
	}
}

func TestTranslateAddressTable(t *testing.T) {
	cases := []struct {
		in       string
		out      string
		notePart string
	}{
		{":8080", "127.0.0.1:8080", ""},
		{":22", "127.0.0.1:22", "privileged port 22"},
		// Explicit hosts are preserved verbatim but always reported with the
		// exact opt-in the operator would need — never silently rewritten.
		{"0.0.0.0:9000", "0.0.0.0:9000", "allow_public_bind"},
		{"192.168.1.5:7000", "192.168.1.5:7000", "allow_public_bind"},
		{"localhost:443", "localhost:443", ""},
		{"noport", "noport", "no port"},
	}
	for _, tc := range cases {
		out, notes := translateAddress(tc.in)
		if out != tc.out {
			t.Errorf("translateAddress(%q) = %q, want %q", tc.in, out, tc.out)
		}
		if tc.notePart != "" && !strings.Contains(strings.Join(notes, "\n"), tc.notePart) {
			t.Errorf("translateAddress(%q) notes = %v, want mention of %q", tc.in, notes, tc.notePart)
		}
	}
	_, notes := translateAddress(":22")
	if !strings.Contains(strings.Join(notes, ""), "allow_privileged_ports") {
		t.Error("privileged-port note must name the exact opt-in flag")
	}
}

// TestEmitConfigRoundTripsThroughStrictLoader is the critical contract: every
// emitted configuration must pass AegisMesh's own strict validation unchanged,
// proving imports never relax loopback or privileged-port defaults.
func TestEmitConfigRoundTripsThroughStrictLoader(t *testing.T) {
	results := []*Result{}
	for _, doc := range []string{httpDoc, `
protocol: tcp
address: ":6399"
banner: hi
commands:
  - regex: "^PING$"
    handler: "+OK PONG"
`, `
protocol: mcp
address: ":9090"
tools:
  - name: t1
    description: d
    handler: '{}'
`} {
		r, err := ImportFile("x.yaml", []byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		results = append(results, r)
	}
	out, err := EmitConfig(results)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if strings.Contains(text, "allow_public_bind") || strings.Contains(text, "allow_privileged_ports") {
		t.Fatal("emitted config must never enable security relaxations")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "emitted.yaml")
	if err := os.WriteFile(p, out, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("emitted config fails strict validation: %v\n---\n%s", err, text)
	}
	if len(cfg.Sensors) != 3 {
		t.Fatalf("want 3 sensors, got %d", len(cfg.Sensors))
	}
	for _, s := range cfg.Sensors {
		if !strings.HasPrefix(s.Listen, "127.0.0.1:") {
			t.Fatalf("emitted sensor bind must be loopback, got %q", s.Listen)
		}
	}
}

func TestEmitConfigRequiresTranslatableSensor(t *testing.T) {
	r, _ := ImportFile("s.yaml", []byte("protocol: ssh\n"))
	if _, err := EmitConfig([]*Result{r}); err == nil {
		t.Fatal("emit with no translatable sensors must fail with guidance")
	}
}

func TestDerivedID(t *testing.T) {
	cases := map[string]string{
		"http-config.yaml":       "beelzebub-http-config",
		"My HTTP Service!.yml":   "beelzebub-my-http-service",
		"weird___name.json":      "beelzebub-weird-name",
		"ab.yaml":                "imported-sensor",
		"UPPER-case-name.config": "beelzebub-upper-case-name",
	}
	for in, want := range cases {
		if got := derivedID(in); got != want {
			t.Errorf("derivedID(%q) = %q, want %q", in, got, want)
		}
	}
	long := derivedID(strings.Repeat("x", 200) + ".yaml")
	if len(long) > len("beelzebub-")+60 {
		t.Errorf("long ids must be truncated, got len %d", len(long))
	}
}

func TestEmittedName(t *testing.T) {
	cases := map[string]string{
		"/etc/beelzebub/http.yaml": "http.aegismesh.yaml",
		"services.tar.gz":          "services.tar.aegismesh.yaml",
		".hidden":                  "config.aegismesh.yaml",
		"":                         "config.aegismesh.yaml",
	}
	for in, want := range cases {
		if got := EmittedName(in); got != want {
			t.Errorf("EmittedName(%q) = %q, want %q", in, got, want)
		}
	}
}

func FuzzImportBeelzebubDoc(f *testing.F) {
	f.Add([]byte(httpDoc))
	f.Add([]byte("protocol: tcp\naddress: ':22'\n"))
	f.Add([]byte("core: {}\n"))
	f.Add([]byte("protocol: [a, b]\n"))
	f.Add([]byte("commands: just-a-string\n"))
	f.Add([]byte("protocol: http\ncommands:\n  - regex: 42\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		r, err := ImportFile("fuzz.yaml", raw)
		if err != nil {
			return // parse failures are fine
		}
		switch r.Detected {
		case "core", "http", "tcp", "mcp", "ssh", "telnet", "unknown":
		default:
			t.Fatalf("unexpected detected value %q", r.Detected)
		}
		if r.Sensor != nil {
			listen, _ := r.Sensor["listen"].(string)
			if listen == "" {
				return
			}
			host, port, err := net.SplitHostPort(listen)
			if err != nil {
				t.Fatalf("unparseable listen escaped translation: %q", listen)
			}
			loop, _ := strconv.ParseInt(port, 10, 64)
			if host == "" && loop > 0 {
				t.Fatalf("empty host must be forced to loopback: %q", listen)
			}
		}
	})
}
