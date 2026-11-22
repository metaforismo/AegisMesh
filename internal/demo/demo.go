// Package demo runs the bounded, synthetic end-to-end product demonstration.
package demo

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/detect"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/honeytoken"
	"github.com/metaforismo/aegismesh/internal/recommend"
	"github.com/metaforismo/aegismesh/internal/runtime"
	"github.com/metaforismo/aegismesh/internal/storage"
)

const (
	schema          = "aegismesh.demo/v1"
	scenarioTimeout = 20 * time.Second
	requestTimeout  = 3 * time.Second
	maxReplyBytes   = 16 << 10
	maxTCPLineBytes = 128
	maxEvents       = 16
)

var sensorOrder = [...]string{"http", "tcp", "mcp", "ssh"}

// Summary is deliberately free of random IDs, times, paths, ports and evidence
// content so both human and JSON CLI output remain deterministic.
type Summary struct {
	DetectionRules    []string `json:"detection_rules"`
	Schema            string   `json:"schema"`
	Mode              string   `json:"mode"`
	Network           string   `json:"network"`
	Egress            string   `json:"egress"`
	Sensors           []string `json:"sensors"`
	Events            int      `json:"events"`
	Interactions      int      `json:"interactions"`
	CanaryInvocations int      `json:"canary_invocations"`
	IntegrityVerified bool     `json:"integrity_verified"`
	Recommendations   int      `json:"recommendations"`
	DryRun            bool     `json:"dry_run"`
	Enforcement       bool     `json:"enforcement"`
	SignalNotIncident bool     `json:"signal_not_incident"`
	ListenersReleased bool     `json:"listeners_released"`
	CleanupComplete   bool     `json:"cleanup_complete"`
}

// Run owns every listener, client, file and cleanup path used by the demo.
// It accepts no external destination or config, and all network traffic is
// validated as loopback before a client connects.
func Run(parent context.Context) (Summary, error) { return run(parent, nil) }

// RunConsole holds the same synthetic scenario until cancellation. The callback
// receives the one-time secret directly; it is never logged or persisted.
func RunConsole(parent context.Context, ready func(string, string) error) (Summary, error) {
	return run(parent, ready)
}
func run(parent context.Context, ready func(string, string) error) (summary Summary, err error) {
	if err := parent.Err(); err != nil {
		return Summary{}, err
	}
	ctx, cancel := context.WithTimeout(parent, scenarioTimeout)
	defer cancel()

	workDir, err := os.MkdirTemp("", "aegismesh-demo-")
	if err != nil {
		return Summary{}, fmt.Errorf("demo: create private workspace: %w", err)
	}
	defer func() {
		if removeErr := os.RemoveAll(workDir); removeErr != nil && err == nil {
			err = fmt.Errorf("demo: remove private workspace: %w", removeErr)
			return
		}
		if err == nil {
			summary.CleanupComplete = true
		}
	}()

	cfg, err := loadConfig(workDir)
	if err != nil {
		return Summary{}, err
	}
	token := ""
	if ready != nil {
		token, err = auth.Token()
		if err != nil {
			return Summary{}, err
		}
		cfg.Console = config.Console{Enabled: true, Listen: "127.0.0.1:0", SessionTTLSeconds: 3600, IndexMaxEvents: 50000, Operators: []config.Operator{{Name: "demo-admin", Role: "admin", TokenSHA256: auth.Digest(token)}}}
		if err = cfg.Validate(); err != nil {
			return Summary{}, err
		}
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sys, err := runtime.Build(cfg, log)
	if err != nil {
		return Summary{}, fmt.Errorf("demo: build runtime: %w", err)
	}
	stopped := false
	defer func() {
		if !stopped {
			sys.Stop(context.Background())
		}
	}()

	if err := sys.Start(ctx); err != nil {
		return Summary{}, fmt.Errorf("demo: start runtime: %w", err)
	}
	endpoints, err := sys.Endpoints()
	if err != nil {
		return Summary{}, fmt.Errorf("demo: discover endpoints: %w", err)
	}
	addresses, err := validatedAddresses(endpoints)
	if err != nil {
		return Summary{}, err
	}
	adminAddr, err := sys.AdminAddr()
	if err != nil {
		return Summary{}, fmt.Errorf("demo: discover admin endpoint: %w", err)
	}
	if err := validateLoopback(adminAddr); err != nil {
		return Summary{}, fmt.Errorf("demo: admin endpoint: %w", err)
	}
	if err := checkReady(ctx, adminAddr); err != nil {
		return Summary{}, err
	}

	if err := interactHTTP(ctx, addresses["http"]); err != nil {
		return Summary{}, err
	}
	if err := interactTCP(ctx, addresses["tcp"]); err != nil {
		return Summary{}, err
	}
	if err := interactMCP(ctx, addresses["mcp"]); err != nil {
		return Summary{}, err
	}
	if err := interactSSH(ctx, addresses["ssh"]); err != nil {
		return Summary{}, err
	}

	if err := interactAI(ctx, addresses["http"], cfg.Honeytokens); err != nil {
		return Summary{}, err
	}
	if ready != nil {
		addr, e := sys.ConsoleAddr()
		if e != nil {
			return Summary{}, e
		}
		if e = ready(addr, token); e != nil {
			return Summary{}, e
		}
		token = ""
		<-parent.Done()
	}
	sys.Stop(context.Background())
	stopped = true
	if err := verifyListenersReleased(addresses, adminAddr); err != nil {
		return Summary{}, err
	}
	summary, err = verifyEvidence(cfg.Runtime.DataDir, cfg.Honeytokens)
	if err != nil {
		return Summary{}, err
	}
	summary.ListenersReleased = true
	return summary, nil
}

func loadConfig(workDir string) (*config.Config, error) {
	cfg := config.Config{
		APIVersion: config.APIVersionV1Alpha1,
		Runtime: config.Runtime{
			InstanceName: "synthetic-demo",
			DataDir:      filepath.Join(workDir, "data"),
		},
		Admin:   config.Admin{Listen: "127.0.0.1:0"},
		Logging: config.Logging{Level: "error", Format: "json"},
		LLM:     config.LLM{Provider: "local"},
		Sensors: []config.Sensor{
			{
				ID: "demo-http", Kind: config.SensorKindHTTP, Listen: "127.0.0.1:0",
				Persona: &config.HTTPPersona{ServerHeader: "AegisMesh-Demo"},
				Rules:   []config.HTTPRule{{Name: "root", PathRegex: "^/$", Methods: []string{"GET"}, Status: http.StatusOK, Body: "synthetic demo\n"}},
			},
			{
				ID: "demo-tcp", Kind: config.SensorKindTCP, Listen: "127.0.0.1:0", Banner: "AEGISMESH DEMO\n",
				Session:         &config.TCPSession{MaxLineBytes: 128, IdleTimeoutSeconds: 3, MaxSessionSeconds: 5},
				TCPResponseRule: []config.TCPRule{{Name: "ping", LineRegex: "^PING$", Response: "+OK PONG\n"}},
			},
			{
				ID: "demo-mcp", Kind: config.SensorKindMCP, Listen: "127.0.0.1:0", MCPPath: "/mcp",
				ServerName: "aegismesh-demo", ServerVer: "1.0.0",
				Tools: []config.MCPTool{{Name: "canary_demo", Description: "Synthetic canary for the local demo", ResultJSON: `{"ok":true}`}},
			},
			{ID: "demo-ssh", Kind: config.SensorKindSSH, Listen: "127.0.0.1:0"},
		},
	}
	ai, err := config.AIDecoyConfig()
	if err != nil {
		return nil, err
	}
	cfg.Honeytokens = ai.Honeytokens
	cfg.Sensors[0].Rules = append(cfg.Sensors[0].Rules, ai.Sensors[0].Rules[1:]...)
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("demo: encode internal config: %w", err)
	}
	path := filepath.Join(workDir, "mesh.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return nil, fmt.Errorf("demo: write internal config: %w", err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		return nil, fmt.Errorf("demo: validate internal config: %w", err)
	}
	return loaded, nil
}

func validatedAddresses(endpoints []runtime.Endpoint) (map[string]string, error) {
	if len(endpoints) != len(sensorOrder) {
		return nil, fmt.Errorf("demo: runtime exposed %d sensor endpoints, want %d", len(endpoints), len(sensorOrder))
	}
	out := make(map[string]string, len(endpoints))
	for i, endpoint := range endpoints {
		wantKind := sensorOrder[i]
		if endpoint.Kind != wantKind || endpoint.ID != "demo-"+wantKind {
			return nil, fmt.Errorf("demo: unexpected sensor endpoint %q (%s)", endpoint.ID, endpoint.Kind)
		}
		if _, duplicate := out[endpoint.Kind]; duplicate {
			return nil, fmt.Errorf("demo: duplicate %s endpoint", endpoint.Kind)
		}
		if err := validateLoopback(endpoint.Addr); err != nil {
			return nil, fmt.Errorf("demo: %s endpoint: %w", endpoint.Kind, err)
		}
		out[endpoint.Kind] = endpoint.Addr
	}
	return out, nil
}

func validateLoopback(addr string) error {
	host, rawPort, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid bound address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("bound address %q is not an IP loopback", addr)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1024 || port > 65535 {
		return fmt.Errorf("bound address %q is not an unprivileged assigned port", addr)
	}
	return nil
}

func checkReady(ctx context.Context, addr string) error {
	status, _, err := request(ctx, http.MethodGet, "http://"+addr+"/readyz", nil)
	if err != nil {
		return fmt.Errorf("demo: readiness: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("demo: readiness returned HTTP %d", status)
	}
	return nil
}

func interactHTTP(ctx context.Context, addr string) error {
	status, body, err := request(ctx, http.MethodGet, "http://"+addr+"/", nil)
	if err != nil {
		return fmt.Errorf("demo: HTTP sensor: %w", err)
	}
	if status != http.StatusOK || string(body) != "synthetic demo\n" {
		return fmt.Errorf("demo: HTTP sensor returned an unexpected response")
	}
	return nil
}

func interactMCP(ctx context.Context, addr string) error {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"canary_demo","arguments":{"scope":"synthetic"}}}`)
	status, reply, err := request(ctx, http.MethodPost, "http://"+addr+"/mcp", body)
	if err != nil {
		return fmt.Errorf("demo: MCP sensor: %w", err)
	}
	if status != http.StatusOK || !bytes.Contains(reply, []byte(`"ok":true`)) {
		return fmt.Errorf("demo: MCP sensor returned an unexpected response")
	}
	return nil
}

func request(ctx context.Context, method, target string, body []byte, headers ...map[string]string) (int, []byte, error) {
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, method, target, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if len(headers) > 0 {
		for k, v := range headers[0] {
			req.Header.Set(k, v)
		}
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("demo redirects are disabled")
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	reply, err := io.ReadAll(io.LimitReader(resp.Body, maxReplyBytes+1))
	if err != nil {
		return 0, nil, err
	}
	if len(reply) > maxReplyBytes {
		return 0, nil, errors.New("response exceeded the demo byte limit")
	}
	return resp.StatusCode, reply, nil
}

func interactTCP(ctx context.Context, addr string) error {
	conn, err := (&net.Dialer{Timeout: requestTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("demo: TCP sensor: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(connectionDeadline(ctx)); err != nil {
		return fmt.Errorf("demo: TCP sensor: %w", err)
	}
	r := bufio.NewReaderSize(conn, maxTCPLineBytes+1)
	banner, err := readTCPLine(r)
	if err != nil || banner != "AEGISMESH DEMO\n" {
		return fmt.Errorf("demo: TCP sensor returned an unexpected banner")
	}
	if _, err := io.WriteString(conn, "PING\n"); err != nil {
		return fmt.Errorf("demo: TCP sensor: %w", err)
	}
	reply, err := readTCPLine(r)
	if err != nil || reply != "+OK PONG\n" {
		return fmt.Errorf("demo: TCP sensor returned an unexpected response")
	}
	return nil
}

func readTCPLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > maxTCPLineBytes {
		return "", errors.New("TCP response exceeded the demo line limit")
	}
	if err != nil {
		return "", err
	}
	return string(line), nil
}

func verifyListenersReleased(addresses map[string]string, adminAddr string) error {
	targets := make([]string, 0, len(sensorOrder)+1)
	for _, kind := range sensorOrder {
		targets = append(targets, addresses[kind])
	}
	targets = append(targets, adminAddr)
	for _, addr := range targets {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err != nil {
			continue
		}
		_ = conn.Close()
		return fmt.Errorf("demo: listener %q remained reachable after shutdown", addr)
	}
	return nil
}

func interactSSH(ctx context.Context, addr string) error {
	conn, err := (&net.Dialer{Timeout: requestTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("demo: SSH sensor: %w", err)
	}
	if err := conn.SetDeadline(connectionDeadline(ctx)); err != nil {
		conn.Close()
		return fmt.Errorf("demo: SSH sensor: %w", err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:            "aegismesh-demo-synthetic-user",
		Auth:            []ssh.AuthMethod{ssh.Password("aegismesh-demo-synthetic-password")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // self-owned ephemeral loopback decoy
		Timeout:         requestTimeout,
	})
	if err != nil {
		conn.Close()
		return fmt.Errorf("demo: SSH sensor handshake: %w", err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	if channel, requests, err := client.OpenChannel("session", nil); err == nil {
		_ = channel.Close()
		go ssh.DiscardRequests(requests)
		client.Close()
		return errors.New("demo: SSH sensor accepted a session channel")
	}
	if err := client.Close(); err != nil {
		return fmt.Errorf("demo: SSH sensor close: %w", err)
	}
	return nil
}

func connectionDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(requestTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		return contextDeadline
	}
	return deadline
}

func verifyEvidence(dataDir string, tokens []honeytoken.Token) (Summary, error) {
	reader, err := storage.NewReader(dataDir)
	if err != nil {
		return Summary{}, fmt.Errorf("demo: open evidence: %w", err)
	}
	var envelopes []event.Envelope
	var corruptErr error
	err = reader.ForEach(func(envelope event.Envelope) error {
		if len(envelopes) == maxEvents {
			return errors.New("demo: evidence exceeded the event limit")
		}
		if err := envelope.Validate(); err != nil {
			return fmt.Errorf("demo: validate evidence: %w", err)
		}
		if err := envelope.VerifyIntegrity(); err != nil {
			return fmt.Errorf("demo: verify evidence: %w", err)
		}
		raw, err := json.Marshal(envelope)
		if err != nil {
			return fmt.Errorf("demo: encode evidence for redaction check: %w", err)
		}
		secrets := []string{"aegismesh-demo-synthetic-user", "aegismesh-demo-synthetic-password"}
		for _, token := range tokens {
			secrets = append(secrets, token.Value)
		}
		for _, secret := range secrets {
			if strings.Contains(string(raw), secret) {
				return errors.New("demo: SSH synthetic credential content reached evidence")
			}
		}
		envelopes = append(envelopes, envelope)
		return nil
	}, func(_ string, readErr error) {
		if corruptErr == nil {
			corruptErr = readErr
		}
	})
	if err != nil {
		return Summary{}, err
	}
	if corruptErr != nil {
		return Summary{}, fmt.Errorf("demo: corrupt evidence: %w", corruptErr)
	}
	if len(envelopes) != 8 {
		return Summary{}, fmt.Errorf("demo: recorded %d observations, want 8", len(envelopes))
	}

	counts := map[string]int{}
	bySensor := map[string]int{}
	for _, envelope := range envelopes {
		counts[envelope.Classification]++
		bySensor[envelope.Sensor.ID]++
	}
	if counts[event.ClassificationInteraction] != 7 || counts[event.ClassificationCanaryHit] != 1 {
		return Summary{}, fmt.Errorf("demo: unexpected evidence classifications")
	}
	for _, kind := range sensorOrder {
		want := 1
		if kind == "http" {
			want = 5
		}
		if bySensor["demo-"+kind] != want {
			return Summary{}, fmt.Errorf("demo: sensor %s did not record the expected observations", kind)
		}
	}
	report, err := recommend.Generate(envelopes, recommend.Options{})
	if err != nil {
		return Summary{}, fmt.Errorf("demo: generate dry-run recommendations: %w", err)
	}
	if len(report.Recommendations) != 5 {
		return Summary{}, fmt.Errorf("demo: generated %d recommendations, want 5", len(report.Recommendations))
	}

	hits := map[string]bool{}
	for _, envelope := range envelopes {
		var obs struct {
			Detection *struct {
				Findings []detect.Finding `json:"findings"`
			} `json:"detection"`
		}
		if json.Unmarshal(envelope.Observation, &obs) != nil {
			return Summary{}, errors.New("demo: invalid detection evidence")
		}
		if obs.Detection != nil {
			for _, finding := range obs.Detection.Findings {
				if detect.ObserveOnly(finding.RuleID) {
					hits[string(finding.RuleID)] = true
				}
			}
		}
	}
	var rules []string
	for _, id := range detect.KnownRuleIDs() {
		if hits[id] {
			rules = append(rules, id)
		}
	}
	for _, id := range []string{"LLM-001", "LLM-002", "LLM-004", "HT-001", "AGT-001"} {
		if !hits[id] {
			return Summary{}, fmt.Errorf("demo: missing expected observation %s", id)
		}
	}
	return Summary{
		DetectionRules:    rules,
		Schema:            schema,
		Mode:              "synthetic",
		Network:           "loopback-only",
		Egress:            "none",
		Sensors:           append([]string(nil), sensorOrder[:]...),
		Events:            len(envelopes),
		Interactions:      counts[event.ClassificationInteraction],
		CanaryInvocations: counts[event.ClassificationCanaryHit],
		IntegrityVerified: true,
		Recommendations:   len(report.Recommendations),
		DryRun:            true,
		Enforcement:       false,
		SignalNotIncident: true,
	}, nil
}

func interactAI(ctx context.Context, addr string, tokens []honeytoken.Token) error {
	if len(tokens) != 2 {
		return errors.New("demo: missing synthetic markers")
	}
	for _, step := range []struct {
		method, path, body string
		headers            map[string]string
	}{
		{"GET", "/api/tags", "", nil},
		{"POST", "/v1/chat/completions", `{"model":"synthetic","messages":[{"role":"user","content":"hi"}],"max_tokens":1}`, nil},
		{"GET", "/v1/models", "", map[string]string{"Authorization": "Bearer " + tokens[0].Value}},
		{"GET", "/diagnostic/" + tokens[1].Value, "", nil},
	} {
		status, _, err := request(ctx, step.method, "http://"+addr+step.path, []byte(step.body), step.headers)
		if err != nil {
			return fmt.Errorf("demo: synthetic AI sequence: %w", err)
		}
		if status != http.StatusOK && status != http.StatusNotFound {
			return errors.New("demo: unexpected AI decoy response")
		}
	}
	return nil
}
