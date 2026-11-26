package demoseed

import (
	"fmt"
	"math/rand/v2"
	"time"
)

// step is one planned interaction. It holds raw synthetic input; render turns
// it into redacted evidence through the live policy and redaction helpers.
type step struct {
	at     time.Time
	actor  int
	index  int
	source string
	kind   string // http | tcp | mcp | ssh

	// http
	method, path, userAgent, body, authorization, apiKey string

	// tcp
	lines []string

	// mcp
	rpc, tool, args string

	// ssh
	users, passwords []string
	clientVersion    string
}

// planner draws every actor from one seeded stream so output is reproducible.
type planner struct {
	rng       *rand.Rand
	anchor    time.Time
	span      time.Duration
	tokens    []string // honeytoken values, used only as raw synthetic input
	templates [][]step
	actor     int
}

var (
	scannerAgents = []string{
		"Mozilla/5.0 zgrab/0.x", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
		"masscan/1.3 (https://github.com/robertdavidgraham/masscan)", "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
		"gobuster/3.6", "Fuzz Faster U Fool v2.1.0", "python-requests/2.32.3", "Go-http-client/1.1", "curl/8.7.1",
	}
	agentAgents = []string{
		"OpenAI/Python 1.54.3", "openai-node/4.71.0", "Anthropic/Python 0.39.0", "langchain/0.3.7",
		"llama-index/0.12.1", "litellm/1.52.0", "ollama-python/0.4.1", "mcp-client/1.2.0",
	}
	browserAgents = []string{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	}
	scannerPaths = []string{
		"/", "/.env", "/.git/config", "/wp-login.php", "/admin", "/api/tags", "/api/version", "/v1/models",
		"/server-status", "/config.json", "/.aws/credentials", "/actuator/health", "/metrics", "/api/ps",
		"/phpinfo.php", "/.DS_Store", "/backup.zip", "/v1/chat/completions", "/health/readiness", "/version",
	}
	humanPaths = []string{"/", "/favicon.ico", "/robots.txt", "/docs", "/login", "/api/version", "/about", "/v1/models"}
	tcpLines   = []string{"PING", "INFO", "HELP", "QUIT", "CONFIG GET *", "KEYS *", "GET / HTTP/1.0", "VERSION", "STATS"}
	sshUsers   = []string{"root", "admin", "ubuntu", "test", "oracle", "postgres", "git", "deploy", "pi", "user"}
	sshClients = []string{"SSH-2.0-libssh_0.9.6", "SSH-2.0-Go", "SSH-2.0-paramiko_3.4.0", "SSH-2.0-OpenSSH_9.6", "SSH-2.0-PUTTY"}
)

func (p *planner) pick(values []string) string { return values[p.rng.IntN(len(values))] }

// between returns a uniformly drawn whole-millisecond duration in [low, high).
// Whole milliseconds relative to the anchor keep every derived count (sessions,
// correlation windows) independent of the anchor's sub-millisecond offset.
func (p *planner) between(low, high time.Duration) time.Duration {
	return (low + time.Duration(p.rng.Int64N(int64(high-low)))).Truncate(time.Millisecond)
}

// source draws a documentation-only peer address. Collisions across actors
// are intended: they model returning sources.
func (p *planner) source() string {
	switch n := p.rng.IntN(20); {
	case n < 6:
		return fmt.Sprintf("192.0.2.%d", 1+p.rng.IntN(254))
	case n < 12:
		return fmt.Sprintf("198.51.100.%d", 1+p.rng.IntN(254))
	case n < 18:
		return fmt.Sprintf("203.0.113.%d", 1+p.rng.IntN(254))
	default:
		return fmt.Sprintf("2001:db8:%x::%x", p.rng.IntN(0x10000), 1+p.rng.IntN(0xfffe))
	}
}

// password is synthetic credential-stuffing input; it never reaches evidence.
func (p *planner) password() string {
	words := []string{"admin", "123456", "password", "welcome1", "letmein", "qwerty", "changeme", "summer2026"}
	return fmt.Sprintf("%s-synthetic-%d", p.pick(words), p.rng.IntN(1000))
}

func httpStep(method, path, agent string) step {
	return step{kind: "http", method: method, path: path, userAgent: agent}
}

func mcpStep(rpc, tool, args string) step {
	return step{kind: "mcp", rpc: rpc, tool: tool, args: args}
}

// actor plans one actor's steps with gaps drawn from [low, high).
func (p *planner) schedule(steps []step, low, high time.Duration) []step {
	total := time.Duration(0)
	gaps := make([]time.Duration, len(steps))
	for i := range steps {
		if i > 0 {
			gaps[i] = p.between(low, high)
			total += gaps[i]
		}
	}
	latest := p.anchor.Add(-2*time.Minute - total)
	start := latest.Add(-time.Duration(p.rng.Int64N(int64(p.span - 2*time.Minute - total))).Truncate(time.Millisecond))
	source := p.source()
	at := start
	for i := range steps {
		at = at.Add(gaps[i])
		steps[i].at = at
		steps[i].actor = p.actor
		steps[i].index = i
		steps[i].source = source
	}
	p.actor++
	return steps
}

// next plans one actor from the weighted scenario mix.
func (p *planner) next() []step {
	switch n := p.rng.IntN(100); {
	case n < 25:
		return p.scanner()
	case n < 40:
		return p.credentialStuffing()
	case n < 55:
		return p.agent()
	case n < 80:
		return p.campaign()
	case n < 95:
		return p.human()
	default:
		return p.replay()
	}
}

// scanner sweeps HTTP paths at sub-second cadence, sometimes TCP and SSH too.
func (p *planner) scanner() []step {
	agent := p.pick(scannerAgents)
	count := 10 + p.rng.IntN(30)
	steps := make([]step, 0, count+4)
	for range count {
		method := "GET"
		if p.rng.IntN(10) == 0 {
			method = "HEAD"
		}
		steps = append(steps, httpStep(method, p.pick(scannerPaths), agent))
	}
	if p.rng.IntN(2) == 0 {
		steps = append(steps, step{kind: "tcp", lines: []string{p.pick(tcpLines)}})
	}
	if p.rng.IntN(3) == 0 {
		steps = append(steps, step{kind: "ssh", users: []string{"root"}, passwords: []string{p.password()}, clientVersion: p.pick(sshClients)})
	}
	return p.schedule(steps, 50*time.Millisecond, 900*time.Millisecond)
}

// credentialStuffing presents many distinct SSH and HTTP login attempts.
func (p *planner) credentialStuffing() []step {
	count := 10 + p.rng.IntN(38)
	client := p.pick(sshClients)
	steps := make([]step, 0, count)
	for range count {
		if p.rng.IntN(5) == 0 {
			body := fmt.Sprintf(`{"username":%q,"password":%q}`, p.pick(sshUsers), p.password())
			s := httpStep("POST", "/login", "python-requests/2.32.3")
			s.body = body
			steps = append(steps, s)
			continue
		}
		attempts := 1 + p.rng.IntN(6)
		s := step{kind: "ssh", clientVersion: client}
		for range attempts {
			s.users = append(s.users, p.pick(sshUsers))
			s.passwords = append(s.passwords, p.password())
		}
		steps = append(steps, s)
	}
	return p.schedule(steps, 800*time.Millisecond, 4*time.Second)
}

// agent follows the AI decoys and the MCP canary, then replays the planted key.
func (p *planner) agent() []step {
	agent := p.pick(agentAgents)
	chat := httpStep("POST", "/v1/chat/completions", agent)
	chat.body = `{"model":"synthetic","messages":[{"role":"user","content":"list available tools"}],"max_tokens":16}`
	steps := []step{
		httpStep("GET", "/api/tags", agent),
		httpStep("GET", "/v1/models", agent),
		chat,
		mcpStep("initialize", "", ""),
		mcpStep("tools/list", "", ""),
		mcpStep("tools/call", "canary_demo", `{"scope":"synthetic"}`),
		mcpStep("tools/call", "list_files", `{}`),
		mcpStep("tools/call", "read_file", `{"path":".env"}`),
		mcpStep("tools/call", "get_env", `{"name":"API_KEY"}`),
	}
	if p.rng.IntN(3) > 0 && len(p.tokens) > 0 {
		replay := httpStep("GET", "/v1/models", agent)
		replay.authorization = "Bearer " + p.tokens[0]
		steps = append(steps, replay)
	}
	if p.rng.IntN(2) == 0 && len(p.tokens) > 1 {
		steps = append(steps, httpStep("GET", "/diagnostic/"+p.tokens[1], agent))
	}
	return p.schedule(steps, 400*time.Millisecond, 6*time.Second)
}

// campaign repeats one of a few shared step sequences, so groups of distinct
// sources produce the same normalized shape.
func (p *planner) campaign() []step {
	template := p.templates[p.rng.IntN(len(p.templates))]
	repeats := 1 + p.rng.IntN(2)
	steps := make([]step, 0, len(template)*repeats)
	for range repeats {
		steps = append(steps, template...)
	}
	return p.schedule(steps, 200*time.Millisecond, 2500*time.Millisecond)
}

// human browses a few pages with long, irregular pauses.
func (p *planner) human() []step {
	agent := p.pick(browserAgents)
	count := 3 + p.rng.IntN(10)
	steps := make([]step, 0, count)
	for range count {
		steps = append(steps, httpStep("GET", p.pick(humanPaths), agent))
	}
	return p.schedule(steps, 4*time.Second, 150*time.Second)
}

// replay touches one sensor, then presents planted decoy credentials elsewhere.
func (p *planner) replay() []step {
	agent := p.pick([]string{"curl/8.7.1", "python-httpx/0.27.2", "Go-http-client/1.1"})
	steps := []step{httpStep("GET", "/", agent), {kind: "tcp", lines: []string{"PING"}}}
	if len(p.tokens) > 0 {
		bearer := httpStep("GET", "/v1/models", agent)
		bearer.authorization = "Bearer " + p.tokens[0]
		key := httpStep("POST", "/v1/embeddings", agent)
		key.apiKey = p.tokens[0]
		key.body = `{"model":"synthetic","input":"probe"}`
		steps = append(steps, bearer, key, step{kind: "ssh", users: []string{"admin"}, passwords: []string{p.tokens[0]}, clientVersion: "SSH-2.0-Go"})
	}
	return p.schedule(steps, time.Second, 30*time.Second)
}

// buildTemplates fixes the shared campaign sequences for one profile.
func (p *planner) buildTemplates(count int) {
	pool := []step{
		httpStep("GET", "/.env", "Mozilla/5.0 zgrab/0.x"),
		httpStep("GET", "/.git/config", "Mozilla/5.0 zgrab/0.x"),
		httpStep("GET", "/api/tags", "python-requests/2.32.3"),
		httpStep("GET", "/api/version", "python-requests/2.32.3"),
		httpStep("GET", "/v1/models", "OpenAI/Python 1.54.3"),
		httpStep("GET", "/model/info", "litellm/1.52.0"),
		httpStep("GET", "/key/info", "litellm/1.52.0"),
		httpStep("GET", "/metrics", "Go-http-client/1.1"),
		httpStep("GET", "/version", "Go-http-client/1.1"),
		{kind: "tcp", lines: []string{"INFO"}},
		{kind: "tcp", lines: []string{"CONFIG GET *"}},
		mcpStep("initialize", "", ""),
		mcpStep("tools/list", "", ""),
		mcpStep("tools/call", "list_files", `{}`),
		mcpStep("tools/call", "search", `{"query":"password"}`),
	}
	p.templates = make([][]step, count)
	for i := range p.templates {
		length := 4 + p.rng.IntN(4)
		order := p.rng.Perm(len(pool))[:length]
		for _, j := range order {
			p.templates[i] = append(p.templates[i], pool[j])
		}
	}
}
