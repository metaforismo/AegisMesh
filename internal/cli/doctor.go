package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/egress"
)

// check is one doctor finding.
type check struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok | warn | fail
	Detail string `json:"detail,omitempty"`
	Hint   string `json:"hint,omitempty"`
}

type doctorReport struct {
	ConfigPath string  `json:"config_path"`
	SchemaOK   bool    `json:"schema_ok"`
	Overall    string  `json:"overall"` // ok | warn | fail
	Checks     []check `json:"checks"`
}

type doctorCmd struct {
	env *Env
	g   globals
}

func newDoctorCmd(env *Env) *doctorCmd { return &doctorCmd{env: env} }

func (c *doctorCmd) Name() string  { return "doctor" }
func (c *doctorCmd) Usage() string { return "doctor --config FILE [--probe-provider] [--json]" }
func (c *doctorCmd) Help() string {
	return `Check the local environment before running: config validity, storage
writability, port availability, safety-flag warnings, and provider
readiness.

Provider checks are STATIC by default (URL policy classification and
credential-reference presence — no network activity). Pass
--probe-provider to additionally send one bounded GET <base_url>/models
to the configured endpoint; it verifies reachability only, sends no
prompt data, and never runs by default.

Exit codes: 0 all clear, 1 at least one failure (warnings do not fail).`
}

func (c *doctorCmd) Run(ctx context.Context, args []string) error {
	fs := newFlagSet(c.Name())
	addGlobalFlags(fs, &c.g)
	cfgPath := fs.String("config", "mesh.yaml", "path to mesh.yaml")
	probe := fs.Bool("probe-provider", false, "opt-in: contact the configured provider endpoint with one bounded GET /models")
	if err := fs.Parse(args); err != nil {
		return Usagef("%v", err)
	}
	if fs.NArg() > 0 {
		return Usagef("unexpected argument %q", fs.Arg(0))
	}

	rep := doctorReport{ConfigPath: *cfgPath}
	add := func(status, name, detail, hint string) {
		rep.Checks = append(rep.Checks, check{Name: name, Status: status, Detail: detail, Hint: hint})
	}

	cfg, cfgErr := loadConfig(*cfgPath)
	if cfgErr != nil {
		add("fail", "config", cfgErr.Error(), "fix the reported field or regenerate with 'aegismesh init'")
		return c.render(rep)
	}
	rep.SchemaOK = true
	add("ok", "config", fmt.Sprintf("%s valid (schema %s, %d sensor(s))", cfg.SourcePath, cfg.APIVersion, len(cfg.Sensors)), "")

	// Storage writability probe (creates nothing persistent).
	dataDir := cfg.Runtime.DataDir
	if !filepath.IsAbs(dataDir) {
		dataDir = filepath.Join(filepath.Dir(cfg.SourcePath), dataDir)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		add("fail", "storage", fmt.Sprintf("data dir %s not creatable: %v", dataDir, err), "check permissions or set runtime.data_dir")
	} else {
		probe, perr := os.CreateTemp(dataDir, ".doctor-probe-*")
		if perr != nil {
			add("fail", "storage", fmt.Sprintf("data dir %s not writable: %v", dataDir, perr), "check ownership")
		} else {
			name := probe.Name()
			_ = probe.Close()
			_ = os.Remove(name)
			add("ok", "storage", fmt.Sprintf("data dir %s writable", dataDir), "")
		}
	}

	// Port availability per sensor + admin.
	for i := range cfg.Sensors {
		s := &cfg.Sensors[i]
		st, detail := probePort(s.Listen)
		add(st, "port:"+s.ID, detail, "stop the conflicting process or change sensors[].listen")
	}
	if cfg.Admin.IsEnabled() {
		st, detail := probePort(cfg.Admin.Listen)
		add(st, "port:admin", detail, "stop the conflicting process or change admin.listen")
	}

	// Safety posture reporting: loud but non-failing.
	if cfg.Security.AllowPublicBind {
		add("warn", "bind-policy", "security.allow_public_bind=true — decoys may bind beyond loopback", "revert unless this is a deliberate network placement")
	}
	if cfg.Security.AllowPrivilegedPorts {
		add("warn", "port-policy", "security.allow_privileged_ports=true — decoys may bind ports <1024", "prefer unprivileged ports; run a port-forward instead")
	}
	switch cfg.LLM.Provider {
	case "local":
		add("ok", "llm", "deterministic local provider (no egress)", "")
	case "ollama", "openai":
		st, detail, hint := providerStaticReadiness(cfg)
		add(st, "llm", detail, hint)
		if *probe {
			st, detail, hint = probeProvider(ctx, cfg)
			add(st, "llm-probe", detail, hint)
		}
	default:
		add("fail", "llm", fmt.Sprintf("provider %q unsupported", cfg.LLM.Provider), "use local|ollama|openai")
	}

	return c.render(rep)
}

// providerStaticReadiness classifies the configured endpoint against the
// egress policy and reports credential-reference presence WITHOUT ever
// printing secret values or file contents.
func providerStaticReadiness(cfg *config.Config) (string, string, string) {
	class, _ := classifyProviderEndpoint(cfg)
	if strings.HasPrefix(class, "DENIED") {
		return "fail", fmt.Sprintf("provider endpoint rejected by egress policy (%s): %s", cfg.LLM.Provider, class),
			"fix llm.base_url; see docs/configuration.md for the destination rules"
	}
	keyRef := "no credential reference (endpoint will be contacted anonymously)"
	switch {
	case cfg.LLM.APIKeyEnv != "":
		set := false
		if v := os.Getenv(cfg.LLM.APIKeyEnv); strings.TrimSpace(v) != "" {
			set = true
		}
		state := "UNSET"
		if set {
			state = "set"
		}
		keyRef = fmt.Sprintf("api_key_env %s is %s", cfg.LLM.APIKeyEnv, state)
	case cfg.LLM.APIKeyFile != "":
		base := filepath.Dir(cfg.SourcePath)
		full := filepath.Join(base, filepath.Clean(cfg.LLM.APIKeyFile))
		if _, err := os.Stat(full); err != nil {
			return "warn", fmt.Sprintf("provider %s, %s; api_key_file %q not readable: %v", cfg.LLM.Provider, class, cfg.LLM.APIKeyFile, err),
				"create the key file or switch to api_key_env"
		}
		keyRef = fmt.Sprintf("api_key_file %q readable", cfg.LLM.APIKeyFile)
	}
	return "ok", fmt.Sprintf("provider %s ready (%s); %s", cfg.LLM.Provider, class, keyRef), ""
}

// probeProvider performs the explicit network check: one GET /models with a
// short deadline through the guarded transport. It verifies reachability
// only — no auth header, no prompt data.
func probeProvider(ctx context.Context, cfg *config.Config) (string, string, string) {
	pol := egress.Policy{
		AllowLoopback: cfg.LLM.Provider == "ollama",
		AllowPrivate:  cfg.Security.AllowPrivateLLMEgress,
	}
	client := &http.Client{
		Timeout:       3 * time.Second,
		Transport:     &http.Transport{DialContext: egress.NewDialer(pol, 2*time.Second).DialContext},
		CheckRedirect: egress.RefuseAllRedirects,
	}
	endpoint := strings.TrimRight(cfg.LLM.BaseURL, "/") + "/models"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "fail", fmt.Sprintf("probe request build failed: %v", err), ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return "warn", fmt.Sprintf("provider unreachable at %s: %v", endpoint, err),
			"start the local daemon or check connectivity; decoys still run with static fallback"
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck // drain only
	// Any HTTP answer proves reachability — 401 without credentials is fine.
	return "ok", fmt.Sprintf("probe: %s answered HTTP %d (reachability only; no data sent)", endpoint, resp.StatusCode), ""
}

func probePort(addr string) (string, string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "fail", fmt.Sprintf("%s unavailable: %v", addr, err)
	}
	_ = ln.Close()
	return "ok", fmt.Sprintf("%s available", addr)
}

func (c *doctorCmd) render(rep doctorReport) error {
	overall := "ok"
	for _, ch := range rep.Checks {
		if ch.Status == "fail" {
			overall = "fail"
		} else if ch.Status == "warn" && overall != "fail" {
			overall = "warn"
		}
	}
	rep.Overall = overall

	if c.g.jsonOut {
		return writeJSON(c.env.Out, rep)
	}
	statusIcon := map[string]string{"ok": "[ ok ]", "warn": "[warn]", "fail": "[FAIL]"}
	fmt.Fprintf(c.env.Out, "aegismesh doctor — %s\n", rep.ConfigPath)
	for _, ch := range rep.Checks {
		line := fmt.Sprintf("%s %-14s %s", statusIcon[ch.Status], ch.Name, ch.Detail)
		fmt.Fprintln(c.env.Out, line)
		if ch.Hint != "" && ch.Status != "ok" {
			fmt.Fprintf(c.env.Out, "       hint: %s\n", ch.Hint)
		}
	}
	fmt.Fprintf(c.env.Out, "overall: %s\n", overall)
	if overall == "fail" {
		return fmt.Errorf("doctor found %d blocking problem(s); see output above", countFailures(rep))
	}
	return nil
}

func countFailures(rep doctorReport) int {
	n := 0
	for _, ch := range rep.Checks {
		if ch.Status == "fail" {
			n++
		}
	}
	return n
}
