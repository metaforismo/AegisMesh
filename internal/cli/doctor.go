package cli

import (
	"context"

	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/metaforismo/aegismesh/internal/config"
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
func (c *doctorCmd) Usage() string { return "doctor --config FILE [--json]" }
func (c *doctorCmd) Help() string {
	return `Check the local environment before running: config validity, storage
writability, port availability, and safety-flag warnings.

Exit codes: 0 all clear, 1 at least one failure (warnings do not fail).`
}

func (c *doctorCmd) Run(_ context.Context, args []string) error {
	fs := newFlagSet(c.Name())
	addGlobalFlags(fs, &c.g)
	cfgPath := fs.String("config", "mesh.yaml", "path to mesh.yaml")
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
	case "openai":
		if keySet(cfg) {
			add("warn", "llm", "remote provider openai configured — provider output is untrusted data; egress will occur", "keep base_url allowlisted")
		} else {
			add("fail", "llm", "provider=openai but AEGISMESH_LLM_API_KEY is not set", "export the key or switch to llm.provider=local")
		}
	}

	return c.render(rep)
}

func keySet(cfg *config.Config) bool { return cfg.LLM.APIKey != "" }

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
