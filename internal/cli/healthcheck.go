package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/metaforismo/aegismesh/internal/egress"
)

// The healthcheck command is a self-probe for environments without a shell
// (distroless containers): one GET against the validated loopback admin
// listener taken from the same strict config the runtime uses, verdict in
// the exit code. It intentionally exposes no URL/host/path/header knobs:
// the blast radius is one request to two fixed paths on loopback.

const (
	healthcheckDefaultTimeout = 2 * time.Second
	healthcheckMaxTimeout     = 10 * time.Second
	// healthcheckMaxBodyBytes caps how much of a response body is drained
	// before close. Body content never influences the verdict and is never
	// echoed; the cap only keeps a misbehaving peer from holding the probe.
	healthcheckMaxBodyBytes = 4 << 10
)

type healthcheckCmd struct {
	env *Env
}

func newHealthcheckCmd(env *Env) *healthcheckCmd { return &healthcheckCmd{env: env} }

func (c *healthcheckCmd) Name() string { return "healthcheck" }

func (c *healthcheckCmd) Usage() string {
	return "healthcheck --config FILE (--live | --ready) [--timeout DURATION]"
}

func (c *healthcheckCmd) Help() string {
	return `Probe this process's loopback admin endpoint and exit by result.

Loads --config strictly, derives the validated admin listener from it, and
issues exactly one HTTP GET to the fixed path /healthz (--live) or /readyz
(--ready) on that listener. Redirects are refused, proxy environment
variables are ignored, and arbitrary hosts, paths, headers, or credentials
are impossible by construction. Sensors never start and storage is never
created. Response bodies are bounded, discarded, and never echoed.

Exit codes: 0 healthy; 1 unhealthy, unreachable, or invalid config (the
category is on stderr); 2 usage error. Built for Kubernetes exec probes on
distroless images where no shell or curl exists: rely on the exit code;
stdout carries one human-readable line.`
}

func (c *healthcheckCmd) Run(_ context.Context, args []string) error {
	fs := newFlagSet(c.Name())
	cfgPath := fs.String("config", "", "path to mesh.yaml (required)")
	live := fs.Bool("live", false, "GET /healthz (liveness)")
	ready := fs.Bool("ready", false, "GET /readyz (readiness)")
	timeout := fs.Duration("timeout", healthcheckDefaultTimeout,
		"probe deadline (>0, at most "+healthcheckMaxTimeout.String()+")")
	if err := fs.Parse(args); err != nil {
		return Usagef("%v", err)
	}
	if fs.NArg() > 0 {
		return Usagef("unexpected argument %q", fs.Arg(0))
	}
	if *cfgPath == "" {
		return Usagef("--config FILE is required")
	}
	if *live == *ready {
		return Usagef("exactly one of --live or --ready is required")
	}
	if *timeout <= 0 || *timeout > healthcheckMaxTimeout {
		return Usagef("--timeout must be greater than 0 and at most %s", healthcheckMaxTimeout)
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return fmt.Errorf("config invalid: %v", err)
	}
	if !cfg.Admin.IsEnabled() {
		return fmt.Errorf("config invalid: admin listener is disabled; nothing to probe")
	}

	mode, path := "live", "/healthz"
	if *ready {
		mode, path = "ready", "/readyz"
	}

	target, err := loopbackAdminTarget(cfg.Admin.Listen)
	if err != nil {
		return fmt.Errorf("admin address unsafe: %v", err)
	}

	url := "http://" + target + path
	if err := probeLoopback(url, *timeout); err != nil {
		return err
	}
	fmt.Fprintf(c.env.Out, "healthcheck ok mode=%s path=%s target=%s\n", mode, path, target)
	return nil
}

// loopbackAdminTarget independently re-validates the admin listener even
// though config.Load already enforces the invariant: a probe must refuse an
// unsafe dial target even if shared validation is ever loosened by mistake.
// Returns host:port suitable both for dialing and URL construction.
func loopbackAdminTarget(listen string) (string, error) {
	host, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("listener %q is malformed (%v)", listen, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		// Port 0 means "OS-assigned" at bind time and is unprobeable here.
		return "", fmt.Errorf("listener %q has unsupported port %q", listen, portStr)
	}
	switch {
	case host == "":
		host = "127.0.0.1" // ":port" binds wildcard server-side; probe loopback only
	case host == "localhost":
		// kept literal: resolves to loopback via the system resolver
	default:
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return "", fmt.Errorf("host %q is not a loopback address", host)
		}
	}
	return net.JoinHostPort(host, portStr), nil
}

// probeLoopback issues exactly one GET to the given loopback URL with
// redirects refused and proxies disabled, requires HTTP 200, bounds and
// discards the body, and always closes it. No goroutines are left behind.
func probeLoopback(url string, timeout time.Duration) error {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:             nil, // ignore HTTP_PROXY and friends: target is local
			DisableKeepAlives: true,
		},
		CheckRedirect: egress.RefuseAllRedirects,
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("probe request build failed: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() {
			return fmt.Errorf("timeout after %s contacting %s", timeout, url)
		}
		return fmt.Errorf("connect failed: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, healthcheckMaxBodyBytes))
	switch {
	case resp.StatusCode == http.StatusOK:
		return nil
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return fmt.Errorf("unhealthy: HTTP %d from %s (redirect refused)", resp.StatusCode, url)
	default:
		return fmt.Errorf("unhealthy: HTTP %d from %s", resp.StatusCode, url)
	}
}
