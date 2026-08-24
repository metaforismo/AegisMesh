package sensorproc

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/sensor"
)

const (
	startupTimeout = 15 * time.Second
	stopGrace      = 2 * time.Second
)

var (
	errWorkerClosed     = errors.New("sensorproc: worker closed before readiness")
	errProtocol         = errors.New("sensorproc: worker protocol violation")
	errWorkerTerminated = errors.New("sensorproc: worker terminated")
)

// Command is the deliberately narrow process seam. Production uses a fixed
// current executable and WorkerArg; tests inject an in-memory or helper
// command without changing the launch policy.
type Command struct {
	Stdin   deadlineWriteCloser
	Stdout  io.ReadCloser
	Start   func() error
	Wait    func() error
	Stop    func() error
	Kill    func() error
	Cleanup func()
}

type deadlineWriteCloser interface {
	io.WriteCloser
	SetWriteDeadline(time.Time) error
}

// CommandFactory cannot receive executable, argv, environment, or directory
// input. Those values are owned by the package's fixed factory.
type CommandFactory func() (*Command, error)

type ProxyOptions struct {
	Spec    WorkerSpec
	Factory CommandFactory
}

// Proxy is a sensor.Sensor backed by one child process. A failed child is
// terminal and marks only this proxy unhealthy; there is intentionally no
// automatic restart in this first isolation slice.
type Proxy struct {
	spec      WorkerSpec
	factory   CommandFactory
	challenge string

	mu        sync.RWMutex
	deps      sensor.Deps
	cmd       *Command
	addr      string
	starting  bool
	attempted bool
	started   bool
	healthy   bool
	closing   bool
	stopErr   error

	done      chan error
	doneOnce  sync.Once
	closeOnce sync.Once
	closeCh   chan struct{}
	stopOnce  sync.Once
	stopDone  chan struct{}
	startDone chan struct{}
	ready     chan error
	waitDone  chan struct{}
	writeMu   sync.Mutex
	readySeen bool
	metrics   metricCache
}

var _ sensor.Sensor = (*Proxy)(nil)

func NewProxy(opts ProxyOptions) (*Proxy, error) {
	if err := ValidateWorkerSpec(opts.Spec); err != nil {
		return nil, err
	}
	if opts.Factory == nil {
		opts.Factory = defaultCommandFactory
	}
	nonce := make([]byte, challengeBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("sensorproc: create readiness challenge: %w", err)
	}
	return &Proxy{
		spec:      opts.Spec,
		factory:   opts.Factory,
		challenge: hex.EncodeToString(nonce),
		done:      make(chan error, 1),
		closeCh:   make(chan struct{}),
		ready:     make(chan error, 1),
		waitDone:  make(chan struct{}),
		stopDone:  make(chan struct{}),
		startDone: make(chan struct{}),
	}, nil
}

func (p *Proxy) ID() string   { return p.spec.Sensor.ID }
func (p *Proxy) Kind() string { return p.spec.Sensor.Kind }

// Addr returns the child-reported bound address after it has been constrained
// to the operator-configured listen host and port policy.
func (p *Proxy) Addr() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.addr
}

func (p *Proxy) Healthy() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.healthy
}

// FailureContained explicitly distinguishes this process-backed sensor from
// an in-process sensor whose failure may have a wider blast radius.
func (p *Proxy) FailureContained() bool { return true }

func (p *Proxy) Done() <-chan error { return p.done }

func (p *Proxy) Start(ctx context.Context, d sensor.Deps) error {
	if err := sensor.ValidateDeps(d); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("sensorproc %s: start canceled: %w", p.ID(), err)
	}
	p.mu.Lock()
	if p.attempted {
		p.mu.Unlock()
		return fmt.Errorf("sensorproc %s: start already attempted", p.ID())
	}
	if p.closing {
		p.mu.Unlock()
		return fmt.Errorf("sensorproc %s: already closed", p.ID())
	}
	p.attempted = true
	p.starting = true
	p.deps = d
	p.mu.Unlock()
	defer p.finishStartAttempt()

	cmd, err := p.factory()
	if err != nil {
		return fmt.Errorf("sensorproc %s: create worker: %w", p.ID(), err)
	}
	if err := validateCommand(cmd); err != nil {
		if cmd != nil && cmd.Cleanup != nil {
			cmd.Cleanup()
		}
		return err
	}
	p.mu.RLock()
	closing := p.closing
	p.mu.RUnlock()
	if closing {
		cmd.Cleanup()
		return fmt.Errorf("sensorproc %s: %w", p.ID(), errWorkerClosed)
	}
	if err := cmd.Start(); err != nil {
		cmd.Cleanup()
		return fmt.Errorf("sensorproc %s: start worker: %w", p.ID(), err)
	}
	p.mu.Lock()
	p.cmd = cmd
	p.started = true
	closing = p.closing
	p.mu.Unlock()

	go p.readLoop(cmd.Stdout)
	go p.waitLoop(cmd)
	if closing {
		p.fail(errWorkerClosed)
		_ = p.waitStopped(context.Background())
		return fmt.Errorf("sensorproc %s: %w", p.ID(), errWorkerClosed)
	}
	startCtx, cancelStart := context.WithTimeout(ctx, startupTimeout)
	startFinished := make(chan struct{})
	go func() {
		select {
		case <-p.closeCh:
			cancelStart()
		case <-startFinished:
		}
	}()
	defer func() {
		close(startFinished)
		cancelStart()
	}()
	if err := p.sendContext(startCtx, frameStart, startPayload{Spec: p.spec, Challenge: p.challenge}); err != nil {
		p.fail(err)
		_ = p.waitStopped(context.Background())
		if p.isClosing() {
			return fmt.Errorf("sensorproc %s: %w", p.ID(), errWorkerClosed)
		}
		return fmt.Errorf("sensorproc %s: send start: %w", p.ID(), err)
	}

	select {
	case err := <-p.ready:
		if err != nil {
			p.fail(err)
			_ = p.waitStopped(context.Background())
			return fmt.Errorf("sensorproc %s: worker ready: %w", p.ID(), err)
		}
		if p.isClosing() {
			p.fail(errWorkerClosed)
			_ = p.waitStopped(context.Background())
			return fmt.Errorf("sensorproc %s: %w", p.ID(), errWorkerClosed)
		}
		return nil
	case <-startCtx.Done():
		startErr := startCtx.Err()
		if p.isClosing() {
			startErr = errWorkerClosed
		}
		p.fail(startErr)
		_ = p.waitStopped(context.Background())
		return fmt.Errorf("sensorproc %s: wait for ready: %w", p.ID(), startErr)
	}
}

func (p *Proxy) finishStartAttempt() {
	p.mu.Lock()
	p.starting = false
	close(p.startDone)
	p.mu.Unlock()
}

func (p *Proxy) readLoop(r io.Reader) {
	sc := bufio.NewScanner(r)
	buf := make([]byte, 4096)
	sc.Buffer(buf, maxFrameBytes+1)
	for sc.Scan() {
		f, err := decodeFrame(sc.Bytes())
		if err != nil {
			p.fail(fmt.Errorf("%w: invalid frame", errProtocol))
			return
		}
		if err := p.handleFrame(f); err != nil {
			p.fail(err)
			return
		}
	}
	if err := sc.Err(); err != nil {
		p.fail(fmt.Errorf("%w: read worker output: %v", errWorkerTerminated, err))
		return
	}
	p.fail(errWorkerTerminated)
}

func (p *Proxy) handleFrame(f wireFrame) error {
	switch f.Type {
	case frameReady:
		var ready readyPayload
		if err := decodePayload(f.Payload, &ready); err != nil {
			return fmt.Errorf("%w: invalid ready payload", errProtocol)
		}
		if err := validateReadyAddr(ready.Addr, p.spec.Sensor.Listen); err != nil {
			return fmt.Errorf("%w: invalid ready address", errProtocol)
		}
		if !validChallenge(ready.Challenge) || ready.Challenge != p.challenge {
			return fmt.Errorf("%w: readiness challenge mismatch", errProtocol)
		}
		p.mu.Lock()
		if p.closing {
			p.mu.Unlock()
			return errWorkerClosed
		}
		if p.readySeen {
			p.mu.Unlock()
			return fmt.Errorf("%w: duplicate ready", errProtocol)
		}
		p.readySeen = true
		p.addr = ready.Addr
		p.healthy = true
		p.mu.Unlock()
		select {
		case p.ready <- nil:
		default:
		}
		return nil
	case frameObservation:
		if !p.isReady() {
			return fmt.Errorf("%w: observation before ready", errProtocol)
		}
		var obs Observation
		if err := decodePayload(f.Payload, &obs); err != nil {
			return fmt.Errorf("%w: invalid observation payload", errProtocol)
		}
		if err := validateObservation(obs, p.spec); err != nil {
			return fmt.Errorf("%w: invalid observation", errProtocol)
		}
		return p.submitObservation(obs)
	case frameMetric:
		var metric Metric
		if err := decodePayload(f.Payload, &metric); err != nil {
			return fmt.Errorf("%w: invalid metric payload", errProtocol)
		}
		if err := validateMetric(metric); err != nil {
			return fmt.Errorf("%w: invalid metric", errProtocol)
		}
		if !p.isReady() {
			return fmt.Errorf("%w: metric before ready", errProtocol)
		}
		return p.applyMetric(metric)
	case frameFailure:
		var failure failurePayload
		if err := decodePayload(f.Payload, &failure); err != nil || !validFailureCode(failure.Code) {
			return fmt.Errorf("%w: failure payload", errProtocol)
		}
		return fmt.Errorf("%w: worker failure %s", errWorkerTerminated, failure.Code)
	case frameStopped:
		var stopped stoppedPayload
		if err := decodePayload(f.Payload, &stopped); err != nil {
			return fmt.Errorf("%w: invalid stopped payload", errProtocol)
		}
		if stopped.Reason != "operator" && stopped.Reason != "context" {
			return fmt.Errorf("%w: invalid stopped reason", errProtocol)
		}
		return fmt.Errorf("%w: worker stopped", errWorkerTerminated)
	default:
		return fmt.Errorf("%w: unexpected frame type", errProtocol)
	}
}

func validFailureCode(code string) bool {
	if len(code) == 0 || len(code) > maxFailureCodeBytes {
		return false
	}
	switch code {
	case "build_failed", "start_failed", "invalid_address", "protocol", "sensor_failed":
		return true
	default:
		return false
	}
}

func validChallenge(challenge string) bool {
	if len(challenge) != 2*challengeBytes {
		return false
	}
	_, err := hex.DecodeString(challenge)
	return err == nil
}

func (p *Proxy) submitObservation(o Observation) error {
	p.mu.RLock()
	d := p.deps
	addr := p.addr
	p.mu.RUnlock()
	listen := addr
	if listen == "" {
		listen = p.spec.Sensor.Listen
	}
	env, err := event.New(d.Seq, d.Instance, event.SensorRef{ID: o.SensorID, Kind: o.Kind, Listen: listen}, o.Classification, o.Observation, o.Redaction)
	if err != nil {
		return fmt.Errorf("%w: construct event: %v", errProtocol, err)
	}
	if !d.Bus.Submit(env) {
		// Bus drops are an existing bounded data-plane behavior; do not turn
		// backpressure into a worker protocol failure or restart signal.
		d.Log.Warn("isolated sensor event dropped", "sensor", p.ID())
	}
	return nil
}

func (p *Proxy) isReady() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.readySeen
}

func (p *Proxy) isClosing() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.closing
}

func validateReadyAddr(addr, configured string) error {
	if len(addr) == 0 || len(addr) > maxAddrBytes {
		return fmt.Errorf("address is empty or exceeds bound")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("address is not host:port")
	}
	cfgHost, cfgPort, err := net.SplitHostPort(configured)
	if err != nil {
		return fmt.Errorf("configured listen is not host:port")
	}
	gotPort, err := strconv.Atoi(port)
	if err != nil || gotPort < 1 || gotPort > 65535 {
		return fmt.Errorf("worker address port is invalid")
	}
	configuredPort, err := strconv.Atoi(cfgPort)
	if err != nil || configuredPort < 0 || configuredPort > 65535 {
		return fmt.Errorf("configured listen port is invalid")
	}
	if configuredPort != 0 && gotPort != configuredPort {
		return fmt.Errorf("port does not match configured listen")
	}
	gotIP := net.ParseIP(host)
	if gotIP == nil {
		return fmt.Errorf("worker address must contain an IP literal")
	}
	if cfgHost == "localhost" {
		if !gotIP.IsLoopback() {
			return fmt.Errorf("worker address is not loopback")
		}
		return nil
	}
	cfgIP := net.ParseIP(cfgHost)
	if cfgIP == nil {
		return fmt.Errorf("configured listen must contain an IP literal or localhost")
	}
	if cfgIP.IsUnspecified() {
		if !gotIP.IsUnspecified() {
			return fmt.Errorf("worker address changed unspecified bind")
		}
		return nil
	}
	if !cfgIP.Equal(gotIP) {
		return fmt.Errorf("worker address changed configured bind")
	}
	return nil
}

type metricCache struct {
	mu           sync.Mutex
	declarations map[string]Metric
	counters     map[string]observe.Counter
	gauges       map[string]observe.Gauge
	vecs         map[string]observe.LabeledCounter
}

func (p *Proxy) applyMetric(m Metric) error {
	p.mu.RLock()
	meter := p.deps.Meter
	p.mu.RUnlock()
	p.metrics.mu.Lock()
	defer p.metrics.mu.Unlock()
	if p.metrics.declarations == nil {
		p.metrics.declarations = make(map[string]Metric)
	}
	declared, exists := p.metrics.declarations[m.Name]
	if m.Operation == "declare" {
		if allowedWorkerMetricKind(m.Name) != m.Kind {
			return fmt.Errorf("%w: worker metric is not allowed", errProtocol)
		}
		if exists {
			if declared.Kind != m.Kind || declared.Help != m.Help || declared.MaxSeries != m.MaxSeries {
				return fmt.Errorf("%w: worker metric declaration changed", errProtocol)
			}
			return nil
		}
		if len(p.metrics.declarations) >= maxDeclaredMetrics {
			return fmt.Errorf("%w: worker metric declaration cap exceeded", errProtocol)
		}
		p.metrics.declarations[m.Name] = m
	} else if !exists || declared.Kind != m.Kind || declared.Help != m.Help || declared.MaxSeries != m.MaxSeries {
		return fmt.Errorf("%w: worker metric used before matching declaration", errProtocol)
	}
	switch m.Kind {
	case "counter":
		if p.metrics.counters == nil {
			p.metrics.counters = make(map[string]observe.Counter)
		}
		c := p.metrics.counters[m.Name]
		if c == nil {
			c = meter.Counter(m.Name, m.Help)
			p.metrics.counters[m.Name] = c
		}
		if m.Operation == "declare" {
			return nil
		}
		if m.Operation == "inc" {
			c.Inc()
		} else {
			c.Add(m.Value)
		}
	case "gauge":
		if p.metrics.gauges == nil {
			p.metrics.gauges = make(map[string]observe.Gauge)
		}
		g := p.metrics.gauges[m.Name]
		if g == nil {
			g = meter.Gauge(m.Name, m.Help)
			p.metrics.gauges[m.Name] = g
		}
		if m.Operation == "declare" {
			return nil
		}
		if m.Operation == "set" {
			g.Set(m.Value)
		} else {
			g.Add(m.Value)
		}
	case "counter_vec":
		if p.metrics.vecs == nil {
			p.metrics.vecs = make(map[string]observe.LabeledCounter)
		}
		v := p.metrics.vecs[m.Name]
		if v == nil {
			v = meter.CounterVec(m.Name, m.Help, m.MaxSeries)
			p.metrics.vecs[m.Name] = v
		}
		if m.Operation != "declare" {
			v.Inc(m.Label)
		}
	}
	return nil
}

func allowedWorkerMetricKind(name string) string {
	switch name {
	case "aegismesh_sensor_http_interactions_total",
		"aegismesh_sensor_tcp_interactions_total",
		"aegismesh_sensor_mcp_canary_invocations_total",
		"aegismesh_sensor_mcp_tools_listed_total",
		"aegismesh_sensor_mcp_resources_read_total",
		"aegismesh_sensor_mcp_prompts_fetched_total",
		"aegismesh_sensor_ssh_connections_total":
		return "counter"
	case "aegismesh_sensor_tcp_active_sessions",
		"aegismesh_sensor_ssh_active_sessions":
		return "gauge"
	case "aegismesh_detect_findings_total", "aegismesh_policy_actions_total":
		return "counter_vec"
	default:
		return ""
	}
}

func (p *Proxy) waitLoop(cmd *Command) {
	_ = cmd.Wait()
	close(p.waitDone)
}

func (p *Proxy) fail(err error) {
	if err == nil {
		err = errWorkerTerminated
	}
	p.mu.Lock()
	closing := p.closing
	started := p.started
	p.healthy = false
	p.mu.Unlock()
	readyErr := err
	doneErr := err
	if closing {
		doneErr = nil
		if !p.isReady() {
			readyErr = errWorkerClosed
		}
	}
	p.doneOnce.Do(func() {
		select {
		case p.ready <- readyErr:
		default:
		}
		p.done <- doneErr
		close(p.done)
	})
	if started && !closing {
		p.beginStop()
	}
}

func (p *Proxy) sendContext(ctx context.Context, typ string, payload any) error {
	b, err := encodeFrame(typ, payload)
	if err != nil {
		return err
	}
	p.mu.RLock()
	stdin := p.cmd.Stdin
	p.mu.RUnlock()
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	return writeAllContext(ctx, stdin, b)
}

func writeAllContext(ctx context.Context, w deadlineWriteCloser, b []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return fmt.Errorf("sensorproc: protocol write requires a deadline")
	}
	if err := w.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("sensorproc: set protocol write deadline: %w", err)
	}
	stopWatch := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-ctx.Done():
			_ = w.SetWriteDeadline(time.Now())
		case <-stopWatch:
		}
	}()
	err := writeAll(w, b)
	close(stopWatch)
	<-watchDone
	_ = w.SetWriteDeadline(time.Time{})
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

func (p *Proxy) stopCommand(ctx context.Context) error {
	p.mu.RLock()
	cmd := p.cmd
	p.mu.RUnlock()
	if cmd == nil {
		return nil
	}
	writeCtx, cancelWrite := context.WithTimeout(ctx, 250*time.Millisecond)
	_ = p.sendContext(writeCtx, frameStop, stopPayload{Reason: "operator shutdown"})
	cancelWrite()
	_ = cmd.Stdin.Close()
	if waitForProcess(ctx, p.waitDone, 250*time.Millisecond) {
		return nil
	}
	_ = cmd.Stop()
	if waitForProcess(ctx, p.waitDone, stopGrace) {
		return nil
	}
	_ = cmd.Kill()
	if waitForProcess(ctx, p.waitDone, stopGrace) {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fmt.Errorf("sensorproc: worker did not exit after kill")
}

func (p *Proxy) beginStop() {
	p.stopOnce.Do(func() {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*stopGrace+time.Second)
			defer cancel()
			err := p.stopCommand(ctx)
			p.mu.Lock()
			p.stopErr = err
			p.mu.Unlock()
			close(p.stopDone)
		}()
	})
}

func (p *Proxy) waitStopped(ctx context.Context) error {
	p.beginStop()
	select {
	case <-p.stopDone:
		p.mu.RLock()
		defer p.mu.RUnlock()
		return p.stopErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func waitForProcess(ctx context.Context, done <-chan struct{}, max time.Duration) bool {
	timer := time.NewTimer(max)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	case <-timer.C:
		return false
	}
}

func (p *Proxy) Close(ctx context.Context) error {
	p.mu.Lock()
	p.closing = true
	starting := p.starting
	started := p.started
	p.healthy = false
	p.mu.Unlock()
	p.closeOnce.Do(func() { close(p.closeCh) })
	if starting {
		select {
		case <-p.startDone:
		case <-ctx.Done():
			return ctx.Err()
		}
		p.mu.RLock()
		started = p.started
		p.mu.RUnlock()
	}
	if !started {
		p.fail(nil)
		return nil
	}
	err := p.waitStopped(ctx)
	p.fail(err)
	return err
}

func validateCommand(c *Command) error {
	if c == nil || c.Stdin == nil || c.Stdout == nil || c.Start == nil || c.Wait == nil {
		return fmt.Errorf("sensorproc: incomplete command")
	}
	if c.Stop == nil {
		c.Stop = func() error { return nil }
	}
	if c.Kill == nil {
		c.Kill = func() error { return nil }
	}
	if c.Cleanup == nil {
		c.Cleanup = func() {}
	}
	return nil
}

func defaultCommandFactory() (*Command, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("sensorproc: resolve current executable: %w", err)
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return nil, fmt.Errorf("sensorproc: resolve executable path: %w", err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return nil, fmt.Errorf("sensorproc: resolve executable symlinks: %w", err)
	}
	info, err := os.Stat(executable)
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("sensorproc: executable is not a regular file")
	}
	workDir, err := os.MkdirTemp("", "aegismesh-sensor-")
	if err != nil {
		return nil, fmt.Errorf("sensorproc: create worker directory: %w", err)
	}
	cmd := exec.Command(executable, WorkerArg) //nolint:gosec // executable and argv are fixed by the running binary, never config
	cmd.Env = []string{WorkerEnv}
	cmd.Dir = workDir
	cmd.SysProcAttr = processAttributes()
	cmd.WaitDelay = stopGrace
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		_ = os.RemoveAll(workDir)
		return nil, fmt.Errorf("sensorproc: worker stdin: %w", err)
	}
	stdin, ok := stdinPipe.(deadlineWriteCloser)
	if !ok {
		_ = stdinPipe.Close()
		_ = os.RemoveAll(workDir)
		return nil, fmt.Errorf("sensorproc: worker stdin does not support write deadlines")
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = os.RemoveAll(workDir)
		return nil, fmt.Errorf("sensorproc: worker stdout: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(workDir) }
	return &Command{
		Stdin:  stdin,
		Stdout: stdout,
		Start:  func() error { return cmd.Start() },
		Wait: func() error {
			err := cmd.Wait()
			cleanup()
			return err
		},
		Stop:    func() error { return terminateProcess(cmd.Process) },
		Kill:    func() error { return killProcess(cmd.Process) },
		Cleanup: cleanup,
	}, nil
}
