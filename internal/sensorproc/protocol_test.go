package sensorproc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/sensor"
)

func testSpec() WorkerSpec {
	return WorkerSpec{
		Sensor: config.Sensor{
			ID: "web", Kind: config.SensorKindHTTP, Listen: "127.0.0.1:0", Persona: &config.HTTPPersona{},
			Rules: []config.HTTPRule{{Name: "root", PathRegex: "^/$", Status: http.StatusOK, Body: "ok"}},
		},
		Instance: "test",
	}
}

func TestBuiltinWorkerInvocationRequiresExactArgvAndMarker(t *testing.T) {
	t.Setenv(workerEnvName, "1")
	if !IsBuiltinWorkerInvocation([]string{"aegismesh", WorkerArg}) {
		t.Fatal("fixed worker invocation not recognized")
	}
	for _, args := range [][]string{{"aegismesh"}, {"aegismesh", WorkerArg, "extra"}, {"aegismesh", "other"}} {
		if IsBuiltinWorkerInvocation(args) {
			t.Fatalf("non-exact worker invocation accepted: %v", args)
		}
	}
	t.Setenv(workerEnvName, "0")
	if IsBuiltinWorkerInvocation([]string{"aegismesh", WorkerArg}) {
		t.Fatal("worker invocation accepted without exact marker")
	}
}

func TestDecodeFrameRejectsMalformedAndNonCanonicalInput(t *testing.T) {
	valid, err := encodeFrame(frameReady, readyPayload{Addr: "127.0.0.1:1234", Challenge: strings.Repeat("a", 2*challengeBytes)})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		line []byte
	}{
		{name: "empty", line: nil},
		{name: "invalid json", line: []byte("{")},
		{name: "unknown top-level", line: []byte(`{"protocol":"aegismesh.sensor/v1","type":"ready","payload":{"addr":""},"extra":1}`)},
		{name: "duplicate top-level", line: []byte(`{"protocol":"aegismesh.sensor/v1","protocol":"aegismesh.sensor/v1","type":"ready","payload":{"addr":""}}`)},
		{name: "trailing json", line: append(append([]byte{}, valid[:len(valid)-1]...), []byte(` {}`)...)},
		{name: "whitespace", line: append([]byte(" "), valid[:len(valid)-1]...)},
		{name: "wrong protocol", line: frameBytes(`{"protocol":"other/v1","type":"ready","payload":{"addr":""}}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := decodeFrame(tt.line); err == nil {
				t.Fatal("decodeFrame accepted invalid input")
			}
		})
	}
	if _, err := decodeFrame(bytes.Repeat([]byte{'x'}, maxFrameBytes+1)); err == nil {
		t.Fatal("decodeFrame accepted oversized input")
	}
}

func TestDecodePayloadRejectsUnknownDuplicateAndTrailingFields(t *testing.T) {
	valid := mustFramePayload(t, readyPayload{Addr: "", Challenge: strings.Repeat("a", 2*challengeBytes)})
	for _, raw := range []json.RawMessage{
		json.RawMessage(`{"addr":"","extra":1}`),
		json.RawMessage(`{"addr":"","addr":""}`),
		json.RawMessage(`{"addr":""} {}`),
	} {
		var ready readyPayload
		if err := decodePayload(raw, &ready); err == nil {
			t.Fatalf("decodePayload accepted %s", raw)
		}
	}
	var ready readyPayload
	if err := decodePayload(valid, &ready); err != nil {
		t.Fatal(err)
	}
}

func TestReadProtocolLineRejectsBeforeUnboundedAccumulation(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 128)), 8)
	if _, err := readProtocolLine(r, 32); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized unterminated line error = %v", err)
	}
}

func TestMaximumValidatedHTTPConfigFitsStartFrame(t *testing.T) {
	body := strings.Repeat("\x00", config.MaxHTTPBodyBytes)
	rules := make([]config.HTTPRule, config.MaxRulesPerSensor)
	for i := range rules {
		rules[i] = config.HTTPRule{Name: "rule", PathRegex: "^/$", Status: 200, Body: body}
	}
	spec := testSpec()
	spec.Sensor.Rules = rules
	b, err := encodeFrame(frameStart, startPayload{Spec: spec, Challenge: strings.Repeat("a", 2*challengeBytes)})
	if err != nil {
		t.Fatalf("maximum validated start frame: %v", err)
	}
	if len(b) <= maxFrameBytes || len(b) > maxStartFrameBytes+1 {
		t.Fatalf("start frame size = %d, want output cap < size <= start cap", len(b))
	}
	if _, err := decodeFrameWithLimit(b, maxStartFrameBytes); err != nil {
		t.Fatalf("decode maximum start frame: %v", err)
	}
}

func TestValidateWorkerSpecRejectsPathBearingConfig(t *testing.T) {
	spec := testSpec()
	spec.Sensor.Rules = []config.HTTPRule{{BodyFile: "secret.txt"}}
	if err := ValidateWorkerSpec(spec); err == nil {
		t.Fatal("path-bearing worker spec accepted")
	}
	spec = testSpec()
	spec.Sensor.Kind = "unknown"
	if err := ValidateWorkerSpec(spec); err == nil {
		t.Fatal("unknown sensor kind accepted")
	}
}

func TestMaterializedBodyPreservesBinaryBytes(t *testing.T) {
	want := []byte{0x00, 0xff, 'x'}
	spec := testSpec()
	spec.Sensor.Rules = []config.HTTPRule{{Name: "root", PathRegex: "^/$", Status: 200}}
	spec.MaterializedBodies = []MaterializedBody{{RuleIndex: 0, Content: want}}
	if err := ValidateWorkerSpec(spec); err != nil {
		t.Fatal(err)
	}
	got := []byte(effectiveWorkerConfig(spec).Rules[0].Body)
	if !bytes.Equal(got, want) {
		t.Fatalf("body bytes = %x, want %x", got, want)
	}
	spec.MaterializedBodies = append(spec.MaterializedBodies, spec.MaterializedBodies[0])
	if err := ValidateWorkerSpec(spec); err == nil {
		t.Fatal("duplicate materialized body accepted")
	}
}

func TestValidateReadyAddrBindsToConfiguredListener(t *testing.T) {
	tests := []struct {
		name, got, configured string
		wantErr               bool
	}{
		{name: "loopback ephemeral", got: "127.0.0.1:4123", configured: "127.0.0.1:0"},
		{name: "wrong host", got: "127.0.0.2:4123", configured: "127.0.0.1:0", wantErr: true},
		{name: "wrong port", got: "127.0.0.1:4123", configured: "127.0.0.1:4124", wantErr: true},
		{name: "hostname output", got: "localhost:4123", configured: "127.0.0.1:0", wantErr: true},
		{name: "empty", got: "", configured: "127.0.0.1:0", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateReadyAddr(tt.got, tt.configured)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateReadyAddr(%q, %q) error=%v wantErr=%v", tt.got, tt.configured, err, tt.wantErr)
			}
		})
	}
}

func TestProxyRejectsReadyWithoutStartChallenge(t *testing.T) {
	p, err := NewProxy(ProxyOptions{Spec: testSpec()})
	if err != nil {
		t.Fatal(err)
	}
	wrongChallenge := "00000000000000000000000000000000"
	if p.challenge == wrongChallenge {
		wrongChallenge = "11111111111111111111111111111111"
	}
	ready := mustDecodedFrame(t, frameReady, readyPayload{
		Addr:      "127.0.0.1:4123",
		Challenge: wrongChallenge,
	})
	if err := p.handleFrame(ready); err == nil || !strings.Contains(err.Error(), "challenge") {
		t.Fatalf("pre-start ready error = %v, want challenge rejection", err)
	}
	if p.Healthy() {
		t.Fatal("challenge-spoofed worker became healthy")
	}
}

func TestObservationIdentityAndEventIntegrity(t *testing.T) {
	spec := testSpec()
	got := make(chan event.Envelope, 1)
	bus := event.NewBus(4, sinkFunc(func(_ context.Context, e event.Envelope) error {
		got <- e
		return nil
	}), slog.Default())
	defer bus.Close()
	p := &Proxy{spec: spec, deps: sensor.Deps{
		Bus:      bus,
		Meter:    observe.NewRegistry(),
		Log:      slog.Default(),
		Seq:      &event.Sequencer{},
		Instance: "instance-a",
	}, addr: "127.0.0.1:4321", readySeen: true}

	obs := Observation{SensorID: "web", Kind: config.SensorKindHTTP, Classification: "interaction", Observation: json.RawMessage(`{"path":"/login"}`), Redaction: []string{"query_string_dropped"}}
	frame := mustDecodedFrame(t, frameObservation, obs)
	if err := p.handleFrame(frame); err != nil {
		t.Fatal(err)
	}
	env := <-got
	if env.Sensor.ID != "web" || env.Sensor.Kind != config.SensorKindHTTP || env.Sensor.Listen != "127.0.0.1:4321" {
		t.Fatalf("unexpected sensor ref: %+v", env.Sensor)
	}
	if env.Seq != 1 || env.Instance != "instance-a" || env.ID == "" {
		t.Fatalf("parent authority was not applied: %+v", env)
	}
	if err := env.VerifyIntegrity(); err != nil {
		t.Fatal(err)
	}
	bad := obs
	bad.SensorID = "other"
	if err := p.handleFrame(mustDecodedFrame(t, frameObservation, bad)); err == nil {
		t.Fatal("identity mismatch accepted")
	}
	for _, raw := range []json.RawMessage{json.RawMessage(`{"x":1,"x":2}`), json.RawMessage(`{"x": 1}`)} {
		bad = obs
		bad.Observation = raw
		if err := validateObservation(bad, spec); err == nil {
			t.Fatalf("non-canonical nested observation accepted: %s", raw)
		}
	}
	bad = obs
	bad.Observation = json.RawMessage(strings.Repeat("[", maxObservationDepth+2) + "0" + strings.Repeat("]", maxObservationDepth+2))
	if err := validateObservation(bad, spec); err == nil {
		t.Fatal("excessively nested observation accepted")
	}
}

func TestProxyErrorsDoNotReflectWorkerText(t *testing.T) {
	p := &Proxy{spec: testSpec()}
	marker := "UNTRUSTED-WORKER-TEXT"
	for _, frame := range []wireFrame{
		mustDecodedFrame(t, frameFailure, failurePayload{Code: marker}),
		mustDecodedFrame(t, marker, struct{}{}),
	} {
		err := p.handleFrame(frame)
		if err == nil {
			t.Fatal("untrusted worker frame accepted")
		}
		if strings.Contains(err.Error(), marker) {
			t.Fatalf("worker text reflected in error: %v", err)
		}
	}
}

func TestProxyLoopbackLifecycleAndMetrics(t *testing.T) {
	spec := testSpec()
	server, client := net.Pipe()
	wait := make(chan struct{})
	var once sync.Once
	factory := func() (*Command, error) {
		return &Command{
			Stdin:  client,
			Stdout: client,
			Start:  func() error { return nil },
			Wait: func() error {
				<-wait
				return nil
			},
			Stop: func() error { once.Do(func() { close(wait); _ = server.Close() }); return nil },
			Kill: func() error { once.Do(func() { close(wait); _ = server.Close() }); return nil },
		}, nil
	}
	reg := observe.NewRegistry()
	bus := event.NewBus(4, sinkFunc(func(context.Context, event.Envelope) error { return nil }), slog.Default())
	defer bus.Close()
	p, err := NewProxy(ProxyOptions{Spec: spec, Factory: factory})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		r := bufio.NewReader(server)
		line, err := r.ReadBytes('\n')
		if err != nil {
			return
		}
		var f wireFrame
		if f, err = decodeFrame(line); err != nil || f.Type != frameStart {
			return
		}
		ready, _ := encodeFrame(frameReady, readyPayload{Addr: "127.0.0.1:4000", Challenge: p.challenge})
		_, _ = server.Write(ready)
		obs, _ := encodeFrame(frameObservation, Observation{SensorID: "web", Kind: "http", Classification: "interaction", Observation: json.RawMessage(`{"ok":true}`)})
		_, _ = server.Write(obs)
		_, _ = r.ReadBytes('\n')
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := p.Start(ctx, sensor.Deps{Config: spec.Sensor, Bus: bus, Meter: reg, Log: slog.Default(), Seq: &event.Sequencer{}, Instance: "i"}); err != nil {
		t.Fatal(err)
	}
	if !p.Healthy() || p.Addr() != "127.0.0.1:4000" || !p.FailureContained() {
		t.Fatalf("unexpected proxy state healthy=%v addr=%q contained=%v", p.Healthy(), p.Addr(), p.FailureContained())
	}
	reg.Counter("worker_events_total", "worker events").Inc()
	if err := p.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if p.Healthy() {
		t.Fatal("proxy remained healthy after close")
	}
	if err := <-p.Done(); err != nil {
		t.Fatalf("normal close reported terminal failure: %v", err)
	}
}

func TestProxyProtocolViolationRevokesWorker(t *testing.T) {
	spec := testSpec()
	server, client := net.Pipe()
	wait := make(chan struct{})
	var once sync.Once
	factory := func() (*Command, error) {
		return &Command{
			Stdin: client, Stdout: client, Start: func() error { return nil },
			Wait: func() error { <-wait; return nil },
			Stop: func() error { once.Do(func() { close(wait); _ = server.Close() }); return nil },
			Kill: func() error { once.Do(func() { close(wait); _ = server.Close() }); return nil },
		}, nil
	}
	p, err := NewProxy(ProxyOptions{Spec: spec, Factory: factory})
	if err != nil {
		t.Fatal(err)
	}
	bus := event.NewBus(1, sinkFunc(func(context.Context, event.Envelope) error { return nil }), slog.Default())
	defer bus.Close()
	go func() {
		r := bufio.NewReader(server)
		_, _ = r.ReadBytes('\n')
		ready, _ := encodeFrame(frameReady, readyPayload{Addr: "127.0.0.1:4000", Challenge: p.challenge})
		_, _ = server.Write(ready)
		_, _ = server.Write([]byte("{}\n"))
		_, _ = r.ReadBytes('\n')
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := p.Start(ctx, sensor.Deps{Config: spec.Sensor, Bus: bus, Meter: observe.NewRegistry(), Log: slog.Default(), Seq: &event.Sequencer{}, Instance: "i"}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-p.Done():
		if err == nil || !strings.Contains(err.Error(), "protocol") {
			t.Fatalf("terminal error = %v, want protocol violation", err)
		}
	case <-ctx.Done():
		t.Fatal("protocol violation did not terminate proxy")
	}
	if p.Healthy() {
		t.Fatal("protocol-violating worker remained healthy")
	}
	if err := p.Close(ctx); err != nil {
		t.Fatalf("reap revoked worker: %v", err)
	}
}

func TestProxyStartFailureRunsCleanup(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	cleaned := false
	p, err := NewProxy(ProxyOptions{Spec: testSpec(), Factory: func() (*Command, error) {
		return &Command{
			Stdin: client, Stdout: client,
			Start: func() error { return errors.New("synthetic start failure") },
			Wait:  func() error { return nil },
			Cleanup: func() {
				cleaned = true
			},
		}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	bus := event.NewBus(1, sinkFunc(func(context.Context, event.Envelope) error { return nil }), slog.Default())
	defer bus.Close()
	err = p.Start(context.Background(), sensor.Deps{Config: testSpec().Sensor, Bus: bus, Meter: observe.NewRegistry(), Log: slog.Default(), Seq: &event.Sequencer{}, Instance: "i"})
	if err == nil || !cleaned {
		t.Fatalf("Start error=%v cleaned=%v", err, cleaned)
	}
}

func TestProxyConcurrentClosePreventsWorkerStart(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	entered := make(chan struct{})
	release := make(chan struct{})
	cleaned := false
	startCalled := false
	p, err := NewProxy(ProxyOptions{Spec: testSpec(), Factory: func() (*Command, error) {
		close(entered)
		<-release
		return &Command{
			Stdin: client, Stdout: client,
			Start: func() error { startCalled = true; return nil },
			Wait:  func() error { return nil },
			Cleanup: func() {
				cleaned = true
			},
		}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	bus := event.NewBus(1, sinkFunc(func(context.Context, event.Envelope) error { return nil }), slog.Default())
	defer bus.Close()
	deps := sensor.Deps{Config: testSpec().Sensor, Bus: bus, Meter: observe.NewRegistry(), Log: slog.Default(), Seq: &event.Sequencer{}, Instance: "i"}
	startErr := make(chan error, 1)
	go func() { startErr <- p.Start(context.Background(), deps) }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	closeErr := make(chan error, 1)
	go func() { closeErr <- p.Close(ctx) }()
	for {
		p.mu.RLock()
		closing := p.closing
		p.mu.RUnlock()
		if closing {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	if err := <-startErr; err == nil || !errors.Is(err, errWorkerClosed) {
		t.Fatalf("Start error = %v, want worker closed", err)
	}
	if err := <-closeErr; err != nil {
		t.Fatalf("Close: %v", err)
	}
	if startCalled || !cleaned {
		t.Fatalf("startCalled=%v cleaned=%v", startCalled, cleaned)
	}
}

func TestProxyCloseCancelsBlockedStartWrite(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	writeEntered := make(chan struct{})
	stdin := &notifyingWriteCloser{deadlineWriteCloser: client, entered: writeEntered}
	wait := make(chan struct{})
	var stopOnce sync.Once
	stopped := make(chan struct{})
	p, err := NewProxy(ProxyOptions{Spec: testSpec(), Factory: func() (*Command, error) {
		return &Command{
			Stdin: stdin, Stdout: client,
			Start: func() error { return nil },
			Wait:  func() error { <-wait; return nil },
			Stop: func() error {
				stopOnce.Do(func() { close(wait); close(stopped) })
				return nil
			},
			Kill: func() error {
				stopOnce.Do(func() { close(wait); close(stopped) })
				return nil
			},
		}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	bus := event.NewBus(1, sinkFunc(func(context.Context, event.Envelope) error { return nil }), slog.Default())
	defer bus.Close()
	deps := sensor.Deps{Config: testSpec().Sensor, Bus: bus, Meter: observe.NewRegistry(), Log: slog.Default(), Seq: &event.Sequencer{}, Instance: "i"}
	startErr := make(chan error, 1)
	go func() { startErr <- p.Start(context.Background(), deps) }()
	<-writeEntered

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := p.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := <-startErr; err == nil || !errors.Is(err, errWorkerClosed) {
		t.Fatalf("Start error = %v, want worker closed", err)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("blocked start write did not escalate worker termination")
	}
}

func TestProxyCloseCancelsReadinessWaitAndHealthStaysFalse(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	wait := make(chan struct{})
	var stopOnce sync.Once
	startFrameRead := make(chan struct{})
	p, err := NewProxy(ProxyOptions{Spec: testSpec(), Factory: func() (*Command, error) {
		return &Command{
			Stdin: client, Stdout: client, Start: func() error { return nil },
			Wait: func() error { <-wait; return nil },
			Stop: func() error { stopOnce.Do(func() { close(wait); _ = server.Close() }); return nil },
			Kill: func() error { stopOnce.Do(func() { close(wait); _ = server.Close() }); return nil },
		}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		r := bufio.NewReader(server)
		_, _ = r.ReadBytes('\n')
		close(startFrameRead)
		_, _ = r.ReadBytes('\n')
	}()
	bus := event.NewBus(1, sinkFunc(func(context.Context, event.Envelope) error { return nil }), slog.Default())
	defer bus.Close()
	deps := sensor.Deps{Config: testSpec().Sensor, Bus: bus, Meter: observe.NewRegistry(), Log: slog.Default(), Seq: &event.Sequencer{}, Instance: "i"}
	startErr := make(chan error, 1)
	go func() { startErr <- p.Start(context.Background(), deps) }()
	<-startFrameRead
	if p.Healthy() {
		t.Fatal("proxy reported healthy before ready")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := p.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := <-startErr; err == nil || !errors.Is(err, errWorkerClosed) {
		t.Fatalf("Start error = %v, want worker closed", err)
	}
}

func TestFrameWriterSendCloseConcurrent(t *testing.T) {
	w := newFrameWriter(io.Discard)
	w.start()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = w.send(frameMetric, Metric{Kind: "counter", Operation: "inc", Name: "events_total"})
			}
		}()
	}
	w.close()
	wg.Wait()
}

func TestMetricValidationAndApplication(t *testing.T) {
	reg := observe.NewRegistry()
	p := &Proxy{spec: testSpec(), deps: sensor.Deps{Meter: reg, Log: slog.Default()}}
	httpMetric := "aegismesh_sensor_http_interactions_total"
	sshGauge := "aegismesh_sensor_ssh_active_sessions"
	for _, metric := range []Metric{
		{Kind: "counter", Operation: "declare", Name: httpMetric, Help: "events"},
		{Kind: "counter", Operation: "add", Name: httpMetric, Help: "events", Value: 2},
		{Kind: "gauge", Operation: "declare", Name: sshGauge},
		{Kind: "gauge", Operation: "set", Name: sshGauge, Value: 3},
	} {
		if err := p.applyMetric(metric); err != nil {
			t.Fatal(err)
		}
	}
	if got := reg.WritePrometheus(); !strings.Contains(got, httpMetric+" 2") || !strings.Contains(got, sshGauge+" 3") {
		t.Fatalf("metrics not applied: %s", got)
	}
	if err := p.applyMetric(Metric{Kind: "counter", Operation: "inc", Name: "attacker_total"}); err == nil {
		t.Fatal("undeclared arbitrary metric accepted")
	}
	if err := p.applyMetric(Metric{Kind: "counter", Operation: "declare", Name: "attacker_total"}); err == nil {
		t.Fatal("arbitrary metric declaration accepted")
	}
	if err := validateMetric(Metric{Kind: "gauge", Operation: "set", Name: "bad name", Value: 1}); err == nil {
		t.Fatal("invalid metric accepted")
	}
	if err := validateMetric(Metric{Kind: "gauge", Operation: "set", Name: "g", Value: math.Inf(1)}); err == nil {
		t.Fatal("non-finite metric accepted")
	}
}

func TestIPCMeterPreservesPreReadyMetricOrder(t *testing.T) {
	var output bytes.Buffer
	w := newFrameWriter(&output)
	w.start()
	meter := &ipcMeter{writer: w}
	first := meter.Counter("first_total", "first")
	meter.Gauge("second_depth", "second")
	meter.Counter("first_total", "duplicate")
	first.Inc()
	meter.activate()
	meter.CounterVec("third_total", "third", 4)
	w.close()

	var got []Metric
	scanner := bufio.NewScanner(&output)
	for scanner.Scan() {
		frame, err := decodeFrame(scanner.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if frame.Type != frameMetric {
			t.Fatalf("frame type = %q, want metric", frame.Type)
		}
		var metric Metric
		if err := decodePayload(frame.Payload, &metric); err != nil {
			t.Fatal(err)
		}
		got = append(got, metric)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	want := []struct {
		name, operation string
	}{
		{name: "first_total", operation: "declare"},
		{name: "second_depth", operation: "declare"},
		{name: "first_total", operation: "inc"},
		{name: "third_total", operation: "declare"},
	}
	if len(got) != len(want) {
		t.Fatalf("declarations = %+v, want %v", got, want)
	}
	for i := range want {
		if got[i].Name != want[i].name || got[i].Operation != want[i].operation {
			t.Fatalf("metric[%d] = %+v, want name=%q operation=%q", i, got[i], want[i].name, want[i].operation)
		}
	}
}

func mustFramePayload(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustDecodedFrame(t *testing.T, typ string, payload any) wireFrame {
	t.Helper()
	b, err := encodeFrame(typ, payload)
	if err != nil {
		t.Fatal(err)
	}
	f, err := decodeFrame(b)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func frameBytes(s string) []byte { return []byte(s) }

type sinkFunc func(context.Context, event.Envelope) error

func (f sinkFunc) Append(ctx context.Context, e event.Envelope) error { return f(ctx, e) }

type notifyingWriteCloser struct {
	deadlineWriteCloser
	once    sync.Once
	entered chan struct{}
}

func (w *notifyingWriteCloser) Write(b []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	return w.deadlineWriteCloser.Write(b)
}
