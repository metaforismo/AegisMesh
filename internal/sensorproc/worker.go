package sensorproc

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"sync"
	"sync/atomic"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/sensor"
)

// SensorBuilder constructs the first-party sensor with the worker's injected
// dependencies. The worker never accepts a provider, executable, path, or
// command from the wire; the caller chooses the concrete builder in code.
type SensorBuilder func(sensor.Deps, config.Detection) (sensor.Sensor, error)

// RunWorker runs the hidden child-side protocol. The first frame must be a
// canonical start frame; after that only a canonical stop frame is accepted
// from the parent. Sensor observations and metrics flow in the opposite
// direction through a bounded writer queue.
func RunWorker(ctx context.Context, input io.Reader, output io.Writer, build SensorBuilder) error {
	if build == nil {
		return fmt.Errorf("sensorproc: nil worker builder")
	}
	reader := bufio.NewReader(input)
	start, err := readStartReader(reader)
	if err != nil {
		return err
	}
	if err := ValidateWorkerSpec(start.Spec); err != nil {
		return err
	}
	if !validChallenge(start.Challenge) {
		return fmt.Errorf("sensorproc: invalid start challenge")
	}
	workerConfig := effectiveWorkerConfig(start.Spec)

	w := newFrameWriter(output)
	w.start()
	defer w.close()

	reg := &ipcMeter{writer: w}
	sink := &workerSink{writer: w, spec: start.Spec, ready: make(chan struct{})}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bus := event.NewBus(128, sink, log)
	defer func() {
		sink.activate(false)
		bus.Close()
	}()
	deps := sensor.Deps{
		Config:   workerConfig,
		Bus:      bus,
		Meter:    reg,
		Log:      log,
		Seq:      &event.Sequencer{},
		Instance: start.Spec.Instance,
	}

	s, err := build(deps, start.Spec.Detection)
	if err != nil {
		_ = w.send(frameFailure, failurePayload{Code: "build_failed"})
		return fmt.Errorf("sensorproc: build worker sensor: %w", err)
	}
	if err := s.Start(ctx, deps); err != nil {
		_ = s.Close(ctx)
		_ = w.send(frameFailure, failurePayload{Code: "start_failed"})
		return fmt.Errorf("sensorproc: start worker sensor: %w", err)
	}
	addr := ""
	if addressed, ok := s.(interface{ Addr() string }); ok {
		addr = addressed.Addr()
	}
	if len(addr) > maxAddrBytes {
		_ = s.Close(ctx)
		_ = w.send(frameFailure, failurePayload{Code: "invalid_address"})
		return fmt.Errorf("sensorproc: worker address exceeds bound")
	}
	if err := w.send(frameReady, readyPayload{Addr: addr, Challenge: start.Challenge}); err != nil {
		_ = s.Close(ctx)
		return err
	}
	sink.activate(true)
	reg.activate()

	stop := make(chan error, 1)
	go readStop(reader, stop)
	select {
	case <-ctx.Done():
		_ = s.Close(ctx)
		bus.Close()
		_ = w.send(frameStopped, stoppedPayload{Reason: "context"})
		return ctx.Err()
	case err := <-stop:
		if err != nil {
			_ = w.send(frameFailure, failurePayload{Code: "protocol"})
			_ = s.Close(ctx)
			return err
		}
		_ = s.Close(ctx)
		bus.Close()
		_ = w.send(frameStopped, stoppedPayload{Reason: "operator"})
		return nil
	case err := <-s.Done():
		_ = s.Close(ctx)
		bus.Close()
		_ = w.send(frameFailure, failurePayload{Code: "sensor_failed"})
		if err != nil {
			return fmt.Errorf("sensorproc: worker sensor failed: %w", err)
		}
		return fmt.Errorf("sensorproc: worker sensor stopped")
	}
}

func effectiveWorkerConfig(spec WorkerSpec) config.Sensor {
	c := spec.Sensor
	if len(spec.MaterializedBodies) == 0 {
		return c
	}
	c.Rules = append([]config.HTTPRule(nil), c.Rules...)
	for _, body := range spec.MaterializedBodies {
		c.Rules[body.RuleIndex].Body = string(body.Content)
	}
	return c
}

func readStartReader(reader *bufio.Reader) (startPayload, error) {
	line, err := readProtocolLine(reader, maxStartFrameBytes)
	if err != nil {
		return startPayload{}, fmt.Errorf("sensorproc: read start: %w", err)
	}
	f, err := decodeFrameWithLimit(line, maxStartFrameBytes)
	if err != nil {
		return startPayload{}, err
	}
	if f.Type != frameStart {
		return startPayload{}, fmt.Errorf("sensorproc: first frame must be start")
	}
	var start startPayload
	if err := decodePayload(f.Payload, &start); err != nil {
		return startPayload{}, err
	}
	return start, nil
}

func readStop(reader *bufio.Reader, result chan<- error) {
	line, err := readProtocolLine(reader, maxFrameBytes)
	if err != nil {
		result <- err
		return
	}
	f, err := decodeFrame(line)
	if err != nil {
		result <- err
		return
	}
	if f.Type != frameStop {
		result <- fmt.Errorf("sensorproc: unexpected parent frame %q", f.Type)
		return
	}
	var stop stopPayload
	if err := decodePayload(f.Payload, &stop); err != nil {
		result <- err
		return
	}
	result <- nil
}

func readProtocolLine(reader *bufio.Reader, limit int) ([]byte, error) {
	line := make([]byte, 0, min(limit+1, 4096))
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(line)+len(fragment) > limit+1 {
			return nil, fmt.Errorf("sensorproc: frame exceeds %d bytes", limit)
		}
		line = append(line, fragment...)
		switch err {
		case nil:
			return line, nil
		case bufio.ErrBufferFull:
			continue
		default:
			return nil, err
		}
	}
}

type frameWriter struct {
	out    io.Writer
	queue  chan []byte
	wg     sync.WaitGroup
	mu     sync.Mutex
	dead   bool
	closed bool
}

func newFrameWriter(out io.Writer) *frameWriter {
	return &frameWriter{out: out, queue: make(chan []byte, maxQueueFrames)}
}

func (w *frameWriter) start() {
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		for b := range w.queue {
			if err := writeAll(w.out, b); err != nil {
				w.mu.Lock()
				w.dead = true
				w.mu.Unlock()
				return
			}
		}
	}()
}

func (w *frameWriter) send(typ string, payload any) error {
	b, err := encodeFrame(typ, payload)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dead || w.closed {
		return io.ErrClosedPipe
	}
	select {
	case w.queue <- b:
		return nil
	default:
		return fmt.Errorf("sensorproc: worker output queue full")
	}
}

func (w *frameWriter) close() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	close(w.queue)
	w.mu.Unlock()
	w.wg.Wait()
}

type workerSink struct {
	writer *frameWriter
	spec   WorkerSpec
	ready  chan struct{}
	once   sync.Once
	accept atomic.Bool
}

func (s *workerSink) Append(_ context.Context, e event.Envelope) error {
	<-s.ready
	if !s.accept.Load() {
		return nil
	}
	obs := Observation{
		SensorID:       e.Sensor.ID,
		Kind:           e.Sensor.Kind,
		Classification: e.Classification,
		Observation:    e.Observation,
		Redaction:      e.Redaction.Rules,
	}
	if err := validateObservation(obs, s.spec); err != nil {
		return err
	}
	return s.writer.send(frameObservation, obs)
}

func (s *workerSink) activate(accept bool) {
	s.once.Do(func() {
		s.accept.Store(accept)
		close(s.ready)
	})
}

type ipcMeter struct {
	writer       *frameWriter
	active       atomic.Bool
	mu           sync.Mutex
	pending      []Metric
	declarations map[string]struct{}
}

var _ observe.Meter = (*ipcMeter)(nil)

func (m *ipcMeter) Counter(name, help string) observe.Counter {
	m.register(Metric{Kind: "counter", Operation: "declare", Name: name, Help: help})
	return ipcCounter{meter: m, name: name, help: help}
}
func (m *ipcMeter) Gauge(name, help string) observe.Gauge {
	m.register(Metric{Kind: "gauge", Operation: "declare", Name: name, Help: help})
	return ipcGauge{meter: m, name: name, help: help}
}
func (m *ipcMeter) CounterVec(name, help string, maxSeries int) observe.LabeledCounter {
	if maxSeries <= 0 {
		maxSeries = 8
	}
	if maxSeries > maxMetricSeries {
		maxSeries = maxMetricSeries
	}
	m.register(Metric{Kind: "counter_vec", Operation: "declare", Name: name, Help: help, MaxSeries: maxSeries})
	return ipcCounterVec{meter: m, name: name, help: help, maxSeries: maxSeries}
}
func (m *ipcMeter) WritePrometheus() string { return "" }

func (m *ipcMeter) register(metric Metric) {
	m.mu.Lock()
	if m.active.Load() {
		m.mu.Unlock()
		_ = m.writer.send(frameMetric, metric)
		return
	}
	if m.declarations == nil {
		m.declarations = make(map[string]struct{})
	}
	key := metric.Kind + ":" + metric.Name
	if _, exists := m.declarations[key]; !exists && len(m.pending) < maxPendingMetrics {
		m.declarations[key] = struct{}{}
		m.pending = append(m.pending, metric)
	}
	m.mu.Unlock()
}

func (m *ipcMeter) emit(metric Metric) {
	m.mu.Lock()
	if m.active.Load() {
		m.mu.Unlock()
		_ = m.writer.send(frameMetric, metric)
		return
	}
	if len(m.pending) < maxPendingMetrics {
		m.pending = append(m.pending, metric)
	}
	m.mu.Unlock()
}

func (m *ipcMeter) activate() {
	m.mu.Lock()
	pending := append([]Metric(nil), m.pending...)
	m.pending = nil
	m.active.Store(true)
	m.mu.Unlock()
	for _, metric := range pending {
		_ = m.writer.send(frameMetric, metric)
	}
}

type ipcCounter struct {
	meter *ipcMeter
	name  string
	help  string
}

func (c ipcCounter) Inc() {
	c.meter.emit(Metric{Kind: "counter", Operation: "inc", Name: c.name, Help: c.help})
}
func (c ipcCounter) Add(v float64) {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return
	}
	c.meter.emit(Metric{Kind: "counter", Operation: "add", Name: c.name, Help: c.help, Value: v})
}

type ipcGauge struct {
	meter *ipcMeter
	name  string
	help  string
}

func (g ipcGauge) Set(v float64) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return
	}
	g.meter.emit(Metric{Kind: "gauge", Operation: "set", Name: g.name, Help: g.help, Value: v})
}
func (g ipcGauge) Add(v float64) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return
	}
	g.meter.emit(Metric{Kind: "gauge", Operation: "add", Name: g.name, Help: g.help, Value: v})
}

type ipcCounterVec struct {
	meter     *ipcMeter
	name      string
	help      string
	maxSeries int
}

func (v ipcCounterVec) Inc(label string) {
	v.meter.emit(Metric{Kind: "counter_vec", Operation: "inc", Name: v.name, Help: v.help, Label: label, MaxSeries: v.maxSeries})
}
