package tcpsensor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/policy"
	"github.com/metaforismo/aegismesh/internal/sensor"
)

type collectingSink struct {
	mu  sync.Mutex
	got []event.Envelope
}

func newCollectingSink() *collectingSink { return &collectingSink{} }

func (s *collectingSink) Append(_ context.Context, e event.Envelope) error {
	s.mu.Lock()
	s.got = append(s.got, e)
	s.mu.Unlock()
	return nil
}

func (s *collectingSink) snapshot() []event.Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]event.Envelope(nil), s.got...)
}

func (s *collectingSink) waitFor(t *testing.T, n int) []event.Envelope {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		got := s.snapshot()
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d/%d events", len(got), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newDeps(cfg config.Sensor, sink *collectingSink) (sensor.Deps, *event.Bus) {
	bus := event.NewBus(64, sink, quietLogger())
	deps := sensor.Deps{
		Config: cfg, Bus: bus, Meter: observe.NewRegistry(), Log: quietLogger(),
		Seq: &event.Sequencer{}, Instance: "test",
	}
	return deps, bus
}

func startTestSensor(t *testing.T, cfg config.Sensor) (*collectingSink, string) {
	t.Helper()
	gate, err := policy.NewTCPGate(cfg, policy.NewEnforcer(config.Detection{}, observe.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, gate)
	if err != nil {
		t.Fatal(err)
	}
	sink := newCollectingSink()
	deps, bus := newDeps(cfg, sink)
	if err := s.Start(context.Background(), deps); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = s.Close(ctx)
		cancel()
		bus.Close()
	})
	return sink, s.Addr()
}

func tcpCfg() config.Sensor {
	return config.Sensor{
		ID: "tcp-test", Kind: "tcp", Listen: "127.0.0.1:0",
		Banner: "decoy ready\n",
		Session: &config.TCPSession{
			MaxLineBytes: 4096, IdleTimeoutSeconds: 5, MaxSessionSeconds: 30,
		},
		TCPResponseRule: []config.TCPRule{
			{Name: "ping", LineRegex: "^PING$", Response: "+OK PONG"},
			{Name: "default", LineRegex: "^.*$", Response: "-ERR unknown"},
		},
	}
}

// dial connects and registers cleanup; it performs no I/O assumptions.
func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// collect reads from conn until every marker appears in the accumulated
// output, the connection closes, or a hard deadline passes. TCP provides no
// message framing: one server write may arrive as several reads and adjacent
// writes may coalesce, so tests never assume write↔read pairing.
func collect(t *testing.T, conn net.Conn, end time.Time, markers ...string) string {
	t.Helper()
	_ = conn.SetReadDeadline(end)
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		out := sb.String()
		complete := len(markers) > 0
		for _, m := range markers {
			if !strings.Contains(out, m) {
				complete = false
				break
			}
		}
		if complete {
			return out
		}
		n, err := conn.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
			continue // re-check markers before blocking again
		}
		if err != nil {
			return sb.String() // timeout or EOF: caller asserts on what arrived
		}
	}
}

func TestTCPSensorBannerAndRules(t *testing.T) {
	sink, addr := startTestSensor(t, tcpCfg())
	end := time.Now().Add(3 * time.Second)

	conn := dial(t, addr)
	banner := collect(t, conn, end, "decoy ready\n")
	if !strings.HasPrefix(banner, "decoy ready\n") {
		t.Fatalf("banner missing: %q", banner)
	}

	if _, err := conn.Write([]byte("PING\n")); err != nil {
		t.Fatal(err)
	}
	got1 := collect(t, conn, end, "+OK PONG\n")

	if _, err := conn.Write([]byte("STAT x\n")); err != nil {
		t.Fatal(err)
	}
	got2 := collect(t, conn, end, "-ERR unknown\n")

	stream := banner + got1 + got2
	if !strings.Contains(stream, "+OK PONG\n") || !strings.Contains(stream, "-ERR unknown\n") {
		t.Fatalf("rule responses missing: %q %q %q", banner, got1, got2)
	}

	events := sink.waitFor(t, 2)
	for _, e := range events {
		if e.Classification != event.ClassificationInteraction {
			t.Fatalf("classification: %s", e.Classification)
		}
		if err := e.VerifyIntegrity(); err != nil {
			t.Fatal(err)
		}
	}
	var obs struct {
		LastLinePreview string `json:"last_line_preview"`
	}
	if err := json.Unmarshal(events[0].Observation, &obs); err != nil {
		t.Fatal(err)
	}
	if obs.LastLinePreview != "PING" {
		t.Fatalf("preview wrong: %q", obs.LastLinePreview)
	}
}

func TestTCPSensorOversizedLineDropsSession(t *testing.T) {
	cfg := tcpCfg()
	cfg.Session.MaxLineBytes = 64
	_, addr := startTestSensor(t, cfg)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(strings.Repeat("A", 200) + "\n")); err != nil {
		t.Fatal(err)
	}

	// The banner may already be buffered client-side; drain until the server
	// closes the session. The invariant is termination without any reply to
	// the oversized line.
	end := time.Now().Add(3 * time.Second)
	_ = conn.SetReadDeadline(end)
	var got strings.Builder
	buf := make([]byte, 4096)
	closed := false
	for time.Now().Before(end) {
		n, rerr := conn.Read(buf)
		got.Write(buf[:n])
		if rerr != nil {
			closed = true
			break
		}
	}
	if !closed {
		t.Fatal("session must be closed after an over-long line")
	}
	stream := got.String()
	if strings.Contains(stream, "+OK") || strings.Contains(stream, "-ERR") {
		t.Fatalf("oversized line must not be answered: %q", stream)
	}
}

func TestTCPSensorEmptyLinesAreIgnored(t *testing.T) {
	sink, addr := startTestSensor(t, tcpCfg())
	end := time.Now().Add(3 * time.Second)

	conn := dial(t, addr)
	collect(t, conn, end, "decoy ready\n")
	for i := 0; i < 5; i++ {
		if _, err := conn.Write([]byte("\r\n")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := conn.Write([]byte("PING\n")); err != nil {
		t.Fatal(err)
	}
	got := collect(t, conn, end, "+OK PONG\n")
	if strings.Contains(got, "-ERR") {
		t.Fatalf("empty lines produced replies: %q", got)
	}

	events := sink.waitFor(t, 1)
	if len(events) != 1 {
		t.Fatalf("want exactly 1 interaction event (empty lines skipped), got %d", len(events))
	}
}

func TestTCPSensorCloseReleasesSessions(t *testing.T) {
	cfg := tcpCfg()
	gate, err := policy.NewTCPGate(cfg, policy.NewEnforcer(config.Detection{}, observe.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, gate)
	if err != nil {
		t.Fatal(err)
	}
	sink := newCollectingSink()
	deps, bus := newDeps(cfg, sink)
	defer bus.Close()
	if err := s.Start(context.Background(), deps); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.Close(ctx); err != nil {
		t.Fatalf("Close must not hang with a live session: %v", err)
	}
	select {
	case <-s.Done():
	default:
		t.Fatal("Done channel should be closed after Close")
	}
}

func FuzzMatchTCPLine(f *testing.F) {
	f.Add([]byte("PING\n"))
	f.Add([]byte(strings.Repeat("A", 5000)))
	f.Add([]byte("\r\n"))
	f.Add([]byte{0x00, 0x01, '\n'})
	f.Add([]byte("no newline at eof"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		r := bufio.NewReader(bytes.NewReader(raw))
		line, err := readLine(r, 1024)
		if err == nil && len(line) > 1024 {
			t.Fatalf("readLine returned %d bytes despite cap", len(line))
		}
	})
}
