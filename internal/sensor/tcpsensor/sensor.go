// Package tcpsensor implements a line-oriented TCP deception sensor: banner,
// bounded line reads, per-session byte and time caps, regex-matched responses.
package tcpsensor

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/policy"
	"github.com/metaforismo/aegismesh/internal/redact"
	"github.com/metaforismo/aegismesh/internal/sensor"
)

const maxConcurrentSessionsPerSensor = 256

type Sensor struct {
	id  string
	cfg config.Sensor
	g   *policy.TCPGate

	mu     sync.Mutex // guards ln: Start, Addr, and Close may run on any goroutine
	ln     net.Listener
	wg     sync.WaitGroup
	runCtx context.Context
	cancel context.CancelFunc

	done chan error
	once sync.Once

	sessions observe.Gauge
	log      *slog.Logger
}

func New(c config.Sensor, g *policy.TCPGate) (*Sensor, error) {
	if c.ID == "" {
		return nil, fmt.Errorf("tcpsensor: empty id")
	}
	return &Sensor{id: c.ID, cfg: c, g: g, done: make(chan error, 1)}, nil
}

func (s *Sensor) ID() string   { return s.id }
func (s *Sensor) Kind() string { return config.SensorKindTCP }

// listener returns the bound listener under the lock; nil before Start.
func (s *Sensor) listener() net.Listener {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ln
}

// Addr reports the bound address once Start has succeeded.
func (s *Sensor) Addr() string {
	ln := s.listener()
	if ln == nil {
		return ""
	}
	return ln.Addr().String()
}
func (s *Sensor) Done() <-chan error {
	return s.done
}

func (s *Sensor) Start(ctx context.Context, d sensor.Deps) error {
	if err := sensor.ValidateDeps(d); err != nil {
		return err
	}
	s.log = d.Log
	s.sessions = d.Meter.Gauge(
		"aegismesh_sensor_tcp_active_sessions",
		"Currently open TCP decoy sessions")

	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("tcpsensor %s: bind %s: %v", s.id, s.cfg.Listen, err)
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	// The Start context only bounds binding; serving runs on an internal
	// lifecycle that Close terminates. Sensors outlive their Start call.
	s.runCtx, s.cancel = context.WithCancel(context.WithoutCancel(ctx))

	sem := make(chan struct{}, maxConcurrentSessionsPerSensor)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					continue
				}
				d.Log.Error("tcp accept failed", "sensor", s.id, "err", err)
				select {
				case s.done <- err:
				default:
				}
				return
			}
			select {
			case sem <- struct{}{}:
			case <-s.runCtx.Done():
				_ = conn.Close()
				return
			}
			s.wg.Add(1)
			go func(c net.Conn) {
				defer func() { <-sem; s.wg.Done() }()
				s.serve(s.runCtx, c, d)
			}(conn)
		}
	}()
	d.Log.Info("tcp sensor listening", "sensor", s.id, "addr", ln.Addr().String())
	return nil
}

// serve handles one session. Every read is deadline-bounded and size-bounded;
// the session ends at the first protocol violation or cap.
func (s *Sensor) serve(ctx context.Context, conn net.Conn, d sensor.Deps) {
	defer conn.Close()

	cfg := *s.cfg.Session
	if cfg.MaxLineBytes <= 0 || cfg.MaxLineBytes > 64<<10 {
		cfg.MaxLineBytes = 4096
	}
	idle := time.Duration(cfg.IdleTimeoutSeconds) * time.Second
	if idle <= 0 || idle > time.Hour {
		idle = 30 * time.Second
	}
	total := time.Duration(cfg.MaxSessionSeconds) * time.Second
	if total <= 0 || total > 24*time.Hour {
		total = 5 * time.Minute
	}

	sessionCtx, cancel := context.WithTimeout(ctx, total)
	defer cancel()
	_ = conn.SetDeadline(time.Now().Add(total))

	interactions := d.Meter.Counter(
		"aegismesh_sensor_tcp_interactions_total",
		"TCP decoy line interactions observed")
	s.sessions.Add(1)
	defer s.sessions.Add(-1)

	ref := event.SensorRef{ID: s.cfg.ID, Kind: s.Kind(), Listen: s.cfg.Listen}
	if s.cfg.Banner != "" {
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte(s.cfg.Banner)); err != nil {
			return
		}
	}

	reader := bufio.NewReader(conn)
	var lines []string
	bytesSeen := 0

	for {
		select {
		case <-sessionCtx.Done():
			return
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(idle))
		line, err := readLine(reader, cfg.MaxLineBytes)
		if err != nil {
			return // timeout, EOF, oversized line, or reset: all end the session
		}
		if len(line) == 0 {
			continue
		}
		bytesSeen += len(line)
		lines = append(lines, line)

		dec := s.g.Resolve(line)
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(dec.Response); err != nil {
			return
		}
		interactions.Inc()
		s.emit(d, ref, conn.RemoteAddr().String(), lines, bytesSeen, dec, len(line))
		lines = nil // one event per exchange keeps evidence granular
	}
}

// readLine reads up to max bytes until '\n', treating EOF as end of input.
// An over-long line is an error (the connection is dropped), never truncated
// silently — truncation would let attackers smuggle rule-splitting payloads.
func readLine(r *bufio.Reader, max int) (string, error) {
	var sb []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && len(sb) > 0 {
				return string(sb), nil
			}
			return "", err
		}
		if b == '\n' {
			out := string(sb)
			return stringsTrimSuffixCR(out), nil
		}
		sb = append(sb, b)
		if len(sb) > max {
			return "", fmt.Errorf("line exceeds %d bytes", max)
		}
	}
}

func stringsTrimSuffixCR(s string) string {
	if len(s) > 0 && s[len(s)-1] == '\r' {
		return s[:len(s)-1]
	}
	return s
}

func (s *Sensor) emit(d sensor.Deps, ref event.SensorRef, remote string, lines []string, bytesSeen int, dec policy.TCPDecision, lastLineLen int) {
	last := ""
	if n := len(lines); n > 0 {
		last = lines[n-1]
	}
	preview, truncated := redact.Preview([]byte(last), redact.MaxPreviewBytes)
	sum := sha256.Sum256([]byte(last))

	obs := observation{
		LinesExchanged:    len(lines),
		BytesTotal:        bytesSeen,
		LastLineLen:       lastLineLen,
		LastLineSHA256:    hex.EncodeToString(sum[:]),
		LastLinePreview:   preview,
		LastLineTruncated: truncated,
		RemoteHost:        sensor.PeerHost(remote),
		Response: responseInfo{
			RuleID:       dec.RuleID,
			Via:          string(dec.From),
			ReplyPreview: safePreview(dec.Response),
		},
	}
	raw, err := json.Marshal(obs)
	if err != nil {
		return
	}
	rules := []string{"credential_scrub"}
	if truncated {
		rules = append(rules, "preview_truncated")
	}
	env, err := event.New(d.Seq, d.Instance, ref, event.ClassificationInteraction, raw, rules)
	if err != nil {
		d.Log.Error("event construction failed", "err", err)
		return
	}
	d.Bus.Submit(env)
}

func safePreview(b []byte) string {
	p, _ := redact.Preview(b, 128)
	return p
}

type observation struct {
	LinesExchanged    int          `json:"lines_exchanged"`
	BytesTotal        int          `json:"bytes_total"`
	LastLineLen       int          `json:"last_line_len"`
	LastLineSHA256    string       `json:"last_line_sha256"`
	LastLinePreview   string       `json:"last_line_preview,omitempty"`
	LastLineTruncated bool         `json:"last_line_truncated,omitempty"`
	RemoteHost        string       `json:"remote_host"`
	Response          responseInfo `json:"response"`
}

type responseInfo struct {
	RuleID       string `json:"rule_id"`
	Via          string `json:"via"`
	ReplyPreview string `json:"reply_preview,omitempty"`
}

func (s *Sensor) Close(ctx context.Context) error {
	var err error
	s.once.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		s.mu.Lock()
		ln := s.ln
		s.mu.Unlock()
		if ln != nil {
			err = ln.Close()
		}
		waitDone := make(chan struct{})
		go func() { s.wg.Wait(); close(waitDone) }()
		select {
		case <-waitDone:
		case <-ctx.Done():
		}
		close(s.done)
	})
	return err
}
