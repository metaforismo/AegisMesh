// Package httpsensor implements the HTTP deception sensor on a hardened
// net/http server: explicit timeouts, header caps, bounded bodies, and no
// handler path that can execute anything.
package httpsensor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/policy"
	"github.com/metaforismo/aegismesh/internal/redact"
	"github.com/metaforismo/aegismesh/internal/sensor"
)

type Sensor struct {
	id   string
	cfg  config.Sensor
	gate *policy.HTTPGate
	srv  *http.Server

	mu sync.Mutex // guards ln: Start, Addr, and Close may run on any goroutine
	ln net.Listener

	done chan error
	once sync.Once
}

func New(c config.Sensor, gate *policy.HTTPGate) (*Sensor, error) {
	if c.ID == "" {
		return nil, fmt.Errorf("httpsensor: empty id")
	}
	return &Sensor{id: c.ID, cfg: c, gate: gate, done: make(chan error, 1)}, nil
}

func (s *Sensor) ID() string   { return s.id }
func (s *Sensor) Kind() string { return config.SensorKindHTTP }

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
	eventsTotal := d.Meter.Counter(
		"aegismesh_sensor_http_interactions_total",
		"HTTP decoy interactions observed")

	maxBody := s.cfg.MaxBodyBytes
	if maxBody <= 0 || maxBody > 4<<20 {
		maxBody = 64 << 10
	}

	h := &handler{
		ref:      event.SensorRef{ID: s.cfg.ID, Kind: s.Kind(), Listen: s.cfg.Listen},
		gate:     s.gate,
		bus:      d.Bus,
		seq:      d.Seq,
		instance: d.Instance,
		log:      d.Log,
		maxBody:  maxBody,
		events:   eventsTotal,
	}

	s.srv = &http.Server{ //nolint:gosec // timeouts set explicitly below; TLS terminated upstream if ever used
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	addr := s.cfg.Listen
	if !strings.Contains(addr, "/") {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return fmt.Errorf("httpsensor %s: bad listen %q", s.id, addr)
		}
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("httpsensor %s: bind %s: %v", s.id, addr, err)
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			d.Log.Error("http sensor failed", "sensor", s.id, "err", err)
			select {
			case s.done <- err:
			default:
			}
		}
	}()
	d.Log.Info("http sensor listening", "sensor", s.id, "addr", ln.Addr().String())
	return nil
}

func (s *Sensor) Close(ctx context.Context) error {
	var err error
	s.once.Do(func() {
		if s.srv != nil {
			err = s.srv.Shutdown(ctx)
		}
		close(s.done)
	})
	return err
}

type handler struct {
	ref      event.SensorRef
	gate     *policy.HTTPGate
	bus      *event.Bus
	seq      *event.Sequencer
	instance string
	log      *slog.Logger
	maxBody  int64
	events   observe.Counter
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	body, truncated := readBounded(r, h.maxBody)

	dec, err := h.gate.Resolve(r.Context(), r.Method, r.RequestURI, body)
	if err != nil {
		h.log.Warn("policy resolution failed", "err", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	for k, v := range dec.Headers {
		w.Header().Set(k, v)
	}
	// Persona realism: advertise the true body size even for HEAD, the way a
	// real origin server would.
	if dec.Body != nil && dec.Headers["Content-Length"] == "" {
		w.Header().Set("Content-Length", strconv.Itoa(len(dec.Body)))
	}
	w.WriteHeader(dec.Status)
	if r.Method != http.MethodHead && len(dec.Body) > 0 {
		if _, wErr := w.Write(dec.Body); wErr != nil {
			h.log.Debug("client write failed", "err", wErr)
		}
	}

	h.events.Inc()
	h.emit(r, body, truncated, dec, start)
}

// readBounded reads at most max bytes without letting the server generate its
// own error page (decoys must answer like the persona would).
func readBounded(r *http.Request, max int64) ([]byte, bool) {
	if r.Body == nil || r.ContentLength == 0 {
		io.Copy(io.Discard, io.LimitReader(r.Body, 4096)) //nolint:errcheck // drain best-effort
		return nil, false
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, max))
	truncated := err != nil || int64(len(b)) >= max //nolint:gosec // bounded above
	return b, truncated
}

func (h *handler) emit(r *http.Request, body []byte, bodyTruncated bool, dec policy.HTTPDecision, start time.Time) {
	hp := redact.DefaultHeaderPolicy()
	headers := map[string]string{}
	for name, vals := range r.Header {
		if len(vals) == 0 {
			continue
		}
		headers[name] = hp.Header(name, strings.Join(vals, ", "))
	}
	queryLen := len(r.URL.RawQuery)

	preview, previewTruncated := redact.Preview(body, redact.MaxPreviewBytes)
	sum := sha256.Sum256(body)

	obs := observation{
		Method:            r.Method,
		Path:              r.URL.Path,
		QueryRedacted:     queryLen > 0,
		QueryLength:       queryLen,
		Headers:           headers,
		Proto:             r.Proto,
		UserAgent:         truncate(hp.Header("User-Agent", r.UserAgent()), 160),
		RemoteHost:        sensor.PeerHost(r.RemoteAddr),
		BodyCapturedBytes: len(body),
		BodyTruncated:     bodyTruncated || previewTruncated,
		BodyPreview:       preview,
		BodySHA256:        hex.EncodeToString(sum[:]),
		DurationMS:        time.Since(start).Milliseconds(),
		Response:          responseInfo{RuleID: dec.RuleID, Via: string(dec.From), Status: dec.Status},
	}
	raw, err := json.Marshal(obs)
	if err != nil {
		h.log.Error("marshal observation", "err", err)
		return
	}
	env, err := event.New(h.seq, h.instance, h.ref, event.ClassificationInteraction, raw, obs.redactionRules())
	if err != nil {
		h.log.Error("event construction failed", "err", err)
		return
	}
	h.bus.Submit(env)
}

type observation struct {
	Method            string            `json:"method"`
	Path              string            `json:"path"`
	QueryRedacted     bool              `json:"query_redacted"`
	QueryLength       int               `json:"query_length,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
	Proto             string            `json:"proto"`
	UserAgent         string            `json:"user_agent,omitempty"`
	RemoteHost        string            `json:"remote_host"`
	BodyCapturedBytes int               `json:"body_captured_bytes"`
	BodyTruncated     bool              `json:"body_truncated,omitempty"`
	BodyPreview       string            `json:"body_preview,omitempty"`
	BodySHA256        string            `json:"body_sha256"`
	DurationMS        int64             `json:"duration_ms"`
	Response          responseInfo      `json:"response"`
}

type responseInfo struct {
	RuleID string `json:"rule_id"`
	Via    string `json:"via"`
	Status int    `json:"status"`
}

func (o *observation) redactionRules() []string {
	rules := []string{"header_values_policy"}
	if o.QueryRedacted {
		rules = append(rules, "query_string_dropped")
	}
	if o.BodyPreview != "" {
		rules = append(rules, "credential_scrub")
	}
	if o.BodyTruncated {
		rules = append(rules, "preview_truncated")
	}
	return rules
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
