// Package webhook delivers evidence envelopes to an operator-configured
// collector over HTTP(S). It is a best-effort, bounded, signed stream: the
// local evidence store stays authoritative and every drop is counted.
//
// Security posture (all enforced, all tested):
//   - destinations re-validated against internal/egress at construction;
//   - every dial target IP is re-classified at connect time (DNS rebinding
//     is defeated even when a name later resolves to a denied address);
//   - no environment proxies; redirects are never followed; TLS >= 1.2,
//     with cleartext http only for loopback behind an explicit opt-in;
//   - bodies are HMAC-SHA256-signed through a caller-provided key; the key
//     value never enters this package's logs or errors.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metaforismo/aegismesh/internal/egress"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
)

const (
	backoffBase = 200 * time.Millisecond
	backoffCap  = 2 * time.Second
)

type counters struct {
	delivered        observe.Counter
	droppedQueueFull observe.Counter
	droppedFailed    observe.Counter
	droppedShutdown  observe.Counter
	failedBatches    observe.Counter
	retryAttempts    observe.Counter
}

// Config constructs the sink. Endpoint must already be normalized by
// egress.ValidateURL in the caller; New re-validates as defense in depth.
type Config struct {
	Endpoint          *url.URL
	AllowLoopbackHTTP bool
	AllowPrivate      bool
	Secret            []byte // optional HMAC-SHA256 key; empty = unsigned (doctor reports it)
	QueueSize         int
	BatchSize         int
	FlushInterval     time.Duration
	Timeout           time.Duration
	MaxRetries        int
	ShutdownFlush     time.Duration
}

// Sink streams envelopes to the configured collector. Offer is safe for
// concurrent use until Close.
type Sink struct {
	cfg        Config
	ctx        context.Context // canceled at forced shutdown
	client     *http.Client
	ch         chan event.Envelope
	c          counters
	log        *slog.Logger
	cancel     context.CancelFunc
	exited     chan struct{}
	doneSignal chan struct{}
	closeOnce  sync.Once
	doneOne    sync.Once
	closed     atomic.Bool
	wg         sync.WaitGroup
}

// New validates the endpoint once more and starts the delivery worker.
func New(cfg Config, meter observe.Meter, log *slog.Logger) (*Sink, error) {
	if cfg.Endpoint == nil {
		return nil, errors.New("webhook: nil endpoint")
	}
	pol := egress.Policy{AllowLoopback: cfg.AllowLoopbackHTTP, AllowPrivate: cfg.AllowPrivate}
	u, err := egress.ValidateURL(pol, cfg.Endpoint.String())
	if err != nil {
		return nil, fmt.Errorf("webhook: %v", err)
	}
	if log == nil {
		log = slog.Default()
	}
	if cfg.QueueSize < 1 {
		cfg.QueueSize = 1
	}
	if cfg.BatchSize < 1 {
		cfg.BatchSize = 1
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.ShutdownFlush <= 0 {
		cfg.ShutdownFlush = 3 * time.Second
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	cfg.Endpoint = u

	ctx, cancel := context.WithCancel(context.Background())
	s := &Sink{
		cfg:        cfg,
		ctx:        ctx,
		cancel:     cancel,
		ch:         make(chan event.Envelope, cfg.QueueSize),
		exited:     make(chan struct{}),
		doneSignal: make(chan struct{}),
		log:        log,
		c: counters{
			delivered:        meter.Counter("aegismesh_webhook_delivered_events_total", "envelopes accepted by the collector"),
			droppedQueueFull: meter.Counter("aegismesh_webhook_dropped_queue_full_total", "envelopes dropped because the queue was full"),
			droppedFailed:    meter.Counter("aegismesh_webhook_dropped_failed_total", "envelopes lost with permanently failed batches"),
			droppedShutdown:  meter.Counter("aegismesh_webhook_dropped_shutdown_total", "envelopes abandoned at shutdown"),
			failedBatches:    meter.Counter("aegismesh_webhook_failed_batches_total", "batches that exhausted retries"),
			retryAttempts:    meter.Counter("aegismesh_webhook_retry_attempts_total", "retry attempts performed"),
		},
	}
	s.client = s.buildClient(pol)
	s.wg.Add(1)
	go s.work()
	return s, nil
}

func (s *Sink) buildClient(pol egress.Policy) *http.Client {
	dialer := egress.NewDialer(pol, 5*time.Second)
	transport := &http.Transport{
		Proxy: nil, // never honor environment proxies for evidence egress
		DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("dial address %q: %v", addr, err)
			}
			// IP literals go straight to the policy-checked dialer; names are
			// resolved here and only policy-compliant addresses are dialed.
			// The dialer's Control hook re-classifies the final IP either way,
			// so a rebinding resolver cannot smuggle traffic toward metadata
			// or private ranges.
			if net.ParseIP(host) != nil {
				return dialer.DialContext(dialCtx, network, addr)
			}
			resolver := &net.Resolver{}
			ips, rerr := resolver.LookupIPAddr(dialCtx, host)
			if rerr != nil {
				return nil, fmt.Errorf("resolve %q: %v", host, rerr)
			}
			var lastErr error
			for _, ia := range ips {
				if egress.Classify(ia.IP, pol) != "" {
					continue
				}
				conn, derr := dialer.DialContext(dialCtx, network, net.JoinHostPort(ia.IP.String(), port))
				if derr == nil {
					return conn, nil
				}
				lastErr = derr
			}
			if lastErr == nil {
				lastErr = fmt.Errorf("no policy-compliant address for %q", host)
			}
			return nil, lastErr
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &http.Client{
		Transport:     transport,
		CheckRedirect: egress.RefuseAllRedirects,
		Timeout:       s.cfg.Timeout,
	}
}

// Offer enqueues one envelope without blocking. It returns false when the
// queue was full (counted) or the sink is closing.
func (s *Sink) Offer(e event.Envelope) bool {
	if s.closed.Load() {
		return false
	}
	select {
	case s.ch <- e:
		return true
	default:
		s.c.droppedQueueFull.Inc()
		return false
	}
}

// Close stops intake, waits up to ShutdownFlush for the worker to finish,
// then cancels in-flight work and abandons whatever remains (counted).
// Idempotent and bounded.
func (s *Sink) Close() {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.ch)
	})
	select {
	case <-s.exited:
	default:
		select {
		case <-s.exited:
		case <-time.After(s.cfg.ShutdownFlush):
			// Flush window expired: abandon the queue, cancel in-flight
			// work, then wait briefly so drop accounting is visible before
			// Close returns.
			s.forceStop()
			select {
			case <-s.exited:
			case <-time.After(2 * time.Second):
			}
		}
	}
	s.cancel()
}

// forceStop signals the worker to abandon its queue and cancels HTTP work.
func (s *Sink) forceStop() {
	s.doneOne.Do(func() { close(s.doneSignal) })
	s.cancel()
}

func (s *Sink) work() {
	defer s.wg.Done()
	defer close(s.exited)
	ticker := time.NewTicker(s.cfg.FlushInterval)
	defer ticker.Stop()

	batch := make([]event.Envelope, 0, s.cfg.BatchSize)
	send := func() {
		if len(batch) == 0 {
			return
		}
		s.deliver(batch)
		batch = batch[:0]
	}

	for {
		select {
		case e, ok := <-s.ch:
			if !ok {
				send()
				return
			}
			batch = append(batch, e)
			if len(batch) >= s.cfg.BatchSize {
				send()
			}
		case <-ticker.C:
			send()
		case <-s.doneSignal:
			s.abandon(&batch)
			return
		}
	}
}

// abandon counts everything still queued as shutdown drops. The channel is
// already closed when this runs, so draining terminates.
func (s *Sink) abandon(batch *[]event.Envelope) {
	n := len(*batch)
	for {
		select {
		case _, ok := <-s.ch:
			if !ok {
				s.countDrops(n)
				return
			}
			n++
		default:
			s.countDrops(n)
			return
		}
	}
}

func (s *Sink) countDrops(n int) {
	for i := 0; i < n; i++ {
		s.c.droppedShutdown.Inc()
	}
	if n > 0 {
		s.log.Warn("webhook shutdown abandoned queued events", "count", n)
	}
}

func (s *Sink) deliver(batch []event.Envelope) {
	body, err := json.Marshal(struct {
		Events []event.Envelope `json:"events"`
	}{Events: batch})
	if err != nil {
		// Envelopes marshal by construction; treat any failure as data loss.
		for range batch {
			s.c.droppedFailed.Inc()
		}
		s.c.failedBatches.Inc()
		return
	}
	attempts := s.cfg.MaxRetries + 1
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if s.ctx.Err() != nil {
			break
		}
		status, perr := s.post(body)
		if perr == nil && status >= 200 && status < 300 {
			for range batch {
				s.c.delivered.Inc()
			}
			return
		}
		if perr == nil {
			lastErr = fmt.Errorf("collector returned status %d", status)
		} else {
			lastErr = perr
		}
		if attempt < attempts {
			s.c.retryAttempts.Inc()
			time.Sleep(fullJitter(backoffBase << uint(min(attempt-1, 3))))
		}
	}
	shuttingDown := s.ctx.Err() != nil || s.closed.Load()
	for range batch {
		if shuttingDown {
			s.c.droppedShutdown.Inc()
		} else {
			s.c.droppedFailed.Inc()
		}
	}
	s.c.failedBatches.Inc()
	// Errors carry statuses and transport reasons only — never body or key material.
	s.log.Warn("webhook batch failed", "reason", fmt.Sprint(lastErr), "events", len(batch))
}

func (s *Sink) post(body []byte) (int, error) {
	ctx, cancel := context.WithTimeout(s.ctx, s.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AegisMesh-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	var batchID [8]byte
	if _, err := rand.Read(batchID[:]); err == nil {
		req.Header.Set("X-AegisMesh-Batch-ID", hex.EncodeToString(batchID[:]))
	}
	if len(s.cfg.Secret) > 0 {
		mac := hmac.New(sha256.New, s.cfg.Secret)
		mac.Write(body)
		req.Header.Set("X-AegisMesh-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	return resp.StatusCode, nil
}

// fullJitter sleeps a random duration in [0, cap) where cap doubles per
// retry attempt and is clamped to backoffCap.
func fullJitter(capDur time.Duration) time.Duration {
	if capDur > backoffCap {
		capDur = backoffCap
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	return time.Duration(binary.BigEndian.Uint64(b[:]) % uint64(capDur))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
