// Package agent sends signed inventory to one fixed, egress-validated hub.
// Hub responses are acknowledgements only and cannot select configuration, files, code or actions.
package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/metaforismo/aegismesh/internal/egress"
	"github.com/metaforismo/aegismesh/internal/fleet/identity"
	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
	"github.com/metaforismo/aegismesh/internal/observe"
)

// Error identifies a safe delivery failure category with a local actionable explanation.
type Error struct {
	// Code is a fixed local error category, never hub-authored text.
	Code string
	// Hint explains an operator action without including credentials or signatures.
	Hint string
}

// Error returns the safe local explanation suitable for status and logging.
func (e *Error) Error() string {
	return "fleet: " + e.Hint
}

func localError(code, hint string) error {
	return &Error{
		Code: code,
		Hint: hint,
	}
}

// Options injects trusted startup configuration, a snapshot seam and deterministic clock when needed.
type Options struct {
	// HubURL is the fixed origin subjected to egress validation.
	HubURL string
	// StateDir is the trusted private identity directory.
	StateDir string
	// Name is the immutable proposed node slug.
	Name string
	// Token is resolved by the caller before construction and never logged.
	Token string
	// CAFile optionally augments the system trust roots.
	CAFile string
	// AllowPrivate permits RFC1918/ULA hub destinations only.
	AllowPrivate bool
	// Interval is the validated 10..300 second reporting interval.
	Interval time.Duration
	// Snapshot returns local inventory without evidence or addresses.
	Snapshot func() protocol.Heartbeat
	// Now supplies the clock used to sign requests; nil uses time.Now.
	Now func() time.Time
	// Meter receives fixed-cardinality delivery counters.
	Meter observe.Meter
	// Log receives safe local error categories only.
	Log *slog.Logger
	// Transport replaces the policy-checked transport in trusted in-process tests only.
	Transport http.RoundTripper
}

// Agent owns one key and one background delivery loop, independent of evidence writes.
type Agent struct {
	stepMu   sync.Mutex
	mu       sync.Mutex
	status   protocol.AgentStatus
	key      ed25519.PrivateKey
	client   *http.Client
	endpoint string
	name     string
	token    string
	interval time.Duration
	snapshot func() protocol.Heartbeat
	now      func() time.Time
	outcomes observe.LabeledCounter
	log      *slog.Logger
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	once     sync.Once
}

// New validates transport and loads identity without sending requests or starting goroutines.
func New(opts Options) (*Agent, error) {
	endpoint, err := egress.ValidateURL(egress.Policy{
		AllowLoopback: true,
		AllowPrivate:  opts.AllowPrivate,
	}, opts.HubURL)
	if err != nil || endpoint.Path != "" && endpoint.Path != "/" || endpoint.RawPath != "" ||
		endpoint.ForceQuery || !protocol.NameValid(opts.Name) || opts.Snapshot == nil ||
		opts.Interval < 10*time.Second || opts.Interval > 300*time.Second ||
		opts.Token != "" && !protocol.Hex(opts.Token, 32) {
		return nil, localError("configuration", "invalid endpoint, name, interval, credential or snapshot dependency")
	}
	client, err := newClient(endpoint, opts.AllowPrivate, opts.CAFile)
	if err != nil {
		return nil, err
	}
	if opts.Transport != nil {
		client.Transport = opts.Transport
	}
	key, err := identity.Load(opts.StateDir)
	if err != nil {
		return nil, err
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Meter == nil {
		opts.Meter = observe.NewRegistry()
	}
	return &Agent{
		status: protocol.AgentStatus{
			Enabled: true,
			HubURL:  strings.TrimSuffix(endpoint.String(), "/"),
			NodeID:  protocol.ID(key.Public().(ed25519.PublicKey)),
		},
		key:      key,
		client:   client,
		endpoint: strings.TrimSuffix(endpoint.String(), "/"),
		name:     opts.Name,
		token:    opts.Token,
		interval: opts.Interval,
		snapshot: opts.Snapshot,
		now:      opts.Now,
		log:      opts.Log,
		outcomes: opts.Meter.CounterVec("aegismesh_fleet_agent_attempts_total", "Fleet delivery outcomes", 2),
	}, nil
}

// Status returns a secret-free value snapshot of this process's delivery state.
func (a *Agent) Status() protocol.AgentStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.status
}

// Step performs one bounded enrollment/heartbeat attempt; failures never escape into the evidence path.
func (a *Agent) Step(ctx context.Context) error {
	a.stepMu.Lock()
	defer a.stepMu.Unlock()
	var err error
	if !a.Status().Enrolled {
		err = a.post(ctx, protocol.EnrollPath, protocol.Enrollment{
			Token:           a.token,
			PublicKey:       hex.EncodeToString(a.key.Public().(ed25519.PublicKey)),
			Name:            a.name,
			IntervalSeconds: int(a.interval / time.Second),
		})
		if err == nil {
			a.mu.Lock()
			a.status.Enrolled = true
			a.mu.Unlock()
			a.token = ""
		}
	}
	if err == nil {
		status := a.snapshot()
		status.Name = a.name
		if !status.Valid() {
			err = localError("projection", "invalid local status projection")
		} else {
			err = a.post(ctx, protocol.HeartbeatPath, status)
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		a.status.LastError = err.Error()
		a.outcomes.Inc("failed")
		a.log.Warn("fleet inventory delivery failed", "reason", a.status.LastError)
		return err
	}
	a.status.LastHeartbeatAt = a.now().UTC().Format(time.RFC3339Nano)
	a.status.LastError = ""
	a.outcomes.Inc("accepted")
	return nil
}

func (a *Agent) post(ctx context.Context, path string, value any) error {
	body, err := json.Marshal(value)
	if err != nil || len(body) > protocol.MaxBodyBytes {
		return localError("request", "local request exceeds bounds")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return localError("request", "cannot construct request")
	}
	request.Header.Set("Content-Type", "application/json")
	if protocol.Sign(request, body, a.key, a.now()) != nil {
		return localError("signing", "request signing failed")
	}
	response, err := a.client.Do(request)
	if err != nil {
		return localError("transport", "hub transport unavailable; check reachability, TLS trust and egress policy")
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, protocol.MaxBodyBytes+1))
	if err != nil || len(payload) > protocol.MaxBodyBytes {
		return localError("response", "invalid or oversized hub response")
	}
	if response.StatusCode != http.StatusOK {
		return responseError(response.StatusCode)
	}
	var acknowledgement struct {
		NodeID string `json:"node_id"`
	}
	if protocol.Decode(payload, &acknowledgement) != nil || acknowledgement.NodeID != a.Status().NodeID {
		return localError("response", "invalid hub acknowledgement")
	}
	return nil
}

func responseError(status int) error {
	switch status {
	case http.StatusUnauthorized:
		return localError("authentication", "authentication refused; check token, clock and enrollment")
	case http.StatusForbidden:
		return localError("revoked", "node revoked; operator review required")
	default:
		return localError("refused", "hub refused inventory submission")
	}
}

// Start launches one asynchronous worker; the caller does not wait for the hub.
func (a *Agent) Start() {
	a.once.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		a.cancel = cancel
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			failures := 0
			for {
				err := a.Step(ctx)
				delay := a.interval
				if err != nil {
					failures = min(failures+1, 9)
					ceiling := min(time.Second*time.Duration(1<<failures), 300*time.Second)
					delay = ceiling/2 + time.Duration(rand.Int64N(int64(ceiling/2)+1))
				} else {
					failures = 0
				}
				timer := time.NewTimer(delay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}()
	})
}

// Close cancels in-flight HTTP work and joins the owned worker before runtime shutdown.
func (a *Agent) Close() {
	if a.cancel != nil {
		a.cancel()
	}
	a.wg.Wait()
	a.client.CloseIdleConnections()
}

// Origin returns the normalized fixed hub URL without credentials or query data.
func Origin(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}
