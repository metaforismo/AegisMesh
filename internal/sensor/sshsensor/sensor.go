// Package sshsensor implements a bounded SSH authentication deception sensor.
// It completes synthetic authentication so clients reveal protocol metadata,
// then rejects every channel and global request. It never provides a shell,
// PTY, forwarding, filesystem, or command-execution path.
package sshsensor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/redact"
	"github.com/metaforismo/aegismesh/internal/sensor"
)

const (
	maxHandshakeTimeout = time.Duration(config.MaxSSHHandshakeTimeoutSeconds) * time.Second
	maxSessionTimeout   = time.Duration(config.MaxSSHSessionSeconds) * time.Second
	maxAuthTries        = config.MaxSSHAuthAttempts

	// These caps bound attacker-controlled values that reach the callbacks and
	// event payload. The SSH library independently bounds individual packets.
	maxUsernameBytes  = 128
	maxPasswordBytes  = 1024
	maxPublicKeyBytes = 8192
	maxClientVersion  = 128

	maxConcurrentSessions = 128
	maxRejectedRequests   = 256
	maxRejectedChannels   = 256
)

var errInputCap = errors.New("ssh sensor input exceeds cap")

type settings struct {
	ID               string
	Listen           string
	ServerVersion    string
	HandshakeTimeout time.Duration
	SessionTimeout   time.Duration
	MaxAuthTries     int
}

// Sensor is a long-running SSH decoy listener.
type Sensor struct {
	id     string
	cfg    settings
	signer ssh.Signer
	listen func(network, address string) (net.Listener, error)

	mu         sync.Mutex
	ln         net.Listener
	conns      map[net.Conn]struct{}
	started    bool
	closing    bool
	runCtx     context.Context
	cancel     context.CancelFunc
	acceptDone chan struct{}
	wg         sync.WaitGroup

	done      chan error
	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error

	active observe.Gauge
	events observe.Counter
}

// New constructs a sensor from the validated versioned repository config with
// a fresh in-memory Ed25519 host key. The private key is intentionally not
// accepted from configuration or persisted to disk; reconstructing the sensor
// therefore rotates its decoy host identity.
func New(c config.Sensor) (*Sensor, error) {
	if c.Kind != config.SensorKindSSH {
		return nil, fmt.Errorf("sshsensor %s: kind must be %q", c.ID, config.SensorKindSSH)
	}
	if c.SSH == nil {
		return nil, fmt.Errorf("sshsensor %s: missing ssh configuration", c.ID)
	}
	if c.SSH.HandshakeTimeoutSeconds <= 0 || c.SSH.HandshakeTimeoutSeconds > config.MaxSSHHandshakeTimeoutSeconds {
		return nil, fmt.Errorf("sshsensor %s: handshake timeout must be within 1..%d seconds", c.ID, config.MaxSSHHandshakeTimeoutSeconds)
	}
	if c.SSH.MaxSessionSeconds <= 0 || c.SSH.MaxSessionSeconds > config.MaxSSHSessionSeconds {
		return nil, fmt.Errorf("sshsensor %s: session timeout must be within 1..%d seconds", c.ID, config.MaxSSHSessionSeconds)
	}
	if c.SSH.MaxAuthAttempts <= 0 || c.SSH.MaxAuthAttempts > config.MaxSSHAuthAttempts {
		return nil, fmt.Errorf("sshsensor %s: max auth attempts must be within 1..%d", c.ID, config.MaxSSHAuthAttempts)
	}
	sensorSettings := settings{
		ID:               c.ID,
		Listen:           c.Listen,
		ServerVersion:    c.SSH.ServerVersion,
		HandshakeTimeout: time.Duration(c.SSH.HandshakeTimeoutSeconds) * time.Second,
		SessionTimeout:   time.Duration(c.SSH.MaxSessionSeconds) * time.Second,
		MaxAuthTries:     c.SSH.MaxAuthAttempts,
	}
	sensorSettings, err := normalizeConfig(sensorSettings)
	if err != nil {
		return nil, err
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sshsensor %s: generate host key: %w", c.ID, err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		return nil, fmt.Errorf("sshsensor %s: create host signer: %w", c.ID, err)
	}
	return &Sensor{
		id:     sensorSettings.ID,
		cfg:    sensorSettings,
		signer: signer,
		listen: net.Listen,
		conns:  make(map[net.Conn]struct{}),
		done:   make(chan error, 1),
		closed: make(chan struct{}),
	}, nil
}

func (s *Sensor) ID() string   { return s.id }
func (s *Sensor) Kind() string { return config.SensorKindSSH }

// Addr reports the bound address after Start succeeds.
func (s *Sensor) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

func (s *Sensor) Done() <-chan error { return s.done }

// Start binds the listener and starts the bounded accept loop. The context
// only bounds startup; Close owns the sensor lifecycle after binding, matching
// the other long-running sensors.
func (s *Sensor) Start(ctx context.Context, d sensor.Deps) error {
	if err := sensor.ValidateDeps(d); err != nil {
		return err
	}

	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return fmt.Errorf("sshsensor %s: already started", s.id)
	}
	if s.closing {
		s.mu.Unlock()
		return fmt.Errorf("sshsensor %s: already closed", s.id)
	}
	s.started = true
	s.mu.Unlock()

	ln, err := s.listen("tcp", s.cfg.Listen)
	if err != nil {
		s.mu.Lock()
		s.started = false
		s.mu.Unlock()
		return fmt.Errorf("sshsensor %s: bind %s: %w", s.id, s.cfg.Listen, err)
	}

	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		_ = ln.Close()
		return fmt.Errorf("sshsensor %s: already closed", s.id)
	}
	s.ln = ln
	s.runCtx, s.cancel = context.WithCancel(context.WithoutCancel(ctx))
	s.acceptDone = make(chan struct{})
	s.active = d.Meter.Gauge(
		"aegismesh_sensor_ssh_active_sessions",
		"Currently open SSH decoy sessions")
	s.events = d.Meter.Counter(
		"aegismesh_sensor_ssh_connections_total",
		"SSH decoy connections observed")
	runCtx := s.runCtx
	acceptDone := s.acceptDone
	s.mu.Unlock()

	sem := make(chan struct{}, maxConcurrentSessions)
	go s.acceptLoop(runCtx, acceptDone, sem, d, ln)
	d.Log.Info("ssh sensor listening", "sensor", s.id, "addr", ln.Addr().String())
	return nil
}

func (s *Sensor) acceptLoop(ctx context.Context, acceptDone chan struct{}, sem chan struct{}, d sensor.Deps, ln net.Listener) {
	defer close(acceptDone)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil || s.isClosing() {
				return
			}
			d.Log.Error("ssh accept failed", "sensor", s.id)
			select {
			case s.done <- fmt.Errorf("sshsensor %s: accept: %w", s.id, err):
			default:
			}
			return
		}

		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			_ = conn.Close()
			return
		default:
			// Do not let a full session cap stall Accept. Excess connections
			// are closed immediately and never reach protocol handling.
			_ = conn.Close()
			continue
		}
		if !s.admit(conn) {
			<-sem
			_ = conn.Close()
			return
		}
		go func(c net.Conn) {
			s.serve(ctx, c, sem, d)
		}(conn)
	}
}

// admit makes WaitGroup accounting and shutdown exclusion atomic with the
// closing flag. Close waits for acceptDone before waiting on the group.
func (s *Sensor) admit(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return false
	}
	s.conns[conn] = struct{}{}
	s.wg.Add(1)
	return true
}

func (s *Sensor) serve(ctx context.Context, conn net.Conn, sem chan struct{}, d sensor.Deps) {
	defer func() {
		_ = conn.Close()
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		if s.active != nil {
			s.active.Add(-1)
		}
		<-sem
		s.wg.Done()
	}()
	if s.active != nil {
		s.active.Add(1)
	}
	if s.events != nil {
		s.events.Inc()
	}

	state := &connectionState{
		remoteHost: boundedRemoteHost(conn.RemoteAddr()),
		outcome:    outcomeHandshakeFailed,
	}
	started := time.Now()
	defer func() { s.emit(d, state, started) }()

	if err := conn.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout)); err != nil {
		return
	}
	serverConn, channels, requests, err := ssh.NewServerConn(conn, s.serverConfig(state))
	if err != nil {
		var authErr *ssh.ServerAuthError
		if errors.As(err, &authErr) {
			state.outcome = outcomeAuthenticationFailed
		} else if timeoutError(err) {
			state.outcome = outcomeHandshakeTimeout
		} else if ctx.Err() != nil || s.isClosing() {
			state.outcome = outcomeShutdown
		}
		return
	}

	state.authenticated = true
	state.outcome = outcomeAuthenticated
	state.clientVersion, state.clientVersionTruncated = boundedPreview(serverConn.ClientVersion(), maxClientVersion)
	if err := conn.SetDeadline(time.Now().Add(s.cfg.SessionTimeout)); err != nil {
		return
	}

	sessionCtx, cancel := context.WithTimeout(ctx, s.cfg.SessionTimeout)
	defer cancel()
	for {
		select {
		case <-sessionCtx.Done():
			if errors.Is(sessionCtx.Err(), context.DeadlineExceeded) {
				state.outcome = outcomeSessionTimeout
			} else {
				state.outcome = outcomeShutdown
			}
			_ = serverConn.Close()
			_ = serverConn.Wait()
			return
		case req, ok := <-requests:
			if !ok {
				state.outcome = sessionCloseOutcome(sessionCtx, serverConn.Wait())
				return
			}
			state.globalRequestsRejected++
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			if state.globalRequestsRejected >= maxRejectedRequests {
				state.outcome = outcomeProtocolCap
				_ = serverConn.Close()
				_ = serverConn.Wait()
				return
			}
		case channel, ok := <-channels:
			if !ok {
				state.outcome = sessionCloseOutcome(sessionCtx, serverConn.Wait())
				return
			}
			state.channelsRejected++
			_ = channel.Reject(ssh.Prohibited, "channels are not available")
			if state.channelsRejected >= maxRejectedChannels {
				state.outcome = outcomeProtocolCap
				_ = serverConn.Close()
				_ = serverConn.Wait()
				return
			}
		}
	}
}

func sessionCloseOutcome(ctx context.Context, err error) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || timeoutError(err) {
		return outcomeSessionTimeout
	}
	return outcomeClosed
}

func (s *Sensor) serverConfig(state *connectionState) *ssh.ServerConfig {
	algorithms := ssh.SupportedAlgorithms()
	serverConfig := &ssh.ServerConfig{
		Config: ssh.Config{
			KeyExchanges: algorithms.KeyExchanges,
			Ciphers:      algorithms.Ciphers,
			MACs:         algorithms.MACs,
		},
		PublicKeyAuthAlgorithms: algorithms.PublicKeyAuths,
		MaxAuthTries:            s.cfg.MaxAuthTries,
		ServerVersion:           s.cfg.ServerVersion,
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			state.recordUsername(conn.User())
			if len(conn.User()) > maxUsernameBytes {
				return nil, errInputCap
			}
			state.passwordBytes, state.passwordTruncated = boundedLength(len(password), maxPasswordBytes)
			if len(password) > maxPasswordBytes {
				return nil, errInputCap
			}
			// Synthetic authentication deliberately accepts any bounded password;
			// the bytes are not copied, compared, hashed, logged, or emitted.
			state.authMethod = "password"
			return nil, nil
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			state.recordUsername(conn.User())
			if len(conn.User()) > maxUsernameBytes {
				return nil, errInputCap
			}
			keyWire := key.Marshal()
			keyBytes, truncated := boundedLength(len(keyWire), maxPublicKeyBytes)
			state.publicKeyBytes = keyBytes
			state.publicKeyTruncated = truncated
			state.publicKeyType = safePublicKeyType(key.Type(), algorithms.PublicKeyAuths)
			if len(keyWire) > maxPublicKeyBytes {
				return nil, errInputCap
			}
			return nil, nil
		},
		VerifiedPublicKeyCallback: func(_ ssh.ConnMetadata, _ ssh.PublicKey, permissions *ssh.Permissions, _ string) (*ssh.Permissions, error) {
			state.authMethod = "publickey"
			return permissions, nil
		},
		AuthLogCallback: func(conn ssh.ConnMetadata, method string, authErr error) {
			state.recordUsername(conn.User())
			if state.authAttempts < maxRejectedRequests {
				state.authAttempts++
			}
			state.lastAuthMethod = canonicalAuthMethod(method)
			if authErr != nil && state.authFailures < maxRejectedRequests {
				state.authFailures++
			}
		},
	}
	serverConfig.AddHostKey(s.signer)
	return serverConfig
}

func (s *Sensor) emit(d sensor.Deps, state *connectionState, started time.Time) {
	obs := observation{
		Outcome:                state.outcome,
		Authenticated:          state.authenticated,
		AuthMethod:             state.authMethod,
		LastAuthMethod:         state.lastAuthMethod,
		AuthAttempts:           state.authAttempts,
		AuthFailures:           state.authFailures,
		UsernameBytes:          state.usernameBytes,
		UsernameTruncated:      state.usernameTruncated,
		PasswordBytes:          state.passwordBytes,
		PasswordTruncated:      state.passwordTruncated,
		PublicKeyType:          state.publicKeyType,
		PublicKeyBytes:         state.publicKeyBytes,
		PublicKeyTruncated:     state.publicKeyTruncated,
		ClientVersionPreview:   state.clientVersion,
		ClientVersionTruncated: state.clientVersionTruncated,
		RemoteHost:             state.remoteHost,
		GlobalRequestsRejected: state.globalRequestsRejected,
		ChannelsRejected:       state.channelsRejected,
		DurationMS:             time.Since(started).Milliseconds(),
	}
	raw, err := json.Marshal(obs)
	if err != nil {
		d.Log.Error("ssh observation marshal failed", "sensor", s.id)
		return
	}
	rules := []string{"username_content_dropped", "credential_content_dropped", "request_payload_dropped", "channel_payload_dropped"}
	if state.usernameTruncated || state.passwordTruncated || state.publicKeyTruncated || state.clientVersionTruncated {
		rules = append(rules, "input_truncated")
	}
	env, err := event.New(
		d.Seq,
		d.Instance,
		event.SensorRef{ID: s.cfg.ID, Kind: config.SensorKindSSH, Listen: s.cfg.Listen},
		event.ClassificationInteraction,
		raw,
		rules,
	)
	if err != nil {
		d.Log.Error("ssh event construction failed", "sensor", s.id)
		return
	}
	d.Bus.Submit(env)
}

func (s *Sensor) isClosing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closing
}

// Close stops accepting and closes active connections. A single background
// drain owns terminal channel closure, so a caller timeout cannot make Done
// signal completion while handlers are still exiting.
func (s *Sensor) Close(ctx context.Context) error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closing = true
		if s.cancel != nil {
			s.cancel()
		}
		ln := s.ln
		acceptDone := s.acceptDone
		active := make([]net.Conn, 0, len(s.conns))
		for conn := range s.conns {
			active = append(active, conn)
		}
		s.mu.Unlock()
		if ln != nil {
			if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				s.mu.Lock()
				s.closeErr = err
				s.mu.Unlock()
			}
		}
		for _, conn := range active {
			_ = conn.Close()
		}
		go s.finishClose(acceptDone)
	})

	select {
	case <-s.closed:
		return s.closeError()
	default:
	}
	select {
	case <-s.closed:
		return s.closeError()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Sensor) finishClose(acceptDone <-chan struct{}) {
	if acceptDone != nil {
		<-acceptDone
	}
	s.wg.Wait()
	close(s.closed)
	close(s.done)
}

func (s *Sensor) closeError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeErr
}

type connectionState struct {
	outcome       string
	authenticated bool
	authMethod    string

	lastAuthMethod string
	authAttempts   int
	authFailures   int

	usernameBytes      int
	usernameTruncated  bool
	passwordBytes      int
	passwordTruncated  bool
	publicKeyType      string
	publicKeyBytes     int
	publicKeyTruncated bool

	clientVersion          string
	clientVersionTruncated bool
	remoteHost             string

	globalRequestsRejected int
	channelsRejected       int
}

const (
	outcomeAuthenticated        = "authenticated"
	outcomeAuthenticationFailed = "authentication_failed"
	outcomeHandshakeFailed      = "handshake_failed"
	outcomeHandshakeTimeout     = "handshake_timeout"
	outcomeSessionTimeout       = "session_timeout"
	outcomeProtocolCap          = "protocol_cap"
	outcomeClosed               = "closed"
	outcomeShutdown             = "shutdown"
)

type observation struct {
	Outcome                string `json:"outcome"`
	Authenticated          bool   `json:"authenticated"`
	AuthMethod             string `json:"auth_method,omitempty"`
	LastAuthMethod         string `json:"last_auth_method,omitempty"`
	AuthAttempts           int    `json:"auth_attempts,omitempty"`
	AuthFailures           int    `json:"auth_failures,omitempty"`
	UsernameBytes          int    `json:"username_bytes,omitempty"`
	UsernameTruncated      bool   `json:"username_truncated,omitempty"`
	PasswordBytes          int    `json:"password_bytes,omitempty"`
	PasswordTruncated      bool   `json:"password_truncated,omitempty"`
	PublicKeyType          string `json:"public_key_type,omitempty"`
	PublicKeyBytes         int    `json:"public_key_bytes,omitempty"`
	PublicKeyTruncated     bool   `json:"public_key_truncated,omitempty"`
	ClientVersionPreview   string `json:"client_version_preview,omitempty"`
	ClientVersionTruncated bool   `json:"client_version_truncated,omitempty"`
	RemoteHost             string `json:"remote_host,omitempty"`
	GlobalRequestsRejected int    `json:"global_requests_rejected,omitempty"`
	ChannelsRejected       int    `json:"channels_rejected,omitempty"`
	DurationMS             int64  `json:"duration_ms"`
}

func (s *connectionState) recordUsername(username string) {
	s.usernameBytes, s.usernameTruncated = boundedLength(len(username), maxUsernameBytes)
}

func normalizeConfig(c settings) (settings, error) {
	if c.ID == "" {
		return settings{}, errors.New("sshsensor: empty id")
	}
	if c.Listen == "" {
		return settings{}, fmt.Errorf("sshsensor %s: missing listen address", c.ID)
	}
	if c.ServerVersion == "" {
		return settings{}, fmt.Errorf("sshsensor %s: missing server version", c.ID)
	}
	if !strings.HasPrefix(c.ServerVersion, "SSH-2.0-") || len(c.ServerVersion) > config.MaxSSHServerVersionBytes {
		return settings{}, fmt.Errorf("sshsensor %s: server version must start with SSH-2.0- and be at most %d bytes", c.ID, config.MaxSSHServerVersionBytes)
	}
	for i := 0; i < len(c.ServerVersion); i++ {
		if c.ServerVersion[i] < 0x20 || c.ServerVersion[i] > 0x7e {
			return settings{}, fmt.Errorf("sshsensor %s: server version must contain printable ASCII only", c.ID)
		}
	}
	if len(c.ServerVersion) == len("SSH-2.0-") {
		return settings{}, fmt.Errorf("sshsensor %s: server version must include a software version", c.ID)
	}
	if c.HandshakeTimeout <= 0 || c.HandshakeTimeout > maxHandshakeTimeout {
		return settings{}, fmt.Errorf("sshsensor %s: handshake timeout must be between 1ns and %s", c.ID, maxHandshakeTimeout)
	}
	if c.SessionTimeout <= 0 || c.SessionTimeout > maxSessionTimeout {
		return settings{}, fmt.Errorf("sshsensor %s: session timeout must be between 1ns and %s", c.ID, maxSessionTimeout)
	}
	if c.MaxAuthTries < 1 || c.MaxAuthTries > maxAuthTries {
		return settings{}, fmt.Errorf("sshsensor %s: max auth tries must be between 1 and %d", c.ID, maxAuthTries)
	}
	return c, nil
}

func boundedLength(n, max int) (int, bool) {
	if n > max {
		return max, true
	}
	return n, false
}

func boundedPreview(b []byte, max int) (string, bool) {
	return redact.Preview(b, max)
}

func boundedRemoteHost(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	preview, _ := redact.Preview([]byte(host), maxClientVersion)
	return preview
}

func safePublicKeyType(keyType string, supported []string) string {
	for _, candidate := range supported {
		if keyType == candidate {
			return keyType
		}
	}
	return "other"
}

func canonicalAuthMethod(method string) string {
	switch method {
	case "none", "password", "publickey", "keyboard-interactive", "gssapi-with-mic":
		return method
	default:
		return "other"
	}
}

func timeoutError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
