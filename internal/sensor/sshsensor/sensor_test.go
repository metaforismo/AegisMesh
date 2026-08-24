package sshsensor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
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
			t.Fatalf("received %d/%d SSH events", len(got), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func startTestSensor(t *testing.T, cfg settings) (*Sensor, *collectingSink, *event.Bus) {
	t.Helper()
	s, err := New(sensorConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	sink := newCollectingSink()
	bus := event.NewBus(32, sink, quietLogger())
	deps := sensor.Deps{
		Config: config.Sensor{ID: cfg.ID, Kind: config.SensorKindSSH, Listen: cfg.Listen},
		Bus:    bus, Meter: observe.NewRegistry(), Log: quietLogger(),
		Seq: &event.Sequencer{}, Instance: "ssh-test",
	}
	if err := s.Start(context.Background(), deps); err != nil {
		bus.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = s.Close(ctx)
		cancel()
		bus.Close()
	})
	return s, sink, bus
}

func testConfig(id string) settings {
	return settings{
		ID:               id,
		Listen:           "127.0.0.1:0",
		ServerVersion:    config.DefaultSSHServerVersion,
		HandshakeTimeout: 2 * time.Second,
		SessionTimeout:   5 * time.Second,
		MaxAuthTries:     3,
	}
}

func sensorConfig(c settings) config.Sensor {
	return config.Sensor{
		ID: c.ID, Kind: config.SensorKindSSH, Listen: c.Listen,
		SSH: &config.SSHConfig{
			ServerVersion:           c.ServerVersion,
			HandshakeTimeoutSeconds: int(c.HandshakeTimeout / time.Second),
			MaxSessionSeconds:       int(c.SessionTimeout / time.Second),
			MaxAuthAttempts:         c.MaxAuthTries,
		},
	}
}

func passwordClient(t *testing.T, addr, password string) *ssh.Client {
	t.Helper()
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "synthetic-user",
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // test-only ephemeral host key
		Timeout:         2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func decodeObservation(t *testing.T, env event.Envelope) observation {
	t.Helper()
	if env.Classification != event.ClassificationInteraction {
		t.Fatalf("classification = %q", env.Classification)
	}
	if err := env.VerifyIntegrity(); err != nil {
		t.Fatal(err)
	}
	var obs observation
	if err := json.Unmarshal(env.Observation, &obs); err != nil {
		t.Fatal(err)
	}
	return obs
}

func TestSSHSensorSyntheticPasswordAndRejectsProtocolBehavior(t *testing.T) {
	s, sink, _ := startTestSensor(t, testConfig("ssh-password"))
	client := passwordClient(t, s.Addr(), "not-a-real-secret")

	for _, requestType := range []string{"keepalive@openssh.com", "tcpip-forward", "unknown@aegismesh.test"} {
		ok, _, err := client.SendRequest(requestType, true, nil)
		if err != nil {
			t.Fatalf("global request %q: %v", requestType, err)
		}
		if ok {
			t.Fatalf("global request %q must be rejected", requestType)
		}
	}
	for _, channelType := range []string{"session", "direct-tcpip", "x11", "unknown@aegismesh.test"} {
		_, _, err := client.OpenChannel(channelType, nil)
		var openErr *ssh.OpenChannelError
		if !errors.As(err, &openErr) {
			t.Fatalf("OpenChannel(%q) error = %v, want *ssh.OpenChannelError", channelType, err)
		}
		if openErr.Reason != ssh.Prohibited {
			t.Fatalf("channel %q rejection reason = %v, want %v", channelType, openErr.Reason, ssh.Prohibited)
		}
	}
	_ = client.Close()

	events := sink.waitFor(t, 1)
	obs := decodeObservation(t, events[0])
	if !obs.Authenticated || obs.AuthMethod != "password" {
		t.Fatalf("synthetic authentication metadata = %+v", obs)
	}
	if obs.GlobalRequestsRejected != 3 || obs.ChannelsRejected != 4 {
		t.Fatalf("rejection metadata = %+v", obs)
	}
	if obs.PasswordBytes != len("not-a-real-secret") {
		t.Fatalf("password length metadata = %d", obs.PasswordBytes)
	}
	for _, want := range []string{"username_content_dropped", "credential_content_dropped", "request_payload_dropped", "channel_payload_dropped"} {
		if !slices.Contains(events[0].Redaction.Rules, want) {
			t.Fatalf("redaction rule %q missing: %v", want, events[0].Redaction.Rules)
		}
	}
	raw := string(events[0].Observation)
	for _, secret := range []string{"not-a-real-secret", "synthetic-user"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("credential-bearing content leaked into event: %q", raw)
		}
	}
}

func TestSSHCallbacksRejectOversizedMetadata(t *testing.T) {
	s, err := New(sensorConfig(testConfig("ssh-callback-caps")))
	if err != nil {
		t.Fatal(err)
	}

	state := &connectionState{}
	server := s.serverConfig(state)
	longUser := strings.Repeat("u", maxUsernameBytes+1)
	if _, err := server.PasswordCallback(testConnMetadata{user: longUser}, []byte("bounded")); !errors.Is(err, errInputCap) {
		t.Fatalf("oversized username error = %v", err)
	}
	if !state.usernameTruncated || state.usernameBytes != maxUsernameBytes {
		t.Fatalf("oversized username metadata = %+v", state)
	}

	state = &connectionState{}
	server = s.serverConfig(state)
	if _, err := server.PublicKeyCallback(testConnMetadata{user: "bounded"}, oversizedPublicKey{}); !errors.Is(err, errInputCap) {
		t.Fatalf("oversized public key error = %v", err)
	}
	if !state.publicKeyTruncated || state.publicKeyBytes != maxPublicKeyBytes {
		t.Fatalf("oversized public key metadata = %+v", state)
	}
}

func TestSSHServerConfigExcludesInsecureAlgorithmsAndCapabilities(t *testing.T) {
	s, err := New(sensorConfig(testConfig("ssh-algorithms")))
	if err != nil {
		t.Fatal(err)
	}
	server := s.serverConfig(&connectionState{})
	if server.NoClientAuth || server.KeyboardInteractiveCallback != nil || server.GSSAPIWithMICConfig != nil {
		t.Fatal("unsupported authentication capability enabled")
	}
	if server.MaxAuthTries != 3 {
		t.Fatalf("MaxAuthTries = %d, want 3", server.MaxAuthTries)
	}
	insecure := ssh.InsecureAlgorithms()
	for _, tc := range []struct {
		name string
		got  []string
		bad  []string
	}{
		{name: "key exchange", got: server.KeyExchanges, bad: insecure.KeyExchanges},
		{name: "cipher", got: server.Ciphers, bad: insecure.Ciphers},
		{name: "MAC", got: server.MACs, bad: insecure.MACs},
		{name: "public-key auth", got: server.PublicKeyAuthAlgorithms, bad: insecure.PublicKeyAuths},
	} {
		for _, algorithm := range tc.got {
			if slices.Contains(tc.bad, algorithm) {
				t.Fatalf("%s enables insecure algorithm %q", tc.name, algorithm)
			}
		}
	}
}

func TestSSHSensorSyntheticPublicKeyAuthentication(t *testing.T) {
	s, sink, _ := startTestSensor(t, testConfig("ssh-publickey"))
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	client, err := ssh.Dial("tcp", s.Addr(), &ssh.ClientConfig{
		User:            "key-user",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // test-only ephemeral host key
		Timeout:         2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()

	obs := decodeObservation(t, sink.waitFor(t, 1)[0])
	if !obs.Authenticated || obs.AuthMethod != "publickey" {
		t.Fatalf("public-key authentication metadata = %+v", obs)
	}
	if obs.PublicKeyType != ssh.KeyAlgoED25519 || obs.PublicKeyBytes == 0 || obs.PublicKeyTruncated {
		t.Fatalf("public-key metadata = %+v", obs)
	}
	raw := string(sink.snapshot()[0].Observation)
	for _, forbidden := range []string{"key-user", string(ssh.MarshalAuthorizedKey(signer.PublicKey()))} {
		if strings.Contains(raw, strings.TrimSpace(forbidden)) {
			t.Fatalf("public-key credential content leaked into event: %q", raw)
		}
	}
}

func TestSSHSensorRejectsInvalidPublicKeyProof(t *testing.T) {
	s, sink, _ := startTestSensor(t, testConfig("ssh-invalid-publickey-proof"))
	_, advertisedPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	advertised, err := ssh.NewSignerFromKey(advertisedPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := ssh.NewSignerFromKey(signingPrivate)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ssh.Dial("tcp", s.Addr(), &ssh.ClientConfig{
		User:            "invalid-proof-user",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(mismatchedSigner{advertised: advertised.PublicKey(), actual: actual})},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // test-only ephemeral host key
		Timeout:         2 * time.Second,
	})
	if err == nil {
		t.Fatal("public key with an invalid signature authenticated")
	}
	obs := decodeObservation(t, sink.waitFor(t, 1)[0])
	if obs.Authenticated || obs.AuthMethod != "" || obs.Outcome == outcomeAuthenticated || obs.AuthFailures == 0 {
		t.Fatalf("invalid public-key proof outcome = %+v", obs)
	}
	if strings.Contains(string(sink.snapshot()[0].Observation), "invalid-proof-user") {
		t.Fatal("username content leaked into invalid-proof event")
	}
}

func TestSSHSensorRejectsUnsupportedAuthenticationMethods(t *testing.T) {
	tests := []struct {
		name string
		auth []ssh.AuthMethod
	}{
		{name: "none"},
		{name: "keyboard interactive", auth: []ssh.AuthMethod{ssh.KeyboardInteractive(func(string, string, []string, []bool) ([]string, error) {
			return []string{"synthetic-answer"}, nil
		})}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, sink, _ := startTestSensor(t, testConfig("ssh-unsupported-"+strings.ReplaceAll(tt.name, " ", "-")))
			_, err := ssh.Dial("tcp", s.Addr(), &ssh.ClientConfig{
				User:            "unsupported-user",
				Auth:            tt.auth,
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         2 * time.Second,
			})
			if err == nil {
				t.Fatal("unsupported authentication method succeeded")
			}
			obs := decodeObservation(t, sink.waitFor(t, 1)[0])
			if obs.Authenticated || obs.Outcome != outcomeAuthenticationFailed {
				t.Fatalf("unsupported authentication outcome = %+v", obs)
			}
			if strings.Contains(string(sink.snapshot()[0].Observation), "unsupported-user") {
				t.Fatal("username content leaked into event")
			}
		})
	}
}

func TestSSHSensorHostKeyIsEphemeralPerSensor(t *testing.T) {
	cfg := sensorConfig(testConfig("ssh-host-key"))
	first, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	firstKey := first.signer.PublicKey().Marshal()
	if !bytes.Equal(firstKey, first.signer.PublicKey().Marshal()) {
		t.Fatal("host key changed within one sensor")
	}
	if bytes.Equal(firstKey, second.signer.PublicKey().Marshal()) {
		t.Fatal("independent sensors must not share an in-memory host key")
	}
}

func TestSSHSensorRejectsOversizedPassword(t *testing.T) {
	s, sink, _ := startTestSensor(t, testConfig("ssh-password-cap"))
	password := strings.Repeat("P", maxPasswordBytes+1)
	_, err := ssh.Dial("tcp", s.Addr(), &ssh.ClientConfig{
		User:            "oversized-user",
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	})
	if err == nil {
		t.Fatal("oversized password must not authenticate")
	}
	obs := decodeObservation(t, sink.waitFor(t, 1)[0])
	if obs.Authenticated || obs.Outcome != outcomeAuthenticationFailed {
		t.Fatalf("oversized password outcome = %+v", obs)
	}
	if !obs.PasswordTruncated || obs.PasswordBytes != maxPasswordBytes {
		t.Fatalf("oversized password metadata = %+v", obs)
	}
	if strings.Contains(string(sink.snapshot()[0].Observation), password) {
		t.Fatal("oversized password leaked into event")
	}
}

func TestSSHSensorCloseReleasesIdleHandshake(t *testing.T) {
	s, sink, _ := startTestSensor(t, testConfig("ssh-close"))
	conn, err := net.DialTimeout("tcp", s.Addr(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("SSH-2.0-test\r\n")); err != nil {
		t.Fatal(err)
	}
	// Let the accept loop admit the connection before exercising shutdown.
	time.Sleep(20 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_ = conn.Close()
	select {
	case <-s.Done():
	default:
		t.Fatal("Done must be closed after Close")
	}
	obs := decodeObservation(t, sink.waitFor(t, 1)[0])
	if obs.Outcome != outcomeShutdown {
		t.Fatalf("idle handshake outcome = %+v", obs)
	}
}

func TestSSHSensorHandshakeAndSessionDeadlines(t *testing.T) {
	t.Run("handshake", func(t *testing.T) {
		cfg := testConfig("ssh-handshake-timeout")
		cfg.HandshakeTimeout = time.Second
		s, sink, _ := startTestSensor(t, cfg)
		conn, err := net.DialTimeout("tcp", s.Addr(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		obs := decodeObservation(t, sink.waitFor(t, 1)[0])
		if obs.Outcome != outcomeHandshakeTimeout || obs.Authenticated {
			t.Fatalf("handshake deadline outcome = %+v", obs)
		}
	})

	t.Run("session", func(t *testing.T) {
		cfg := testConfig("ssh-session-timeout")
		cfg.SessionTimeout = time.Second
		s, sink, _ := startTestSensor(t, cfg)
		client := passwordClient(t, s.Addr(), "bounded-password")
		obs := decodeObservation(t, sink.waitFor(t, 1)[0])
		if obs.Outcome != outcomeSessionTimeout || !obs.Authenticated {
			t.Fatalf("session deadline outcome = %+v", obs)
		}
		_ = client.Close()
	})
}

func TestSSHSensorClosesConnectionsAboveCap(t *testing.T) {
	cfg := testConfig("ssh-connection-cap")
	cfg.HandshakeTimeout = 30 * time.Second
	cfg.SessionTimeout = 30 * time.Second
	s, _, _ := startTestSensor(t, cfg)

	connections := make([]net.Conn, 0, maxConcurrentSessions)
	defer func() {
		for _, conn := range connections {
			_ = conn.Close()
		}
	}()
	for i := 0; i < maxConcurrentSessions; i++ {
		conn, err := net.DialTimeout("tcp", s.Addr(), 2*time.Second)
		if err != nil {
			t.Fatalf("dial admitted connection %d: %v", i, err)
		}
		if _, err := conn.Write([]byte("SSH-2.0-cap-test\r\n")); err != nil {
			conn.Close()
			t.Fatalf("write admitted connection %d: %v", i, err)
		}
		connections = append(connections, conn)
	}
	waitForActiveConnections(t, s, maxConcurrentSessions)

	excess, err := net.DialTimeout("tcp", s.Addr(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer excess.Close()
	if err := excess.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	if _, err := excess.Read(one[:]); err == nil {
		t.Fatal("connection above the cap remained open")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("connection above the cap was not closed promptly")
	}
}

func TestSSHSensorCannotStartAfterClose(t *testing.T) {
	cfg := testConfig("ssh-closed")
	s, err := New(sensorConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	sink := newCollectingSink()
	bus := event.NewBus(1, sink, quietLogger())
	defer bus.Close()
	deps := sensor.Deps{
		Config: sensorConfig(cfg), Bus: bus, Meter: observe.NewRegistry(), Log: quietLogger(),
		Seq: &event.Sequencer{}, Instance: "ssh-test",
	}
	if err := s.Start(context.Background(), deps); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("Start after Close error = %v", err)
	}
}

func TestSSHSensorCloseDuringStartDoesNotPublishListener(t *testing.T) {
	cfg := testConfig("ssh-start-close-race")
	s, err := New(sensorConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	listenEntered := make(chan struct{})
	releaseListen := make(chan struct{})
	s.listen = func(string, string) (net.Listener, error) {
		close(listenEntered)
		<-releaseListen
		return ln, nil
	}

	bus := event.NewBus(1, newCollectingSink(), quietLogger())
	defer bus.Close()
	deps := sensor.Deps{
		Config: sensorConfig(cfg), Bus: bus, Meter: observe.NewRegistry(), Log: quietLogger(),
		Seq: &event.Sequencer{}, Instance: "ssh-test",
	}
	startDone := make(chan error, 1)
	go func() { startDone <- s.Start(context.Background(), deps) }()
	<-listenEntered
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(releaseListen)
	if err := <-startDone; err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("Start racing Close error = %v", err)
	}
	if got := s.Addr(); got != "" {
		t.Fatalf("listener published after Close: %s", got)
	}
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 100*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Fatal("listener remained reachable after Close won startup race")
	}
}

func TestSSHSensorCloseTimeoutDoesNotSignalTerminalCompletion(t *testing.T) {
	s, err := New(sensorConfig(testConfig("ssh-close-timeout")))
	if err != nil {
		t.Fatal(err)
	}
	acceptDone := make(chan struct{})
	s.acceptDone = acceptDone

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := s.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close error = %v, want deadline exceeded", err)
	}
	select {
	case <-s.Done():
		t.Fatal("Done signaled before the shutdown drain completed")
	default:
	}
	close(acceptDone)
	select {
	case <-s.Done():
	case <-time.After(time.Second):
		t.Fatal("Done did not signal after the shutdown drain completed")
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func waitForActiveConnections(t *testing.T, s *Sensor, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		got := len(s.conns)
		s.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	s.mu.Lock()
	got := len(s.conns)
	s.mu.Unlock()
	t.Fatalf("active SSH connections = %d, want %d", got, want)
}

func TestSSHSensorConfigCaps(t *testing.T) {
	tests := []struct {
		name string
		cfg  settings
	}{
		{name: "empty id", cfg: settings{}},
		{name: "bad version", cfg: settings{ID: "bad", Listen: "127.0.0.1:0", ServerVersion: "not-ssh", HandshakeTimeout: time.Second, SessionTimeout: time.Second, MaxAuthTries: 1}},
		{name: "long version", cfg: settings{ID: "long", Listen: "127.0.0.1:0", ServerVersion: "SSH-2.0-" + strings.Repeat("v", config.MaxSSHServerVersionBytes), HandshakeTimeout: time.Second, SessionTimeout: time.Second, MaxAuthTries: 1}},
		{name: "negative handshake", cfg: settings{ID: "negative-handshake", Listen: "127.0.0.1:0", ServerVersion: "SSH-2.0-test", HandshakeTimeout: -time.Second, SessionTimeout: time.Second, MaxAuthTries: 1}},
		{name: "long handshake", cfg: settings{ID: "long-handshake", Listen: "127.0.0.1:0", ServerVersion: "SSH-2.0-test", HandshakeTimeout: (config.MaxSSHHandshakeTimeoutSeconds + 1) * time.Second, SessionTimeout: time.Second, MaxAuthTries: 1}},
		{name: "negative session", cfg: settings{ID: "negative-session", Listen: "127.0.0.1:0", ServerVersion: "SSH-2.0-test", HandshakeTimeout: time.Second, SessionTimeout: -time.Second, MaxAuthTries: 1}},
		{name: "long session", cfg: settings{ID: "long-session", Listen: "127.0.0.1:0", ServerVersion: "SSH-2.0-test", HandshakeTimeout: time.Second, SessionTimeout: (config.MaxSSHSessionSeconds + 1) * time.Second, MaxAuthTries: 1}},
		{name: "zero auth tries is rejected", cfg: settings{ID: "default-auth", Listen: "127.0.0.1:0", ServerVersion: "SSH-2.0-test", HandshakeTimeout: time.Second, SessionTimeout: time.Second}},
		{name: "too many auth tries", cfg: settings{ID: "too-many-auth", Listen: "127.0.0.1:0", ServerVersion: "SSH-2.0-test", HandshakeTimeout: time.Second, SessionTimeout: time.Second, MaxAuthTries: maxAuthTries + 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(sensorConfig(tt.cfg))
			if err == nil {
				t.Fatal("expected config error")
			}
		})
	}
}

type testConnMetadata struct{ user string }

func (m testConnMetadata) User() string        { return m.user }
func (testConnMetadata) SessionID() []byte     { return nil }
func (testConnMetadata) ClientVersion() []byte { return nil }
func (testConnMetadata) ServerVersion() []byte { return nil }
func (testConnMetadata) RemoteAddr() net.Addr  { return nil }
func (testConnMetadata) LocalAddr() net.Addr   { return nil }

type oversizedPublicKey struct{}

func (oversizedPublicKey) Type() string { return ssh.KeyAlgoED25519 }
func (oversizedPublicKey) Marshal() []byte {
	return make([]byte, maxPublicKeyBytes+1)
}
func (oversizedPublicKey) Verify([]byte, *ssh.Signature) error { return nil }

type mismatchedSigner struct {
	advertised ssh.PublicKey
	actual     ssh.Signer
}

func (s mismatchedSigner) PublicKey() ssh.PublicKey { return s.advertised }
func (s mismatchedSigner) Sign(random io.Reader, data []byte) (*ssh.Signature, error) {
	return s.actual.Sign(random, data)
}
func (s mismatchedSigner) SignWithAlgorithm(random io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	algorithmSigner, ok := s.actual.(ssh.AlgorithmSigner)
	if !ok {
		return nil, errors.New("actual signer does not support algorithm selection")
	}
	return algorithmSigner.SignWithAlgorithm(random, data, algorithm)
}

func FuzzSSHMetadataHelpers(f *testing.F) {
	f.Add([]byte("SSH-2.0-OpenSSH_9.9"), "password")
	f.Add([]byte{0xff, 0x00, '\n'}, "unknown-method")
	f.Fuzz(func(t *testing.T, version []byte, method string) {
		preview, _ := boundedPreview(version, maxClientVersion)
		if len(preview) > maxClientVersion*4 {
			t.Fatalf("escaped preview grew without bound: %d", len(preview))
		}
		got := canonicalAuthMethod(method)
		switch got {
		case "none", "password", "publickey", "keyboard-interactive", "gssapi-with-mic", "other":
		default:
			t.Fatalf("unbounded auth method %q", got)
		}
	})
}
