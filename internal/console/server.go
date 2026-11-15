package console

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console/audit"
	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/console/investigations"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/observe"
)

// CSP restricts UI resources and API connections to this console's origin.
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// CookieName is the host-only operator session cookie name.
const CookieName = "aegismesh_session"

// Options supplies trusted configuration, value snapshots, and bounded UI assets.
type Options struct {
	// Security supplies the validated exposure policy for this listener.
	Security config.Security
	// Config supplies console addresses, session bounds, and operator digests.
	Config config.Console
	// StateDir is the trusted directory for console-owned annotation and audit files.
	StateDir string
	// Index supplies disposable projections of successfully stored evidence.
	Index *evidenceindex.Index
	// Runtime supplies value snapshots without sensor control capabilities.
	Runtime Runtime
	// Rules supplies catalog metadata with effective runtime enablement.
	Rules []Rule
	// Meter receives bounded console counters and gauges.
	Meter observe.Meter
	// UI supplies build-owned assets; nil serves the API notice at the root.
	UI fs.FS
	// Now supplies a trusted clock for session expiry and login throttling; nil uses time.Now.
	Now func() time.Time
}

type asset struct {
	body        []byte
	contentType string
	cache       string
}

// Server owns the console listener, ephemeral authentication, and operator state.
type Server struct {
	assets     map[string]asset
	cfg        config.Console
	index      *evidenceindex.Index
	runtime    Runtime
	rules      []Rule
	ui         fs.FS
	auth       *auth.Manager
	audit      *audit.Log
	cases      *investigations.Store
	httpServer *http.Server
	listener   net.Listener
	mux        *http.ServeMux
	done       chan struct{}
	wg         sync.WaitGroup
	once       sync.Once
	startOnce  sync.Once
	requests   observe.LabeledCounter
	failures   observe.Counter
	clients    observe.Gauge
	slots      chan struct{}
	streams    chan struct{}
	key        [32]byte
}

// New validates dependencies and opens the dedicated console listener without starting it.
func New(opts Options) (_ *Server, err error) {
	if err := (&config.Config{
		Console:  opts.Config,
		Security: opts.Security,
	}).ValidateConsole(); err != nil {
		return nil, err
	}

	if opts.Index == nil || opts.Runtime == nil || opts.Meter == nil {
		return nil, errors.New("console: index, runtime and meter are required")
	}

	sessions, err := auth.NewWithClock(
		opts.Config.Operators,
		time.Duration(opts.Config.SessionTTLSeconds)*time.Second,
		opts.Now,
	)
	if err != nil {
		return nil, err
	}

	server := &Server{
		cfg:     opts.Config,
		index:   opts.Index,
		runtime: opts.Runtime,
		rules:   append([]Rule{}, opts.Rules...),
		ui:      opts.UI,
		auth:    sessions,
		done:    make(chan struct{}),
		mux:     http.NewServeMux(),
		slots:   make(chan struct{}, 8),
		streams: make(chan struct{}, 16),
		requests: opts.Meter.CounterVec(
			"aegismesh_console_requests_total", "Console requests by fixed endpoint group", 32,
		),
		failures: opts.Meter.Counter("aegismesh_console_auth_failures_total", "Console authentication failures"),
		clients:  opts.Meter.Gauge("aegismesh_console_sse_clients", "Active console SSE clients"),
	}

	// Construction owns every opened resource until the complete server is returned.
	defer func() {
		if err != nil {
			server.closeResources()
		}
	}()
	if err = server.openState(opts.StateDir); err != nil {
		return nil, err
	}

	if _, err = rand.Read(server.key[:]); err != nil {
		return nil, err
	}

	if server.listener, err = listen(opts.Config); err != nil {
		return nil, err
	}

	if err = server.loadAssets(); err != nil {
		return nil, err
	}

	server.routes()
	server.httpServer = &http.Server{
		Handler:           server,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	return server, nil
}

func (s *Server) openState(dir string) error {
	auditLog, err := audit.New(dir)
	if err != nil {
		return fmt.Errorf("console audit: %w", err)
	}

	s.audit = auditLog
	cases, err := investigations.New(dir)
	if err != nil {
		return fmt.Errorf("console investigations: %w", err)
	}

	s.cases = cases
	return nil
}

func listen(cfg config.Console) (net.Listener, error) {
	var tlsConfig *tls.Config
	if cfg.TLSCertFile != "" {
		certificate, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, errors.New("console: load TLS certificate and key failed")
		}
		tlsConfig = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{certificate},
		}
	}

	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("console: bind: %w", err)
	}

	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}

	return listener, nil
}

func (s *Server) closeResources() {
	if s.listener != nil {
		_ = s.listener.Close()
	}

	if s.cases != nil {
		_ = s.cases.Close()
	}

	if s.audit != nil {
		_ = s.audit.Close()
	}
}

// Addr returns the actual bound console authority, including an assigned port.
func (s *Server) Addr() string {
	return s.listener.Addr().String()
}

// Start serves requests in the background once.
func (s *Server) Start() {
	s.startOnce.Do(func() {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			_ = s.httpServer.Serve(s.listener)
		}()
	})
}

// Close ends streams, drains handlers, and releases the listener and state files.
func (s *Server) Close(ctx context.Context) error {
	var err error
	s.once.Do(func() {
		close(s.done)
		err = s.httpServer.Shutdown(ctx)
		_ = s.httpServer.Close()
		_ = s.listener.Close()
		s.wg.Wait()
		_ = s.cases.Close()
		_ = s.audit.Close()
	})
	return err
}
