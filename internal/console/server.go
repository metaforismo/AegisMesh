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
	"path/filepath"
	"sync"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console/audit"
	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/console/investigations"
	"github.com/metaforismo/aegismesh/internal/console/oidc"
	"github.com/metaforismo/aegismesh/internal/console/tenant"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/fleet/hub"
	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
	"github.com/metaforismo/aegismesh/internal/observe"
)

// CSP restricts UI resources and API connections to this console's origin.
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// CookieName is the host-only operator session cookie name.
const CookieName = "aegismesh_session"

// Options supplies trusted configuration, value snapshots, and bounded UI assets.
type Options struct {
	// TenantIndexes supplies runtime-owned indexes for declared remote partitions.
	TenantIndexes map[string]*evidenceindex.Index
	// OIDCSecret resolves a private reference without persisting its contents.
	OIDCSecret func() (string, error)
	// OIDCTransport is a test-only HTTP seam; production uses guarded direct sockets.
	OIDCTransport http.RoundTripper
	// FleetHub provides inventory administration only, without agent control.
	FleetHub *hub.Hub
	// FleetStatus snapshots local role and delivery state.
	FleetStatus func() protocol.Status
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
	gzip        []byte
	etag        string
	gzipETag    string
	body        []byte
	contentType string
	cache       string
}

// Server owns the console listener, ephemeral authentication, and operator state.
type Server struct {
	unassignedAudit *audit.Log
	tenantID        string
	views           map[string]*Server
	oidc            *oidc.Manager
	oidcCancel      context.CancelFunc
	fleetHub        *hub.Hub
	fleetStatus     func() protocol.Status
	assets          map[string]asset
	cfg             config.Console
	index           *evidenceindex.Index
	runtime         Runtime
	rules           []Rule
	ui              fs.FS
	auth            *auth.Manager
	audit           *audit.Log
	cases           *investigations.Store
	httpServer      *http.Server
	listener        net.Listener
	mux             *http.ServeMux
	done            chan struct{}
	wg              sync.WaitGroup
	once            sync.Once
	startOnce       sync.Once
	requests        observe.LabeledCounter
	failures        observe.Counter
	clients         observe.Gauge
	slots           chan struct{}
	streams         chan struct{}
	key             [32]byte
}

// New validates dependencies and opens the dedicated console listener without starting it.
func New(opts Options) (_ *Server, err error) {
	opts.Config = opts.Config.WithDefaults()
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
		cfg:         opts.Config,
		fleetHub:    opts.FleetHub,
		fleetStatus: opts.FleetStatus,
		index:       opts.Index,
		runtime:     opts.Runtime,
		rules:       append([]Rule{}, opts.Rules...),
		ui:          opts.UI,
		auth:        sessions,
		done:        make(chan struct{}),
		mux:         http.NewServeMux(),
		slots:       make(chan struct{}, 8),
		streams:     make(chan struct{}, 16),
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
	paths, err := tenant.Prepare(opts.StateDir, opts.Config.Tenants)
	if err != nil {
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

	if opts.Config.OIDC.Enabled {
		secret := ""
		if opts.OIDCSecret != nil {
			secret, err = opts.OIDCSecret()
			if err != nil {
				return nil, err
			}
		} else if opts.Config.OIDC.ClientSecretEnv != "" || opts.Config.OIDC.ClientSecretFile != "" {
			return nil, errors.New("console: OIDC secret resolver required")
		}
		server.oidc, err = oidc.New(oidc.Options{
			Config: opts.Config.OIDC, Tenants: opts.Config.Tenants, Secret: secret,
			Now: opts.Now, Transport: opts.OIDCTransport,
		})
		if err != nil {
			return nil, err
		}
		request, _ := http.NewRequest("GET", opts.Config.OIDC.RedirectURI, nil)
		if request == nil || !server.validHost(request.URL.Host) {
			return nil, errors.New("console: OIDC redirect_uri must match the console listener")
		}
	}
	if len(opts.Config.Tenants) > 1 {
		server.unassignedAudit, err = audit.New(filepath.Join(opts.StateDir, "authentication"))
		if err != nil {
			return nil, err
		}
	}
	server.views = map[string]*Server{}
	for _, name := range opts.Config.Tenants {
		view, err := server.scopedServer(name, opts, paths[name])
		if err != nil {
			return nil, err
		}
		server.views[name] = view
	}
	local := server.views[opts.Config.LocalTenant]
	server.audit, server.cases = local.audit, local.cases
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
	var cases *investigations.Store
	if len(s.cfg.Tenants) > 1 {
		cases, err = investigations.NewScoped(dir, s.index)
	} else {
		cases, err = investigations.New(dir)
	}
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

	for _, view := range s.views {
		view.closeState()
	}
	if s.unassignedAudit != nil {
		_ = s.unassignedAudit.Close()
	}

}

// Addr returns the actual bound console authority, including an assigned port.
func (s *Server) Addr() string {
	return s.listener.Addr().String()
}

// Start serves requests in the background once.
func (s *Server) Start() {
	s.startOnce.Do(func() {
		if s.oidc != nil {
			ctx, cancel := context.WithCancel(context.Background())
			s.oidcCancel = cancel
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.oidc.Run(ctx)
			}()
		}
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
		if s.oidcCancel != nil {
			s.oidcCancel()
		}
		err = s.httpServer.Shutdown(ctx)
		_ = s.httpServer.Close()
		_ = s.listener.Close()
		s.wg.Wait()
		for _, view := range s.views {
			view.closeState()
		}
		if s.unassignedAudit != nil {
			_ = s.unassignedAudit.Close()
		}
	})
	return err
}
