package console

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console/accounts"
	"github.com/metaforismo/aegismesh/internal/console/audit"
	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/console/investigations"
	"github.com/metaforismo/aegismesh/internal/console/notifications"
	"github.com/metaforismo/aegismesh/internal/console/oidc"
	"github.com/metaforismo/aegismesh/internal/console/settings"
	"github.com/metaforismo/aegismesh/internal/console/tenant"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/fleet/hub"
	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/posture"
)

// CSP restricts UI resources and API connections to this console's origin.
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// CookieName is the host-only operator session cookie name.
const CookieName = "aegismesh_session"

// Options supplies trusted configuration, value snapshots, and bounded UI assets.
type Options struct {
	// Posture supplies the secret-free configuration snapshot for posture review;
	// nil limits the review to evidence-only checks.
	Posture *posture.Facts
	// Decoys supplies safe configured surface metadata, without response bodies.
	Decoys []Decoy
	// Honeytokens supplies configured marker identifiers and planting, never values.
	Honeytokens []Honeytoken
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
	// Sources reports where configuration values came from (config.Config.Sources);
	// nil reports explicitly supplied values as "config".
	Sources map[string]string
	// Logger receives startup warnings such as ignored settings overrides; nil discards them.
	Logger *slog.Logger
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
	decoyCatalog    []Decoy
	tokenCatalog    []Honeytoken
	postureFacts    *posture.Facts
	unassignedAudit *audit.Log
	tenantID        string
	instanceID      string
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
	inbox           *notifications.Store
	derive          *deriver
	inboxStreams    chan struct{}
	accounts        *accounts.Store
	overlay         *settings.Store
	live            *liveSettings
	log             *slog.Logger
	security        config.Security
	settingSources  map[string]string
	startedAt       time.Time
	certExpiry      time.Time
	now             func() time.Time
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
	memo            analysisMemo
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
	if err = sessions.SetIdleTimeout(time.Duration(opts.Config.IdleSeconds()) * time.Second); err != nil {
		return nil, err
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	server := &Server{
		decoyCatalog:   append([]Decoy{}, opts.Decoys...),
		tokenCatalog:   append([]Honeytoken{}, opts.Honeytokens...),
		postureFacts:   opts.Posture,
		cfg:            opts.Config,
		instanceID:     opts.StateDir,
		fleetHub:       opts.FleetHub,
		fleetStatus:    opts.FleetStatus,
		index:          opts.Index,
		runtime:        opts.Runtime,
		rules:          append([]Rule{}, opts.Rules...),
		ui:             opts.UI,
		auth:           sessions,
		security:       opts.Security,
		settingSources: opts.Sources,
		startedAt:      now().UTC(),
		now:            now,
		done:           make(chan struct{}),
		mux:            http.NewServeMux(),
		slots:          make(chan struct{}, 8),
		streams:        make(chan struct{}, 16),
		inboxStreams:   make(chan struct{}, 16),
		requests: opts.Meter.CounterVec(
			"aegismesh_console_requests_total", "Console requests by fixed endpoint group", 40,
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

	reserved := []string{}
	for _, operator := range opts.Config.Operators {
		reserved = append(reserved, operator.Name)
	}
	// Fixed directory name under the trusted state root; never request-selected.
	server.accounts, err = accounts.Open(filepath.Join(opts.StateDir, "accounts"), accounts.Options{
		Tenants: opts.Config.Tenants, LocalTenant: opts.Config.LocalTenant, Reserved: reserved, Now: opts.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("console accounts: %w", err)
	}
	sessions.SetRegistry(server.accounts)

	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	server.log = logger
	// Fixed directory name under the trusted state root; never request-selected.
	server.overlay, err = settings.Open(filepath.Join(opts.StateDir, "settings"), opts.Now)
	if err != nil {
		return nil, fmt.Errorf("console settings: %w", err)
	}
	server.live = &liveSettings{}
	if err = server.applySettings(true); err != nil {
		return nil, err
	}

	if server.listener, server.certExpiry, err = listen(opts.Config); err != nil {
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
	inbox, err := notifications.Open(dir)
	if err != nil {
		return fmt.Errorf("console notifications: %w", err)
	}
	s.inbox = inbox
	s.newDeriver()
	return nil
}

func listen(cfg config.Console) (net.Listener, time.Time, error) {
	var tlsConfig *tls.Config
	var expiry time.Time
	if cfg.TLSCertFile != "" {
		certificate, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, time.Time{}, errors.New("console: load TLS certificate and key failed")
		}
		if len(certificate.Certificate) > 0 {
			if leaf, err := x509.ParseCertificate(certificate.Certificate[0]); err == nil {
				expiry = leaf.NotAfter.UTC()
			}
		}
		tlsConfig = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{certificate},
		}
	}

	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("console: bind: %w", err)
	}

	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}

	return listener, expiry, nil
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
	if s.accounts != nil {
		_ = s.accounts.Close()
	}
	if s.overlay != nil {
		_ = s.overlay.Close()
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
		// One notification deriver per tenant view, stopped by Close.
		for _, view := range s.views {
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				view.runDeriver()
			}()
		}
		// last_used_at updates are kept in memory and persisted at most once a minute.
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			ticker := time.NewTicker(accounts.LastUsedResolution)
			defer ticker.Stop()
			for {
				select {
				case <-s.done:
					return
				case <-ticker.C:
					_ = s.accounts.Flush()
				}
			}
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
		if s.accounts != nil {
			_ = s.accounts.Close()
		}
		if s.overlay != nil {
			_ = s.overlay.Close()
		}
	})
	return err
}
