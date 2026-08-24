// Package runtime wires config into a running system: sensors, evidence bus,
// store, retention loop, and admin listener, with graceful shutdown.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metaforismo/aegismesh/internal/admin"
	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/ext"
	"github.com/metaforismo/aegismesh/internal/extmanager"
	"github.com/metaforismo/aegismesh/internal/llm"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/policy"
	"github.com/metaforismo/aegismesh/internal/sensor"
	"github.com/metaforismo/aegismesh/internal/sensor/httpsensor"
	"github.com/metaforismo/aegismesh/internal/sensor/mcpsensor"
	"github.com/metaforismo/aegismesh/internal/sensor/sshsensor"
	"github.com/metaforismo/aegismesh/internal/sensor/tcpsensor"
	"github.com/metaforismo/aegismesh/internal/storage"
	"github.com/metaforismo/aegismesh/internal/webhook"
)

const (
	busCapacity    = 4096
	retentionEvery = 10 * time.Minute
	flushEvery     = 5 * time.Second
	shutdownGrace  = 8 * time.Second
	startTimeout   = 15 * time.Second
)

var errRuntime = errors.New("runtime")

// System is a fully wired but not-yet-started AegisMesh instance.
type System struct {
	cfg       *config.Config
	store     *storage.Store
	bus       *event.Bus
	meter     observe.Meter
	seq       *event.Sequencer
	adminSrv  *admin.Server
	sensors   []sensor.Sensor
	extMgr    *extmanager.Manager
	hook      *webhook.Sink
	corr      *correlateAdapter
	log       *slog.Logger
	started   atomic.Uint64
	failed    atomic.Uint64
	stopMaint chan struct{}
	maintOnce sync.Once
	stopOnce  sync.Once
}

// evidenceSink keeps evidence authoritative while offering every envelope to
// optional best-effort consumers (observer extensions, webhook stream). Both
// offers never block and their drops are counted on their own metrics, so the
// store path can neither be slowed nor failed by them.
type evidenceSink struct {
	primary event.Sink
	mgr     *extmanager.Manager // may be nil
	hook    *webhook.Sink       // may be nil
	corr    *correlateAdapter   // may be nil
}

func (s evidenceSink) Append(ctx context.Context, e event.Envelope) error {
	err := s.primary.Append(ctx, e)
	if s.mgr != nil {
		s.mgr.Deliver(e)
	}
	if s.hook != nil {
		s.hook.Offer(e)
	}
	if s.corr != nil {
		s.corr.observe(e)
	}
	return err
}

// Build validates and constructs everything. No listener is bound yet.
func Build(cfg *config.Config, log *slog.Logger) (*System, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: nil config", errRuntime)
	}
	if log == nil {
		log = slog.Default()
	}

	reg := observe.NewRegistry()
	storeOpts := storage.Options{
		Dir:          cfg.Runtime.DataDir,
		MaxFileBytes: cfg.Storage.MaxFileBytes,
		MaxEvents:    cfg.Storage.Retention.MaxEvents,
		MaxAgeDays:   cfg.Storage.Retention.MaxAgeDays,
	}
	store, err := storage.New(storeOpts)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errRuntime, err)
	}

	prov, err := providerFor(*cfg)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("%w: %v", errRuntime, err)
	}

	enf := policy.NewEnforcer(cfg.Detection, reg)

	sys := &System{
		cfg:       cfg,
		store:     store,
		meter:     reg,
		seq:       &event.Sequencer{},
		log:       log,
		stopMaint: make(chan struct{}),
	}

	if cfg.Extensions.IsEnabled() {
		manifests, err := loadObserverManifests(cfg.Extensions)
		if err != nil {
			sys.closeAll()
			return nil, fmt.Errorf("%w: %v", errRuntime, err)
		}
		sys.extMgr = extmanager.New(manifests, reg, log,
			cfg.Extensions.QueueSize,
			time.Duration(cfg.Extensions.ShutdownFlushSeconds)*time.Second)
	}

	if cfg.Webhook.IsEnabled() {
		secret, err := cfg.ResolveWebhookSecret()
		if err != nil {
			sys.closeAll()
			return nil, fmt.Errorf("%w: %v", errRuntime, err)
		}
		u, err := url.Parse(strings.TrimSpace(cfg.Webhook.URL))
		if err != nil {
			sys.closeAll()
			return nil, fmt.Errorf("%w: webhook.url: %v", errRuntime, err)
		}
		hook, err := webhook.New(webhook.Config{
			Endpoint:          u,
			AllowLoopbackHTTP: cfg.Webhook.AllowLoopbackHTTP,
			AllowPrivate:      cfg.Security.AllowPrivateLLMEgress,
			Secret:            []byte(secret),
			QueueSize:         cfg.Webhook.QueueSize,
			BatchSize:         cfg.Webhook.BatchSize,
			FlushInterval:     time.Duration(cfg.Webhook.FlushIntervalSeconds) * time.Second,
			Timeout:           time.Duration(cfg.Webhook.TimeoutSeconds) * time.Second,
			MaxRetries:        cfg.Webhook.MaxRetries,
			ShutdownFlush:     3 * time.Second,
		}, reg, log)
		if err != nil {
			sys.closeAll()
			return nil, fmt.Errorf("%w: %v", errRuntime, err)
		}
		sys.hook = hook
	}

	if cfg.Correlation.IsEnabled() {
		sys.corr = newCorrelateAdapter(correlateOptions{
			WindowSeconds:   cfg.Correlation.WindowSeconds,
			PerSourceEvents: cfg.Correlation.PerSourceEvents,
			MaxSources:      cfg.Correlation.MaxSources,
			DisabledRules:   cfg.Correlation.DisabledRules,
		}, correlateDeps{
			seq:      sys.seq,
			instance: cfg.Runtime.InstanceName,
			store:    store,
		}, reg, log)
	}

	sink := event.Sink(store)
	if sys.extMgr != nil || sys.hook != nil || sys.corr != nil {
		sink = evidenceSink{primary: store, mgr: sys.extMgr, hook: sys.hook, corr: sys.corr}
	}
	sys.bus = event.NewBus(busCapacity, sink, log)

	for i := range cfg.Sensors {
		s, err := buildSensor(&cfg.Sensors[i], cfg, prov, enf)
		if err != nil {
			sys.closeAll()
			return nil, fmt.Errorf("%w: sensor %q: %v", errRuntime, cfg.Sensors[i].ID, err)
		}
		sys.sensors = append(sys.sensors, s)
	}

	if cfg.Admin.IsEnabled() {
		asrv, err := admin.New(cfg.Admin.Listen, sys.Status, reg, log)
		if err != nil {
			sys.closeAll()
			return nil, fmt.Errorf("%w: %v", errRuntime, err)
		}
		sys.adminSrv = asrv
	}
	return sys, nil
}

// loadObserverManifests loads, verifies, and capability-checks every
// configured extension manifest. Fail-closed: any problem refuses startup.
func loadObserverManifests(c config.Extensions) ([]*ext.Manifest, error) {
	seen := map[string]bool{}
	manifests := make([]*ext.Manifest, 0, len(c.Manifests))
	for _, path := range c.Manifests {
		m, err := ext.LoadManifest(path)
		if err != nil {
			return nil, fmt.Errorf("extension manifest %s: %v", filepath.Base(path), err)
		}
		if seen[m.Name] {
			return nil, fmt.Errorf("extension name %q declared twice (unique names are required for metrics and logs)", m.Name)
		}
		seen[m.Name] = true
		wired := false
		for _, p := range m.Permissions {
			if p == "observe" {
				wired = true
			}
		}
		if !wired {
			return nil, fmt.Errorf("extension %q must declare the observe permission; no other permission is wired into the runtime today", m.Name)
		}
		if _, err := ext.Verify(m, c.Ed25519PubKeyHex); err != nil {
			return nil, fmt.Errorf("extension %q failed verification: %v", m.Name, err)
		}
		manifests = append(manifests, m)
	}
	return manifests, nil
}

// providerFor materializes the configured provider. Remote construction is
// fail-closed: egress policy validation, model presence, and credential
// resolution all happen here, before any listener binds.
func providerFor(c config.Config) (llm.Provider, error) {
	lc := c.LLM
	switch lc.Provider {
	case "", "local":
		return llm.Local{}, nil
	case "ollama", "openai":
		key, err := c.ResolveAPIKey()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errRuntime, err)
		}
		return llm.NewRemote(llm.RemoteConfig{
			Name:             lc.Provider,
			BaseURL:          lc.BaseURL,
			Model:            lc.Model,
			APIKey:           key,
			AllowLoopback:    lc.Provider == "ollama",
			AllowPrivate:     c.Security.AllowPrivateLLMEgress,
			Timeout:          time.Duration(lc.TimeoutSeconds) * time.Second,
			MaxResponseBytes: lc.MaxResponseBytes,
		})
	default:
		return nil, fmt.Errorf("provider %q is not supported; use local|ollama|openai", lc.Provider)
	}
}

func buildSensor(c *config.Sensor, cfg *config.Config, prov llm.Provider, enf *policy.Enforcer) (sensor.Sensor, error) {
	switch c.Kind {
	case config.SensorKindHTTP:
		gate, err := policy.NewHTTPGate(*c, cfg.ResolveBodyFile, prov, enf)
		if err != nil {
			return nil, err
		}
		return httpsensor.New(*c, gate)
	case config.SensorKindTCP:
		gate, err := policy.NewTCPGate(*c, enf)
		if err != nil {
			return nil, err
		}
		return tcpsensor.New(*c, gate)
	case config.SensorKindMCP:
		return mcpsensor.New(*c, enf)
	case config.SensorKindSSH:
		return sshsensor.New(*c)
	default:
		return nil, fmt.Errorf("unknown kind %q", c.Kind)
	}
}

// Start brings up admin, observer extensions, and all sensors. Partial
// failures tear everything down.
func (s *System) Start(ctx context.Context) error {
	if s.adminSrv != nil {
		s.adminSrv.Start()
	}
	if s.extMgr != nil {
		// Extensions start before sensors so early observations flow; a
		// failed extension startup fails the whole start (fail-closed).
		sctx, cancel := context.WithTimeout(ctx, startTimeout)
		err := s.extMgr.Start(sctx)
		cancel()
		if err != nil {
			s.Stop(context.Background())
			return fmt.Errorf("%w: %v", errRuntime, err)
		}
	}
	for _, sen := range s.sensors {
		d := sensor.Deps{
			Config:   *s.sensorCfg(sen.ID()),
			Bus:      s.bus,
			Meter:    s.meter,
			Log:      s.log,
			Seq:      s.seq,
			Instance: s.cfg.Runtime.InstanceName,
		}
		sctx, cancel := context.WithTimeout(ctx, startTimeout)
		err := sen.Start(sctx, d)
		cancel()
		if err != nil {
			s.Stop(context.Background())
			return fmt.Errorf("%w: start sensor %q: %v", errRuntime, sen.ID(), err)
		}
		s.started.Add(1)
	}
	go s.maintenanceLoop()
	return nil
}

func (s *System) sensorCfg(id string) *config.Sensor {
	for i := range s.cfg.Sensors {
		if s.cfg.Sensors[i].ID == id {
			return &s.cfg.Sensors[i]
		}
	}
	return nil // unreachable: sensors are built from this slice
}

// Status reports readiness for the admin endpoints.
func (s *System) Status() admin.Status {
	started := s.started.Load()
	failed := s.failed.Load()
	if failed > started {
		failed = started
	}
	return admin.Status{
		SensorsStarted: int(started - failed),
		SensorsWanted:  len(s.sensors),
		StoreHealthy:   true,
		DroppedEvents:  s.bus.Dropped(),
	}
}

func (s *System) maintenanceLoop() {
	flush := time.NewTicker(flushEvery)
	defer flush.Stop()
	retention := time.NewTicker(retentionEvery)
	defer retention.Stop()
	for {
		select {
		case <-s.stopMaint:
			return
		case <-flush.C:
			if err := s.store.Flush(); err != nil {
				s.log.Warn("evidence flush failed", "err", err)
			}
		case <-retention.C:
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			removed, err := s.store.ApplyRetention(ctx)
			cancel()
			if err != nil {
				s.log.Warn("retention pass failed", "err", err)
			} else if len(removed) > 0 {
				s.log.Info("retention removed segments", "count", len(removed))
			}
		}
	}
}

// Stop shuts down gracefully: stop intake, drain sensors, flush store.
func (s *System) Stop(_ context.Context) {
	s.stopOnce.Do(s.closeAll)
}

func (s *System) closeAll() {
	// Halt the maintenance loop first so it cannot touch the store mid-close.
	if s.stopMaint != nil {
		s.maintOnce.Do(func() { close(s.stopMaint) })
	}
	for _, sen := range s.sensors {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		if err := sen.Close(ctx); err != nil {
			s.log.Warn("sensor close error", "sensor", sen.ID(), "err", err)
		}
		cancel()
	}
	if s.adminSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		if err := s.adminSrv.Close(ctx); err != nil {
			s.log.Warn("admin close error", "err", err)
		}
		cancel()
	}
	if s.bus != nil {
		s.bus.Close()
	}
	if s.extMgr != nil {
		// After bus drain (so queued events were offered) and before store
		// close: bounded flush window, then hosts are stopped regardless.
		s.extMgr.Stop()
	}
	if s.hook != nil {
		// Same position in the ordering: drain-then-abandon is the webhook
		// sink's own bounded policy.
		s.hook.Close()
	}
	if s.store != nil {
		if err := s.store.Flush(); err != nil {
			s.log.Warn("final flush failed", "err", err)
		}
		if err := s.store.Close(); err != nil {
			s.log.Warn("store close failed", "err", err)
		}
	}
}

// Run blocks until ctx is cancelled, then stops the system. Returns an error
// if any sensor failed terminally while running.
func (s *System) Run(ctx context.Context) error {
	if err := s.Start(ctx); err != nil {
		return err
	}
	defer s.Stop(context.Background())

	failures := make(chan error, len(s.sensors))
	for _, sen := range s.sensors {
		go func(se sensor.Sensor) {
			select {
			case err := <-se.Done():
				if err != nil {
					s.failed.Add(1)
					failures <- fmt.Errorf("sensor %s: %v", se.ID(), err)
				}
			case <-ctx.Done():
			}
		}(sen)
	}

	select {
	case <-ctx.Done():
		s.log.Info("shutdown signal received")
		return nil
	case err := <-failures:
		return fmt.Errorf("%w: %v", errRuntime, err)
	}
}
