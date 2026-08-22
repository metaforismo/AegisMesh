// Package runtime wires config into a running system: sensors, evidence bus,
// store, retention loop, and admin listener, with graceful shutdown.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metaforismo/aegismesh/internal/admin"
	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/llm"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/policy"
	"github.com/metaforismo/aegismesh/internal/sensor"
	"github.com/metaforismo/aegismesh/internal/sensor/httpsensor"
	"github.com/metaforismo/aegismesh/internal/sensor/mcpsensor"
	"github.com/metaforismo/aegismesh/internal/sensor/tcpsensor"
	"github.com/metaforismo/aegismesh/internal/storage"
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
	log       *slog.Logger
	failed    atomic.Uint64
	stopMaint chan struct{}
	maintOnce sync.Once
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

	prov, err := providerFor(cfg.LLM)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("%w: %v", errRuntime, err)
	}

	sys := &System{
		cfg:       cfg,
		store:     store,
		meter:     reg,
		seq:       &event.Sequencer{},
		log:       log,
		stopMaint: make(chan struct{}),
	}
	sys.bus = event.NewBus(busCapacity, store, log)

	for i := range cfg.Sensors {
		s, err := buildSensor(&cfg.Sensors[i], cfg, prov)
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

func providerFor(lc config.LLM) (llm.Provider, error) {
	switch lc.Provider {
	case "", "local":
		return llm.Local{}, nil
	default:
		// Remote adapters land with roadmap R2; fail closed meanwhile.
		if lc.APIKey == "" {
			return nil, llm.ErrNoAPIKey
		}
		return nil, fmt.Errorf("provider %q is not implemented in this release; use llm.provider=local", lc.Provider)
	}
}

func buildSensor(c *config.Sensor, cfg *config.Config, prov llm.Provider) (sensor.Sensor, error) {
	switch c.Kind {
	case config.SensorKindHTTP:
		gate, err := policy.NewHTTPGate(*c, cfg.ResolveBodyFile, prov)
		if err != nil {
			return nil, err
		}
		return httpsensor.New(*c, gate)
	case config.SensorKindTCP:
		gate, err := policy.NewTCPGate(*c)
		if err != nil {
			return nil, err
		}
		return tcpsensor.New(*c, gate)
	case config.SensorKindMCP:
		return mcpsensor.New(*c)
	default:
		return nil, fmt.Errorf("unknown kind %q", c.Kind)
	}
}

// Start brings up admin + all sensors. Partial failures tear everything down.
func (s *System) Start(ctx context.Context) error {
	if s.adminSrv != nil {
		s.adminSrv.Start()
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
	return admin.Status{
		SensorsStarted: len(s.sensors) - int(s.failed.Load()),
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
func (s *System) Stop(ctx context.Context) {
	s.closeAll()
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
