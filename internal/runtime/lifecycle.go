package runtime

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/metaforismo/aegismesh/internal/admin"
	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/sensor"
)

// Start brings up admin, observer extensions, and all sensors. Partial
// failures tear everything down.
func (s *System) Start(ctx context.Context) error {
	return s.start(ctx, true)
}

// StartDryRun verifies listeners without starting fleet agent egress or consuming an enrollment token.
func (s *System) StartDryRun(ctx context.Context) error {
	return s.start(ctx, false)
}

func (s *System) start(ctx context.Context, reportFleet bool) error {
	if s.fleetServer != nil {
		s.fleetServer.Start()
	}
	if s.consoleSrv != nil {
		s.consoleSrv.Start()
	}
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
	if reportFleet && s.fleetAgent != nil {
		s.fleetAgent.Start()
	}
	s.maintWG.Add(1)
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
	startedTotal := int(s.started.Load())
	startedHealthy := startedTotal
	for i := 0; i < startedTotal && i < len(s.sensors); i++ {
		if h, ok := s.sensors[i].(healthProvider); ok && !h.Healthy() {
			startedHealthy--
		}
	}
	return admin.Status{
		SensorsStarted: startedHealthy,
		SensorsWanted:  len(s.sensors),
		StoreHealthy:   !s.storageFailed.Load(),
		DroppedEvents:  s.bus.Dropped(),
	}
}

func (s *System) maintenanceLoop() {
	defer s.maintWG.Done()
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
				s.storageFailed.Store(true)
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
	s.stopOnce.Do(func() {
		s.stopped.Store(true)
		s.closeAll()
	})
}

func (s *System) closeAll() {
	// Halt the maintenance loop first so it cannot touch the store mid-close.
	if s.stopMaint != nil {
		s.maintOnce.Do(func() { close(s.stopMaint) })
	}
	s.maintWG.Wait()
	if s.fleetAgent != nil {
		s.fleetAgent.Close()
	}
	if s.fleetServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		_ = s.fleetServer.Close(ctx)
		cancel()
	}
	if s.fleetHub != nil {
		_ = s.fleetHub.Close()
	}
	if s.consoleSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		if err := s.consoleSrv.Close(ctx); err != nil {
			s.log.Warn("console close failed", "err", err)
		}
		cancel()
	}
	s.closeSensors()
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

func (s *System) closeSensors() {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	var wg sync.WaitGroup
	for _, sen := range s.sensors {
		wg.Add(1)
		go func(se sensor.Sensor) {
			defer wg.Done()
			if err := se.Close(ctx); err != nil {
				s.log.Warn("sensor close error", "sensor", se.ID(), "err", err)
			}
		}(sen)
	}
	wg.Wait()
}

// Run blocks until ctx is cancelled, then stops the system. Returns an error
// if an in-process sensor failed terminally while running. An isolated sensor
// failure degrades readiness while the remaining sensors continue serving.
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
					if isolated, ok := se.(failureContained); ok && isolated.FailureContained() {
						s.log.Error("isolated sensor failed; readiness degraded", "sensor", se.ID(), "err", err)
						return
					}
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
