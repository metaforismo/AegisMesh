package runtime

import (
	"context"
	"crypto/tls"
	"sync/atomic"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/fleet/agent"
	"github.com/metaforismo/aegismesh/internal/fleet/hub"
	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
	"github.com/metaforismo/aegismesh/internal/storage"
	"github.com/metaforismo/aegismesh/internal/version"
)

type fleetCounts struct {
	interaction atomic.Uint64
	canary      atomic.Uint64
	correlation atomic.Uint64
}

type fleetSink struct {
	primary event.Sink
	system  *System
}

func (s *fleetSink) Append(ctx context.Context, envelope event.Envelope) error {
	if err := s.primary.Append(ctx, envelope); err != nil {
		s.system.storageFailed.Store(true)
		return err
	}
	switch string(envelope.Classification) {
	case "interaction":
		s.system.fleetCounts.interaction.Add(1)
	case "canary_invocation":
		s.system.fleetCounts.canary.Add(1)
	case "correlation_signal":
		s.system.fleetCounts.correlation.Add(1)
	}
	if s.system.fleetAgent != nil {
		s.system.fleetAgent.Enqueue(envelope)
	}
	return nil
}

func (s *System) buildFleet() error {
	cfg := s.cfg
	if cfg.Fleet.Hub.Enabled {
		if cfg.Fleet.Hub.TLSCertFile != "" {
			if _, err := tls.LoadX509KeyPair(cfg.Fleet.Hub.TLSCertFile, cfg.Fleet.Hub.TLSKeyFile); err != nil {
				return &hub.Error{Code: "invalid hub TLS certificate/key"}
			}
		}
		var evidence *hub.EvidenceOptions
		if cfg.Fleet.Hub.AcceptEvidence.Enabled {
			opts := storage.Options{
				MaxFileBytes: cfg.Storage.MaxFileBytes, MaxEventBytes: cfg.Storage.MaxEventBytes,
				MaxEvents: cfg.Storage.Retention.MaxEvents, MaxAgeDays: cfg.Storage.Retention.MaxAgeDays,
			}
			if cfg.Storage.Encryption != nil && cfg.Storage.Encryption.Enabled {
				opts.Encryption = &storage.EncryptionOptions{Recipient: cfg.Storage.Encryption.Recipient}
			}
			evidence = &hub.EvidenceOptions{Store: opts}
		}
		registry, err := hub.New(hub.Options{
			Evidence: evidence,
			Tenants:  cfg.Console.Tenants,
			TenantAppend: func(name, id string, envelope event.Envelope) {
				if index := s.tenantIndexes[name]; index != nil {
					index.AddForwarded(envelope, id)
				}
			},
			TenantAudit: func(name, action, target, outcome string) error {
				if s.consoleSrv != nil {
					return s.consoleSrv.RecordFleetTenant(name, action, target, outcome)
				}
				return nil
			},
			StateDir: cfg.FleetStateDir(false),
			Meter:    s.meter,
		})
		if err != nil {
			return err
		}
		s.fleetHub = registry
	}
	if cfg.Fleet.Agent.Enabled {
		token, err := cfg.ResolveFleetToken()
		if err != nil {
			return err
		}
		reporter, err := agent.New(agent.Options{
			ForwardEvidence: cfg.Fleet.Agent.ForwardEvidence.Enabled,
			HubURL:          cfg.Fleet.Agent.HubURL,
			StateDir:        cfg.FleetStateDir(true),
			Name:            cfg.FleetNodeName(),
			Token:           token,
			CAFile:          cfg.Fleet.Agent.HubCAFile,
			AllowPrivate:    cfg.Fleet.Agent.AllowPrivateEgress,
			Interval:        time.Duration(cfg.Fleet.Agent.HeartbeatIntervalSeconds) * time.Second,
			Snapshot:        s.fleetHeartbeat,
			Meter:           s.meter,
			Log:             s.log,
		})
		if err != nil {
			return err
		}
		s.fleetAgent = reporter
	}
	return nil
}

func (s *System) fleetHeartbeat() protocol.Heartbeat {
	status := s.Status()
	build := version.Get()
	snapshot := protocol.Heartbeat{
		Name: s.cfg.FleetNodeName(),
		Version: protocol.Version{
			Version: build.Version,
			Commit:  build.Commit,
			Go:      build.GoVersion,
		},
		UptimeSeconds:  int64(time.Since(s.builtAt) / time.Second),
		Sensors:        []protocol.Sensor{},
		SensorsWanted:  status.SensorsWanted,
		SensorsStarted: status.SensorsStarted,
		Counters: protocol.Counters{
			Interaction:       s.fleetCounts.interaction.Load(),
			CanaryInvocation:  s.fleetCounts.canary.Load(),
			CorrelationSignal: s.fleetCounts.correlation.Load(),
		},
		BusDroppedEvents: status.DroppedEvents,
		StorageHealthy:   status.StoreHealthy && !s.storageFailed.Load(),
		ConsoleEnabled:   s.cfg.Console.Enabled,
		HubEnabled:       s.cfg.Fleet.Hub.Enabled,
	}
	for _, sensor := range s.ConsoleSensors() {
		snapshot.Sensors = append(snapshot.Sensors, protocol.Sensor{
			ID:    sensor.ID,
			Kind:  sensor.Kind,
			State: sensor.State,
		})
	}
	return snapshot
}

// FleetStatus returns configured roles and safe delivery state, even when both roles are disabled.
func (s *System) FleetStatus() protocol.Status {
	status := protocol.Status{
		Hub: protocol.HubStatus{
			AcceptEvidence: s.cfg.Fleet.Hub.AcceptEvidence.Enabled,
			Enabled:        s.cfg.Fleet.Hub.Enabled,
			Listen:         s.cfg.Fleet.Hub.Listen,
			TLS:            s.cfg.Fleet.Hub.TLSCertFile != "",
		},
		Agent: protocol.AgentStatus{
			Enabled: s.cfg.Fleet.Agent.Enabled,
			HubURL:  agent.Origin(s.cfg.Fleet.Agent.HubURL),
		},
	}
	if s.fleetAgent != nil {
		status.Agent = s.fleetAgent.Status()
	}
	if s.fleetServer != nil {
		status.Hub.Listen = s.fleetServer.Addr()
	}
	return status
}
