package runtime

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/metaforismo/aegismesh/internal/console"
	"github.com/metaforismo/aegismesh/internal/consoleui"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/rulecatalog"
	"github.com/metaforismo/aegismesh/internal/storage"
	"github.com/metaforismo/aegismesh/internal/version"
)

// Both bus observations and directly persisted correlation signals share this
// append-only tap. Signals never enter the bus or its outbound fan-out.
type indexedSink struct {
	mu      sync.Mutex
	primary event.Sink
	index   *evidenceindex.Index
}

// Append updates the disposable index only after the authoritative evidence append succeeds.
func (s *indexedSink) Append(ctx context.Context, envelope event.Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.primary.Append(ctx, envelope); err != nil {
		return err
	}

	s.index.Add(envelope)
	return nil
}

func (s *System) buildConsole() error {
	index, err := evidenceindex.New(s.cfg.Console.IndexMaxEvents, s.meter)
	if err != nil {
		return err
	}

	s.index = index
	if s.cfg.Storage.Encryption != nil && s.cfg.Storage.Encryption.Enabled {
		index.SetHistory("unavailable")
	} else {
		corrupt := false
		err = s.store.Reader().ForEach(func(envelope event.Envelope) error {
			if envelope.Validate() != nil || envelope.VerifyIntegrity() != nil || !evidenceindex.ValidID(envelope.ID) {
				corrupt = true
				return nil
			}
			index.Add(envelope)
			return nil
		}, func(_ string, _ error) {
			corrupt = true
		})
		if err != nil {
			return fmt.Errorf("console: evidence backfill: %w", err)
		}
		if corrupt {
			index.SetHistory("unavailable")
		}
	}

	rules := []console.Rule{}
	for _, rule := range rulecatalog.All() {
		enabled := s.cfg.Detection.IsEnabled()
		disabled := s.cfg.Detection.DisabledRules
		if rule.Family == rulecatalog.FamilyCorrelation {
			enabled = s.cfg.Correlation.IsEnabled()
			disabled = s.cfg.Correlation.DisabledRules
		}
		for _, id := range disabled {
			if rule.ID == id {
				enabled = false
			}
		}
		rules = append(rules, console.Rule{
			ID:       rule.ID,
			Family:   rule.Family,
			Title:    rule.Summary,
			Severity: rule.Severity,
			Enabled:  enabled,
		})
	}

	server, err := console.New(console.Options{
		Config:   s.cfg.Console,
		Security: s.cfg.Security,
		StateDir: s.cfg.ConsoleStateDir(),
		Index:    index,
		Runtime:  s,
		Rules:    rules,
		Meter:    s.meter,
		UI:       consoleui.FS(),
	})
	if err != nil {
		return err
	}

	s.consoleSrv = server
	return nil
}

// ConsoleAddr returns the bound console authority while the console is enabled and running.
func (s *System) ConsoleAddr() (string, error) {
	if s.consoleSrv == nil || s.stopped.Load() {
		return "", fmt.Errorf("%w: console disabled or stopped", errRuntime)
	}

	return s.consoleSrv.Addr(), nil
}

// ConsoleNode returns runtime values and bounded storage metadata without reading evidence.
func (s *System) ConsoleNode() (console.Node, error) {
	status := s.Status()
	buildVersion := version.Get()
	node := console.Node{
		Instance: s.cfg.Runtime.InstanceName,
		Version: console.NodeVersion{
			Version: buildVersion.Version,
			Commit:  buildVersion.Commit,
			Go:      buildVersion.GoVersion,
		},
		StartedAt:     s.builtAt.UTC().Format(time.RFC3339Nano),
		UptimeSeconds: int64(time.Since(s.builtAt) / time.Second),
		Healthy:       !s.stopped.Load() && status.SensorsStarted == status.SensorsWanted && status.StoreHealthy,
		Sensors: console.NodeSensors{
			Wanted:  status.SensorsWanted,
			Started: status.SensorsStarted,
		},
		Bus: console.NodeBus{DroppedEvents: status.DroppedEvents},
		Storage: console.NodeStorage{
			Encrypted: s.cfg.Storage.Encryption != nil && s.cfg.Storage.Encryption.Enabled,
			Retention: console.Retention{
				MaxEvents:  s.cfg.Storage.Retention.MaxEvents,
				MaxAgeDays: s.cfg.Storage.Retention.MaxAgeDays,
			},
		},
	}

	metadata, err := s.store.SnapshotMetadata(storage.MaxMetadataEntries)
	if err != nil {
		return console.Node{}, err
	}

	node.Storage.Segments = metadata.Segments
	node.Storage.Bytes = metadata.Bytes
	return node, nil
}

// ConsoleSensors returns configured sensors with their current listener and health snapshots.
func (s *System) ConsoleSensors() []console.Sensor {
	sensors := make([]console.Sensor, 0, len(s.sensors))
	started := int(s.started.Load())
	for i, sensor := range s.sensors {
		cfg := s.cfg.Sensors[i]
		state := "stopped"
		listen := cfg.Listen
		if i < started && !s.stopped.Load() {
			state = "running"
			if health, ok := sensor.(healthProvider); ok && !health.Healthy() {
				state = "failed"
			}
			if address, ok := sensor.(addrProvider); ok {
				listen = address.Addr()
			}
		}
		sensors = append(sensors, console.Sensor{
			ID:               cfg.ID,
			Kind:             cfg.Kind,
			Listen:           listen,
			State:            state,
			ProcessIsolation: cfg.ProcessIsolation,
		})
	}

	return sensors
}
