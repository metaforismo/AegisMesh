// Package runtime wires config into a running system: sensors, evidence bus,
// store, retention loop, and admin listener, with graceful shutdown.
package runtime

import (
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
	"github.com/metaforismo/aegismesh/internal/console"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/ext"
	"github.com/metaforismo/aegismesh/internal/extmanager"
	"github.com/metaforismo/aegismesh/internal/fleet/agent"
	"github.com/metaforismo/aegismesh/internal/fleet/hub"
	"github.com/metaforismo/aegismesh/internal/llm"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/policy"
	"github.com/metaforismo/aegismesh/internal/sensor"
	"github.com/metaforismo/aegismesh/internal/sensorfactory"
	"github.com/metaforismo/aegismesh/internal/sensorproc"
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
	fleetHub      *hub.Hub
	fleetServer   *hub.Server
	fleetAgent    *agent.Agent
	fleetCounts   fleetCounts
	storageFailed atomic.Bool
	consoleSrv    *console.Server
	index         *evidenceindex.Index
	tenantIndexes map[string]*evidenceindex.Index
	builtAt       time.Time
	cfg           *config.Config
	store         *storage.Store
	bus           *event.Bus
	meter         observe.Meter
	seq           *event.Sequencer
	adminSrv      *admin.Server
	sensors       []sensor.Sensor
	extMgr        *extmanager.Manager
	hook          *webhook.Sink
	corr          *correlateAdapter
	log           *slog.Logger
	started       atomic.Uint64
	stopped       atomic.Bool
	stopMaint     chan struct{}
	maintOnce     sync.Once
	maintWG       sync.WaitGroup
	stopOnce      sync.Once
}

// Build constructs resources and binds admin/console listeners. Sensors bind
// during Start, after console exposure and state have passed validation.
func Build(cfg *config.Config, log *slog.Logger) (*System, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: nil config", errRuntime)
	}
	if cfg.Console.Enabled || cfg.Fleet.Hub.Enabled || cfg.Fleet.Agent.Enabled {
		if err := cfg.Validate(); err != nil {
			return nil, err
		}
	}
	if log == nil {
		log = slog.Default()
	}

	reg := observe.NewRegistry()
	storeOpts := storage.Options{
		Dir:           cfg.Runtime.DataDir,
		MaxFileBytes:  cfg.Storage.MaxFileBytes,
		MaxEventBytes: cfg.Storage.MaxEventBytes,
		MaxEvents:     cfg.Storage.Retention.MaxEvents,
		MaxAgeDays:    cfg.Storage.Retention.MaxAgeDays,
	}
	if cfg.Storage.Encryption != nil && cfg.Storage.Encryption.Enabled {
		storeOpts.Encryption = &storage.EncryptionOptions{
			Recipient: cfg.Storage.Encryption.Recipient,
		}
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

	enf := policy.NewEnforcer(cfg.Detection, reg, cfg.Honeytokens...)

	sys := &System{
		cfg:       cfg,
		builtAt:   time.Now(),
		store:     store,
		meter:     reg,
		seq:       &event.Sequencer{},
		log:       log,
		stopMaint: make(chan struct{}),
	}

	if err := sys.buildFleet(); err != nil {
		sys.closeAll()
		return nil, fmt.Errorf("%w: %v", errRuntime, err)
	}
	primary := event.Sink(store)
	if cfg.Console.Enabled {
		if err := sys.buildConsole(); err != nil {
			sys.closeAll()
			return nil, fmt.Errorf("%w: %v", errRuntime, err)
		}
		primary = &indexedSink{primary: store, index: sys.index}
	}
	if cfg.Fleet.Agent.Enabled {
		primary = &fleetSink{
			primary: primary,
			system:  sys,
		}
	}
	if cfg.Fleet.Hub.Enabled {
		listener, err := hub.Listen(cfg.Fleet.Hub.Listen, cfg.Fleet.Hub.TLSCertFile, cfg.Fleet.Hub.TLSKeyFile, sys.fleetHub)
		if err != nil {
			sys.closeAll()
			return nil, fmt.Errorf("%w: fleet hub listener: %v", errRuntime, err)
		}
		sys.fleetServer = listener
	}
	if cfg.Extensions.IsEnabled() {
		manifests, err := loadObserverManifests(cfg)
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
			WindowSeconds:       cfg.Correlation.WindowSeconds,
			AutomationThreshold: cfg.Correlation.AutomationThreshold, CredentialThreshold: cfg.Correlation.CredentialThreshold,
			PerSourceEvents: cfg.Correlation.PerSourceEvents,
			MaxSources:      cfg.Correlation.MaxSources,
			DisabledRules:   cfg.Correlation.DisabledRules,
		}, correlateDeps{
			seq:      sys.seq,
			instance: cfg.Runtime.InstanceName,
			store:    primary,
		}, reg, log)
	}

	sink := primary
	if sys.extMgr != nil || sys.hook != nil || sys.corr != nil {
		fanout := evidenceSink{primary: primary}
		if sys.extMgr != nil {
			fanout.mgr = sys.extMgr
		}
		if sys.hook != nil {
			fanout.hook = sys.hook
		}
		if sys.corr != nil {
			fanout.corr = sys.corr
		}
		sink = fanout
	}
	sys.bus = event.NewBus(busCapacity, sink, log)

	for i := range cfg.Sensors {
		var s sensor.Sensor
		var err error
		if cfg.Sensors[i].ProcessIsolation {
			var spec sensorproc.WorkerSpec
			spec, err = isolatedSensorSpec(cfg.Sensors[i], cfg)
			if err == nil {
				s, err = sensorproc.NewProxy(sensorproc.ProxyOptions{Spec: spec})
			}
		} else {
			s, err = sensorfactory.Build(cfg.Sensors[i], cfg.ResolveBodyFile, prov, enf)
		}
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
func loadObserverManifests(cfg *config.Config) ([]*ext.Manifest, error) {
	c := cfg.Extensions
	seen := map[string]bool{}
	manifests := make([]*ext.Manifest, 0, len(c.Manifests))
	for _, rel := range c.Manifests {
		path, err := cfg.ResolveExtensionManifestPath(rel)
		if err != nil {
			return nil, err
		}
		m, err := ext.LoadManifest(path)
		if err != nil {
			return nil, fmt.Errorf("extension manifest %s: %v", filepath.Base(path), err)
		}
		if seen[m.Name] {
			return nil, fmt.Errorf("extension name %q declared twice (unique names are required for metrics and logs)", m.Name)
		}
		seen[m.Name] = true
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
