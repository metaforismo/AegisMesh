// Package sensor defines the runtime contract every deception sensor
// implements. Sensors receive only their own validated config slice plus the
// capabilities they need (sink, meter, logger) — never the whole world.
package sensor

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/observe"
)

// Deps are the injected capabilities for one sensor instance.
type Deps struct {
	Config   config.Sensor
	Bus      *event.Bus
	Meter    observe.Meter
	Log      *slog.Logger
	Seq      *event.Sequencer
	Instance string
}

// Sensor is a long-running decoy listener.
type Sensor interface {
	// ID and Kind identify the sensor in events and metrics.
	ID() string
	Kind() string

	// Start begins serving. It must not block shutdown signals; implementations
	// return once listeners are bound. Errors after Start surface via Done.
	Start(ctx context.Context, d Deps) error

	// Done reports terminal failure after a successful Start (e.g., accept loop
	// died). The runtime logs it and shuts down gracefully.
	Done() <-chan error

	// Close stops listeners and waits for in-flight handlers, bounded by ctx.
	Close(ctx context.Context) error
}

// ValidateDeps guards against nil capabilities — fail fast at construction,
// not mid-attack-capture.
func ValidateDeps(d Deps) error {
	switch {
	case d.Config.ID == "":
		return fmt.Errorf("sensor: missing config")
	case d.Bus == nil:
		return fmt.Errorf("sensor %s: nil event bus", d.Config.ID)
	case d.Meter == nil:
		return fmt.Errorf("sensor %s: nil meter", d.Config.ID)
	case d.Log == nil:
		return fmt.Errorf("sensor %s: nil logger", d.Config.ID)
	case d.Seq == nil:
		return fmt.Errorf("sensor %s: nil sequencer", d.Config.ID)
	}
	return nil
}

// PeerHost extracts the host portion of an address without ever trusting it
// for authorization decisions — it is recorded as observation data only.
func PeerHost(addr string) string {
	host := addr
	if i := len(host) - 1; i >= 0 { // last colon splits v6 zone-less hosts
		for j := len(host) - 1; j >= 0; j-- {
			if host[j] == ':' {
				host = host[:j]
				break
			}
			if host[j] == ']' {
				break
			}
		}
	}
	return host
}
