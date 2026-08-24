// Package sensorfactory owns construction of repository-provided sensors.
package sensorfactory

import (
	"fmt"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/llm"
	"github.com/metaforismo/aegismesh/internal/policy"
	"github.com/metaforismo/aegismesh/internal/sensor"
	"github.com/metaforismo/aegismesh/internal/sensor/httpsensor"
	"github.com/metaforismo/aegismesh/internal/sensor/mcpsensor"
	"github.com/metaforismo/aegismesh/internal/sensor/sshsensor"
	"github.com/metaforismo/aegismesh/internal/sensor/tcpsensor"
)

type BodyResolver func(string) ([]byte, error)

// Build constructs one validated first-party sensor. Callers own the
// provider, policy enforcer, body resolver, and lifecycle.
func Build(c config.Sensor, resolveBody BodyResolver, prov llm.Provider, enf *policy.Enforcer) (sensor.Sensor, error) {
	switch c.Kind {
	case config.SensorKindHTTP:
		gate, err := policy.NewHTTPGate(c, resolveBody, prov, enf)
		if err != nil {
			return nil, err
		}
		return httpsensor.New(c, gate)
	case config.SensorKindTCP:
		gate, err := policy.NewTCPGate(c, enf)
		if err != nil {
			return nil, err
		}
		return tcpsensor.New(c, gate)
	case config.SensorKindMCP:
		return mcpsensor.New(c, enf)
	case config.SensorKindSSH:
		return sshsensor.New(c)
	default:
		return nil, fmt.Errorf("unknown kind %q", c.Kind)
	}
}
