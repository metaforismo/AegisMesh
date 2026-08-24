package sensorproc

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/llm"
	"github.com/metaforismo/aegismesh/internal/policy"
	"github.com/metaforismo/aegismesh/internal/sensor"
	"github.com/metaforismo/aegismesh/internal/sensorfactory"
)

// IsBuiltinWorkerInvocation recognizes only the fixed private argv and
// environment pair emitted by the production command factory.
func IsBuiltinWorkerInvocation(args []string) bool {
	return len(args) == 2 && args[1] == WorkerArg && os.Getenv(workerEnvName) == "1"
}

// RunBuiltinWorker is the fixed hidden same-binary worker entrypoint. It has
// no configuration path, provider credential, or destination authority.
func RunBuiltinWorker(ctx context.Context, input io.Reader, output io.Writer) error {
	if os.Getenv(workerEnvName) != "1" {
		return fmt.Errorf("sensorproc: worker environment marker is missing")
	}
	if err := PrepareWorkerProcess(); err != nil {
		return fmt.Errorf("sensorproc: apply worker descriptor cap: %w", err)
	}
	return RunWorker(ctx, input, output, buildBuiltinSensor)
}

func buildBuiltinSensor(d sensor.Deps, detection config.Detection) (sensor.Sensor, error) {
	enforcer := policy.NewEnforcer(detection, d.Meter)
	resolveBody := func(string) ([]byte, error) {
		return nil, fmt.Errorf("sensorproc: worker cannot resolve body files")
	}
	return sensorfactory.Build(d.Config, resolveBody, llm.Local{}, enforcer)
}
