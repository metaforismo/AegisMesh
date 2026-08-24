package runtime

import (
	"fmt"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/sensorproc"
)

func isolatedSensorSpec(c config.Sensor, cfg *config.Config) (sensorproc.WorkerSpec, error) {
	var specBodies []sensorproc.MaterializedBody
	if c.Kind == config.SensorKindHTTP {
		c.Rules = append([]config.HTTPRule(nil), c.Rules...)
		for i := range c.Rules {
			if c.Rules[i].BodyFile == "" {
				continue
			}
			body, err := cfg.ResolveBodyFile(c.Rules[i].BodyFile)
			if err != nil {
				return sensorproc.WorkerSpec{}, fmt.Errorf("materialize rule %q body: %w", c.Rules[i].Name, err)
			}
			c.Rules[i].BodyFile = ""
			bodyCopy := make([]byte, len(body))
			copy(bodyCopy, body)
			specBodies = append(specBodies, sensorproc.MaterializedBody{RuleIndex: i, Content: bodyCopy})
		}
	}
	return sensorproc.WorkerSpec{
		Sensor:             c,
		Detection:          cfg.Detection,
		Instance:           cfg.Runtime.InstanceName,
		MaterializedBodies: specBodies,
	}, nil
}
