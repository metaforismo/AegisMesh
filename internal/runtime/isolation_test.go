package runtime

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/sensorproc"
)

func TestOmittedProcessIsolationUsesInProcessSensors(t *testing.T) {
	sys, err := Build(testConfig(t), quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer sys.closeAll()
	for _, s := range sys.sensors {
		if _, isolated := s.(*sensorproc.Proxy); isolated {
			t.Fatalf("sensor %q used a worker without process_isolation", s.ID())
		}
	}
}

func TestIsolatedSensorSpecMaterializesBodyWithoutMutatingConfig(t *testing.T) {
	dir := t.TempDir()
	wantBody := []byte{'s', 'y', 'n', 't', 'h', 0x00, 0xff}
	if err := os.WriteFile(filepath.Join(dir, "body.txt"), wantBody, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		SourcePath: filepath.Join(dir, "mesh.yaml"),
		Runtime:    config.Runtime{InstanceName: "mesh-one"},
		Sensors: []config.Sensor{{
			ID: "web", Kind: config.SensorKindHTTP, Listen: "127.0.0.1:0",
			Rules: []config.HTTPRule{{Name: "root", BodyFile: "body.txt"}},
		}},
	}
	spec, err := isolatedSensorSpec(cfg.Sensors[0], cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := spec.Sensor.Rules[0]; got.Body != "" || got.BodyFile != "" {
		t.Fatalf("materialized rule = %+v", got)
	}
	if len(spec.MaterializedBodies) != 1 || spec.MaterializedBodies[0].RuleIndex != 0 || !bytes.Equal(spec.MaterializedBodies[0].Content, wantBody) {
		t.Fatalf("materialized bodies = %+v", spec.MaterializedBodies)
	}
	if got := cfg.Sensors[0].Rules[0]; got.Body != "" || got.BodyFile != "body.txt" {
		t.Fatalf("source config mutated: %+v", got)
	}
	if spec.Instance != "mesh-one" {
		t.Fatalf("instance = %q", spec.Instance)
	}
}
