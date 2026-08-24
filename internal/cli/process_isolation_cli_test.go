package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/sensorproc"
)

func TestMain(m *testing.M) {
	if sensorproc.IsBuiltinWorkerInvocation(os.Args) {
		if err := sensorproc.RunBuiltinWorker(context.Background(), os.Stdin, os.Stdout); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestRunDryRunWithIsolatedSensor(t *testing.T) {
	dir := t.TempDir()
	doc := fmt.Sprintf(`
api_version: aegismesh.io/v1alpha1
runtime:
  instance_name: isolated-dry-run
  data_dir: %q
admin:
  enabled: false
sensors:
  - id: web
    kind: http
    listen: "127.0.0.1:0"
    process_isolation: true
    rules:
      - name: root
        path_regex: "^/$"
        status: 200
        body: ok
`, filepath.Join(dir, "data"))
	path := filepath.Join(dir, "mesh.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := run(t, "run", "--config", path, "--dry-run")
	if code != 0 || !strings.Contains(out, "dry-run ok") {
		t.Fatalf("isolated dry-run: code=%d out=%q stderr=%q", code, out, stderr)
	}
}
