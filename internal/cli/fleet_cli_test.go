package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFleetValidateAndDoctorStayStatic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mesh.yaml")
	raw := `api_version: aegismesh.io/v1alpha1
runtime:
  data_dir: data
admin:
  enabled: false
fleet:
  agent:
    enabled: true
    forward_evidence:
      enabled: true
    hub_url: http://127.0.0.1:1
    node_name: synthetic-node
    enrollment_token_env: AEGISMESH_TEST_FLEET_SECRET
sensors:
  - id: web
    kind: http
    listen: 127.0.0.1:0
    rules:
      - name: root
        path_regex: ^/$
        status: 200
        body: synthetic
`
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	secret := strings.Repeat("a", 64)
	t.Setenv("AEGISMESH_TEST_FLEET_SECRET", secret)
	for _, command := range []string{"validate", "effective", "doctor"} {
		var out bytes.Buffer
		env := &Env{Out: &out}
		args := []string{"--config", path, "--json"}
		var err error
		switch command {
		case "validate":
			err = newValidateCmd(env).Run(context.Background(), args)
		case "effective":
			err = newValidateCmd(env).Run(context.Background(), append(args, "--effective"))
		case "doctor":
			err = newDoctorCmd(env).Run(context.Background(), args)
		}
		if !strings.Contains(out.String(), "forward_evidence") {
			t.Fatalf("missing forwarding disclosure: %s", out.String())
		}
		if err != nil || !strings.Contains(out.String(), "fleet") || strings.Contains(out.String(), secret) {
			t.Fatalf("%s: err=%v output=%s", command, err, out.String())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "data", "fleet-agent")); !os.IsNotExist(err) {
		t.Fatal("readiness check created identity or contacted hub")
	}
}
