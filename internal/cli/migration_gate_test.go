package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const migrationInlineKeyFixture = `protocol: http
address: ":8081"
description: "leaky source"
commands:
  - regex: "^/admin$"
    handler: "denied"
`

func TestMigrateRefusesInlineCredentialMaterial(t *testing.T) {
	src := filepath.Join(t.TempDir(), "leak.yaml")
	body := migrationInlineKeyFixture + "api_key: \"" + strings.Repeat("A1b2C3d4E5f6G7h8I9j0K1l2", 3) + "\"\n"
	os.WriteFile(src, []byte(body), 0o600)

	outDir := filepath.Join(t.TempDir(), "out")
	code, out, stderr := run(t, "migrate", "beelzebub", src, "--out", outDir)
	if code == 0 {
		t.Fatalf("inline credential must refuse import: %q", out)
	}
	msg := out + stderr
	if !strings.Contains(msg, "credential material detected at $.api_key") {
		t.Fatalf("error must name the offending path: %q", msg)
	}
	if strings.Contains(msg, strings.Repeat("A1b2", 4)) {
		t.Fatal("refusal message must never echo the secret value")
	}
	if entries, _ := os.ReadDir(outDir); len(entries) != 0 {
		t.Fatal("refused import must write nothing")
	}
}

func TestMigrateReportsCredentialReferenceWithoutCarryingIt(t *testing.T) {
	src := filepath.Join(t.TempDir(), "ref.yaml")
	os.WriteFile(src, []byte(migrationInlineKeyFixture+"token: /etc/beelzebub/auth.token\n"), 0o600)

	outDir := filepath.Join(t.TempDir(), "out")
	code, out, stderr := run(t, "migrate", "beelzebub", src, "--out", outDir, "--write")
	if code != 0 {
		t.Fatalf("path-shaped reference may import, reported: %q %q", out, stderr)
	}
	if !strings.Contains(out, "credential reference detected") {
		t.Fatalf("reference must be surfaced as unsupported note: %q", out)
	}
	generated := filepath.Join(outDir, "ref.aegismesh.yaml")
	emitted, err := os.ReadFile(generated)
	if err != nil {
		t.Fatalf("generated config missing: %v", err)
	}
	if strings.Contains(string(emitted), "/etc/beelzebub/auth.token") {
		t.Fatal("credential reference must never be carried into emitted config")
	}
}

func TestMigrateExampleFixturesRoundTrip(t *testing.T) {
	for _, name := range []string{"beelzebub-http.yaml", "beelzebub-mcp.yaml"} {
		t.Run(name, func(t *testing.T) {
			src := filepath.Join("..", "migrate", "beelzebub", "testdata", "example", name)
			if _, err := os.Stat(src); err != nil {
				t.Skipf("fixture unavailable: %v", err)
			}
			outDir := t.TempDir()
			code, out, stderr := run(t, "migrate", "beelzebub", src, "--out", outDir, "--write")
			if code != 0 {
				t.Fatalf("example fixture must migrate cleanly: %s%s", out, stderr)
			}
			generated := filepath.Join(outDir, strings.TrimSuffix(name, ".yaml")+".aegismesh.yaml")
			code, _, stderr = run(t, "validate", "--config", generated)
			if code != 0 {
				t.Fatalf("emitted config must pass strict validation: %s", stderr)
			}
		})
	}
}
