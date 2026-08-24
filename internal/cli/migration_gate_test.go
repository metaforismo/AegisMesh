package cli

import (
	"bytes"
	"encoding/json"
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

func TestMigrateSSHReportAndHelpBoundary(t *testing.T) {
	env := &Env{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
	help := NewMigrateCmd(env).Help()
	for _, want := range []string{"SSH", "synthetic", "commands", "plugins", "host keys", "Telnet"} {
		if !strings.Contains(help, want) {
			t.Fatalf("migration help must state SSH boundary %q: %s", want, help)
		}
	}

	src := filepath.Join(t.TempDir(), "ssh-service.yaml")
	if err := os.WriteFile(src, []byte(`protocol: ssh
address: ":2222"
commands:
  - regex: "^id$"
    handler: "uid=0(root)"
serverName: ubuntu
passwordRegex: "^(root)$"
hostKeyFile: /etc/beelzebub/host_key
`), 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(t.TempDir(), "migrated")
	code, out, stderr := run(t, "migrate", "beelzebub", src, "--out", outDir, "--json")
	if code != 0 {
		t.Fatalf("SSH dry-run failed: %s%s", out, stderr)
	}
	var report struct {
		DryRun       bool `json:"dry_run"`
		Translatable int  `json:"translatable"`
		Results      []struct {
			Detected    string   `json:"detected"`
			Mapped      []string `json:"mapped_fields"`
			Unsupported []struct {
				Path string `json:"path"`
			} `json:"unsupported_fields"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("SSH --json output is not valid JSON: %v\n%s", err, out)
	}
	if !report.DryRun || report.Translatable != 1 || len(report.Results) != 1 || report.Results[0].Detected != "ssh" {
		t.Fatalf("unexpected SSH migration report: %+v", report)
	}
	for _, want := range []string{
		"protocol -> sensors[0].kind=ssh",
		"address -> sensors[0].listen=127.0.0.1:2222",
	} {
		found := false
		for _, got := range report.Results[0].Mapped {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("mapped SSH field %q missing: %+v", want, report.Results[0].Mapped)
		}
	}
	for _, want := range []string{"commands", "serverName", "passwordRegex", "hostKeyFile"} {
		found := false
		for _, note := range report.Results[0].Unsupported {
			if note.Path == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("unsupported SSH field %q missing: %+v", want, report.Results[0].Unsupported)
		}
	}
	if entries, _ := os.ReadDir(outDir); len(entries) != 0 {
		t.Fatal("JSON dry-run must not write files")
	}
}
