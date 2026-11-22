package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/honeytoken"
	"gopkg.in/yaml.v3"
)

func TestHoneytokenCLI(t *testing.T) {
	for _, kind := range []string{honeytoken.Credential, honeytoken.AgentCanary} {
		for _, format := range []string{"openai", "anthropic", "aws", "github", "generic"} {
			t.Run(kind+"/"+format, func(t *testing.T) {
				code, out, stderr := run(t, "honeytoken", "new", "--kind", kind, "--format", format, "--id", "test-plant")
				if code != 0 || stderr != "" {
					t.Fatal(code, stderr)
				}
				var snippet struct {
					Tokens []honeytoken.Token `yaml:"honeytokens"`
				}
				if err := yaml.Unmarshal([]byte(out), &snippet); err != nil {
					t.Fatal(err)
				}
				if len(snippet.Tokens) != 1 || snippet.Tokens[0].Kind != kind || honeytoken.Validate(snippet.Tokens) != nil {
					t.Fatal("invalid snippet")
				}
				if !strings.Contains(out, "Never use real credentials") {
					t.Fatal("missing warning")
				}
			})
		}
	}
	for _, args := range [][]string{{"new"}, {"new", "--kind", "invalid", "--id", "valid"}, {"new", "--kind", "credential", "--id", "bad/id"}, {"new", "--kind", "credential", "--id", "valid", "--format", "other"}, {"new", "--kind", "credential", "--id", "valid", "extra"}} {
		if code, _, _ := run(t, append([]string{"honeytoken"}, args...)...); code == 0 {
			t.Fatal("accepted", args)
		}
	}
}

func TestAIDecoyInitCLI(t *testing.T) {
	dir := t.TempDir()
	code, _, stderr := run(t, "init", "--dir", dir, "--profile", "ai-decoy")
	if code != 0 {
		t.Fatal(stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "mesh.yaml")); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = run(t, "validate", "--config", filepath.Join(dir, "mesh.yaml"))
	if code != 0 {
		t.Fatal(stderr)
	}
}

func TestRulesGoldenFrameworkOutput(t *testing.T) {
	for _, tc := range []struct {
		file string
		args []string
	}{{"rules.golden.txt", []string{"rules", "list"}}, {"rules.golden.json", []string{"rules", "list", "--json"}}} {
		code, out, stderr := run(t, tc.args...)
		if code != 0 {
			t.Fatal(stderr)
		}
		want, err := os.ReadFile(filepath.Join("testdata", tc.file))
		if err != nil {
			t.Fatal(err)
		}
		if out != string(want) {
			t.Fatalf("%s output drift", tc.file)
		}
	}
}
