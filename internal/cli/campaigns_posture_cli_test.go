package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
)

var goldenEpoch = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func fixedClock(t *testing.T) {
	t.Helper()
	previous := cliNow
	cliNow = func() time.Time { return goldenEpoch.Add(time.Hour) }
	t.Cleanup(func() { cliNow = previous })
}

// campaignFixture writes two sources following the same model-listing then
// chat sequence, plus an unrelated MCP session, as verified JSONL evidence.
func campaignFixture(t *testing.T) string {
	t.Helper()
	lines := []string{}
	seq := &event.Sequencer{}
	add := func(kind, class, source, observation string, at time.Duration) {
		e, err := event.New(seq, "synthetic", event.SensorRef{ID: "ai-" + kind, Kind: kind}, class, json.RawMessage(observation), nil)
		if err != nil {
			t.Fatal(err)
		}
		e.Time = goldenEpoch.Add(at)
		e.ID = fmt.Sprintf("%032x", len(lines)+1)
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(line))
	}
	for i, source := range []string{"192.0.2.10", "198.51.100.20"} {
		offset := time.Duration(i) * time.Minute
		for j, path := range []string{"/api/tags", "/v1/models", "/v1/models"} {
			add("http", "interaction", source, fmt.Sprintf(`{"method":"GET","path":%q,"remote_host":%q,"user_agent":"OpenAI/Python 1.54.0","response":{"status":200},"detection":{"action":"observe","findings":[{"rule_id":"LLM-001"}]}}`, path, source), offset+time.Duration(j)*time.Second)
		}
		add("http", "interaction", source, fmt.Sprintf(`{"method":"POST","path":"/v1/chat/completions","remote_host":%q,"user_agent":"OpenAI/Python 1.54.0","response":{"status":200},"detection":{"action":"observe","findings":[{"rule_id":"LLM-002"}]}}`, source), offset+4*time.Second)
	}
	for j, method := range []string{"initialize", "tools/list", "tools/call"} {
		add("mcp", "interaction", "203.0.113.9", fmt.Sprintf(`{"method":%q,"remote_host":"203.0.113.9"}`, method), 5*time.Minute+time.Duration(j)*time.Second)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "events-fixture.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func checkGolden(t *testing.T, name, output string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("AEGISMESH_UPDATE_CAMPAIGN_GOLDENS") == "1" {
		if err := os.WriteFile(path, []byte(output), 0600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil || output != string(want) {
		t.Fatalf("%s mismatch (set AEGISMESH_UPDATE_CAMPAIGN_GOLDENS=1 to refresh):\n%s", name, output)
	}
}

func TestCampaignsCLIGolden(t *testing.T) {
	fixedClock(t)
	dir := campaignFixture(t)
	code, text, stderr := run(t, "campaigns", "--data-dir", dir)
	if code != 0 {
		t.Fatal(code, stderr)
	}
	checkGolden(t, "campaigns.golden.txt", text)
	code, body, stderr := run(t, "campaigns", "--data-dir", dir, "--json")
	if code != 0 {
		t.Fatal(code, stderr)
	}
	checkGolden(t, "campaigns.golden.json", body)
	id := regexp.MustCompile(`cmp_[0-9a-f]{12}`).FindString(text)
	code, detail, stderr := run(t, "campaigns", "--data-dir", dir, "--id", id)
	if code != 0 {
		t.Fatal(code, stderr)
	}
	checkGolden(t, "campaign-detail.golden.txt", detail)
	if code, _, _ := run(t, "campaigns", "--data-dir", dir, "--id", "cmp_000000000000"); code != 1 {
		t.Fatal("unknown campaign must exit 1")
	}
	for _, args := range [][]string{{}, {"--data-dir", dir, "--id", "nope"}, {"--data-dir", dir, "positional"}, {"--data-dir", dir, "--json", "--json"}} {
		if code, _, _ := run(t, append([]string{"campaigns"}, args...)...); code != 2 {
			t.Fatal(args, code)
		}
	}
}

func TestPostureCLIGolden(t *testing.T) {
	fixedClock(t)
	dir := campaignFixture(t)
	workspace := t.TempDir()
	config := filepath.Join(workspace, "mesh.yaml")
	body := `api_version: aegismesh.io/v1alpha1
runtime:
  data_dir: ` + dir + `
admin:
  enabled: false
sensors:
  - id: ai-http
    kind: http
    listen: 127.0.0.1:18080
    rules:
      - name: models
        path_regex: ^/v1/models$
        status: 200
        body: synthetic
  - id: quiet-tcp
    kind: tcp
    listen: 127.0.0.1:18081
`
	if err := os.WriteFile(config, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	code, text, stderr := run(t, "posture", "--config", config)
	if code != 0 {
		t.Fatal(code, stderr)
	}
	checkGolden(t, "posture.golden.txt", text)
	code, out, stderr := run(t, "posture", "--config", config, "--json")
	if code != 0 {
		t.Fatal(code, stderr)
	}
	checkGolden(t, "posture.golden.json", out)
	missing := filepath.Join(workspace, "absent")
	code, out, _ = run(t, "posture", "--config", config, "--data-dir", missing, "--json")
	if code != 0 || !strings.Contains(out, "Not evaluated: the evidence directory does not exist yet.") {
		t.Fatal(code, out)
	}
	for _, args := range [][]string{{}, {"--config", config, "extra"}, {"--config", config, "--data-dir", " bad"}} {
		if code, _, _ := run(t, append([]string{"posture"}, args...)...); code != 2 {
			t.Fatal(args, code)
		}
	}
}
