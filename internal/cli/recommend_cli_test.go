package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/recommend"
	"github.com/metaforismo/aegismesh/internal/storage"
)

func TestRecommendHumanAndJSONAreStableAndEvidenceLinked(t *testing.T) {
	dir := seedRecommendations(t,
		recommendationEvent{sensor: "http-decoy-1", class: event.ClassificationInteraction, observation: `{"detection":{"action":"observe","findings":[{"rule_id":"PI-001","severity":"high","confidence":"high","reason":"static"}]},"marker":"do-not-copy"}`},
	)

	code, human, stderr := run(t, "recommend", "--data-dir", dir)
	if code != 0 {
		t.Fatalf("human recommendation failed: %d %s", code, stderr)
	}
	if !strings.Contains(human, "DRY-RUN RECOMMENDATIONS") ||
		!strings.Contains(human, "signal_not_incident") ||
		!strings.Contains(human, "sensor_id: http-decoy-1") ||
		!strings.Contains(human, "sensor_kind: http") ||
		!strings.Contains(human, "payload_sha256:") ||
		strings.Contains(human, "do-not-copy") {
		t.Fatalf("unexpected human output:\n%s", human)
	}

	code, jsonOut, stderr := run(t, "recommend", "--data-dir", dir, "--json")
	if code != 0 {
		t.Fatalf("JSON recommendation failed: %d %s", code, stderr)
	}
	var report recommend.Report
	if err := json.Unmarshal([]byte(jsonOut), &report); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, jsonOut)
	}
	if len(report.Recommendations) != 1 {
		t.Fatalf("recommendation count = %d", len(report.Recommendations))
	}
	rec := report.Recommendations[0]
	if rec.Classification != event.ClassificationInteraction || len(rec.RuleIDs) != 1 || rec.RuleIDs[0] != "PI-001" {
		t.Fatalf("unexpected recommendation: %+v", rec)
	}
	if rec.SensorID != "http-decoy-1" || rec.SensorKind != "http" {
		t.Fatalf("sensor metadata missing: %+v", rec)
	}
	if len(rec.Evidence) != 1 || rec.Evidence[0].EventID == "" || len(rec.Evidence[0].PayloadSHA256) != 64 {
		t.Fatalf("evidence link is incomplete: %+v", rec.Evidence)
	}
	if !strings.Contains(jsonOut, "observation_payload_only") || !strings.Contains(jsonOut, "payload_hash_consistent") {
		t.Fatalf("integrity contract missing: %s", jsonOut)
	}

	code, again, _ := run(t, "recommend", "--data-dir", dir, "--json")
	if code != 0 || again != jsonOut {
		t.Fatalf("JSON output is not byte-stable:\nfirst=%s\nsecond=%s", jsonOut, again)
	}
}

func TestRecommendGoldenOutputs(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "recommend.event.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "events-golden.jsonl"), fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		args   []string
		golden string
	}{
		{name: "human", args: []string{"recommend", "--data-dir", dir}, golden: "recommend.golden.txt"},
		{name: "json", args: []string{"recommend", "--data-dir", dir, "--json"}, golden: "recommend.golden.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, got, stderr := run(t, tc.args...)
			if code != 0 || stderr != "" {
				t.Fatalf("golden command failed: code=%d stderr=%q", code, stderr)
			}
			want, err := os.ReadFile(filepath.Join("testdata", tc.golden))
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Fatalf("output drifted from %s:\n--- got ---\n%s\n--- want ---\n%s", tc.golden, got, want)
			}
		})
	}
}

func TestRecommendFiltersBeforeLimitAndSupportsClasses(t *testing.T) {
	dir := seedRecommendations(t,
		recommendationEvent{sensor: "http-decoy-1", class: event.ClassificationInteraction, observation: detectionObservation("PI-002")},
		recommendationEvent{sensor: "tcp-decoy-1", class: event.ClassificationInteraction, observation: detectionObservation("PI-001")},
		recommendationEvent{sensor: "mcp-canary-1", class: event.ClassificationCanaryHit, observation: `{}`},
		recommendationEvent{sensor: "http-decoy-1", class: event.ClassificationCorrelationSignal, observation: `{"rule_id":"COR-001","summary":"untrusted","source_key":"source","source_event_ids":[],"truncated":false}`},
	)

	code, out, stderr := run(t, "recommend", "--data-dir", dir, "--rule", "PI-001", "--limit", "1", "--json")
	if code != 0 {
		t.Fatalf("rule filter failed: %d %s", code, stderr)
	}
	var report recommend.Report
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Recommendations) != 1 || report.Recommendations[0].RuleIDs[0] != "PI-001" {
		t.Fatalf("filter was applied after limit: %+v", report.Recommendations)
	}

	for _, class := range []string{event.ClassificationInteraction, event.ClassificationCanaryHit, event.ClassificationCorrelationSignal} {
		code, out, stderr = run(t, "recommend", "--data-dir", dir, "--classification", class, "--json")
		if code != 0 {
			t.Fatalf("classification %s failed: %d %s", class, code, stderr)
		}
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatal(err)
		}
		wantCount := 1
		if class == event.ClassificationInteraction {
			wantCount = 2
		}
		if len(report.Recommendations) != wantCount {
			t.Fatalf("classification filter leaked rows: %s %+v", class, report.Recommendations)
		}
		for _, rec := range report.Recommendations {
			if rec.Classification != class {
				t.Fatalf("classification filter leaked row: want=%s got=%s", class, rec.Classification)
			}
		}
	}

	code, out, stderr = run(t, "recommend", "--data-dir", dir, "--sensor", "tcp-decoy-1", "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("sensor filter failed: %d %s", code, stderr)
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Recommendations) != 1 || report.Recommendations[0].RuleIDs[0] != "PI-001" {
		t.Fatalf("sensor filter wrong: %+v", report.Recommendations)
	}

	code, out, stderr = run(t, "recommend", "--data-dir", dir, "--rule", "COR-004", "--json")
	if code != 0 || stderr != "" || !strings.Contains(out, `"recommendations": []`) {
		t.Fatalf("no-match report wrong: code=%d stderr=%q out=%s", code, stderr, out)
	}
}

func TestRecommendRejectsStrictFlagFormsWithoutOutput(t *testing.T) {
	dir := seedRecommendations(t,
		recommendationEvent{sensor: "http-decoy-1", class: event.ClassificationInteraction, observation: detectionObservation("PI-001")},
	)
	cases := []struct {
		name string
		args []string
	}{
		{"missing data dir", []string{"recommend"}},
		{"empty data dir", []string{"recommend", "--data-dir", ""}},
		{"equals empty data dir", []string{"recommend", "--data-dir="}},
		{"whitespace data dir", []string{"recommend", "--data-dir", "   "}},
		{"padded data dir", []string{"recommend", "--data-dir", " " + dir}},
		{"data dir consumes next flag", []string{"recommend", "--data-dir", "--limit", "1"}},
		{"data dir equals dash value", []string{"recommend", "--data-dir=-not-a-directory"}},
		{"repeated data dir", []string{"recommend", "--data-dir", dir, "--data-dir", dir}},
		{"limit empty", []string{"recommend", "--data-dir", dir, "--limit", ""}},
		{"limit equals empty", []string{"recommend", "--data-dir", dir, "--limit="}},
		{"limit missing", []string{"recommend", "--data-dir", dir, "--limit"}},
		{"limit whitespace", []string{"recommend", "--data-dir", dir, "--limit", " 20"}},
		{"limit padded", []string{"recommend", "--data-dir", dir, "--limit", "20 "}},
		{"limit comma", []string{"recommend", "--data-dir", dir, "--limit", "20,21"}},
		{"limit zero", []string{"recommend", "--data-dir", dir, "--limit", "0"}},
		{"limit negative", []string{"recommend", "--data-dir", dir, "--limit", "-1"}},
		{"limit overflow", []string{"recommend", "--data-dir", dir, "--limit", "18446744073709551616"}},
		{"limit too high", []string{"recommend", "--data-dir", dir, "--limit", "1001"}},
		{"limit repeated", []string{"recommend", "--data-dir", dir, "--limit", "1", "--limit", "2"}},
		{"rule empty", []string{"recommend", "--data-dir", dir, "--rule", ""}},
		{"rule equals empty", []string{"recommend", "--data-dir", dir, "--rule="}},
		{"rule missing", []string{"recommend", "--data-dir", dir, "--rule"}},
		{"rule whitespace", []string{"recommend", "--data-dir", dir, "--rule", "   "}},
		{"rule padded", []string{"recommend", "--data-dir", dir, "--rule", " PI-001"}},
		{"rule comma", []string{"recommend", "--data-dir", dir, "--rule", "PI-001,COR-001"}},
		{"rule invalid", []string{"recommend", "--data-dir", dir, "--rule", "NOPE-999"}},
		{"rule repeated", []string{"recommend", "--data-dir", dir, "--rule", "PI-001", "--rule", "PI-001"}},
		{"rule consumes next flag", []string{"recommend", "--data-dir", dir, "--rule", "--json"}},
		{"sensor empty", []string{"recommend", "--data-dir", dir, "--sensor", ""}},
		{"sensor equals empty", []string{"recommend", "--data-dir", dir, "--sensor="}},
		{"sensor missing", []string{"recommend", "--data-dir", dir, "--sensor"}},
		{"sensor whitespace", []string{"recommend", "--data-dir", dir, "--sensor", "   "}},
		{"sensor padded", []string{"recommend", "--data-dir", dir, "--sensor", "http-decoy-1 "}},
		{"sensor comma", []string{"recommend", "--data-dir", dir, "--sensor", "http-decoy-1,tcp"}},
		{"sensor invalid", []string{"recommend", "--data-dir", dir, "--sensor", "A1"}},
		{"sensor repeated", []string{"recommend", "--data-dir", dir, "--sensor", "http-decoy-1", "--sensor", "http-decoy-1"}},
		{"sensor consumes next flag", []string{"recommend", "--data-dir", dir, "--sensor", "--classification", "interaction"}},
		{"classification empty", []string{"recommend", "--data-dir", dir, "--classification", ""}},
		{"classification equals empty", []string{"recommend", "--data-dir", dir, "--classification="}},
		{"classification missing", []string{"recommend", "--data-dir", dir, "--classification"}},
		{"classification whitespace", []string{"recommend", "--data-dir", dir, "--classification", "   "}},
		{"classification padded", []string{"recommend", "--data-dir", dir, "--classification", " interaction"}},
		{"classification comma", []string{"recommend", "--data-dir", dir, "--classification", "interaction,canary_invocation"}},
		{"classification invalid", []string{"recommend", "--data-dir", dir, "--classification", "incident"}},
		{"classification repeated", []string{"recommend", "--data-dir", dir, "--classification", "interaction", "--classification", "interaction"}},
		{"classification consumes next flag", []string{"recommend", "--data-dir", dir, "--classification", "--json"}},
		{"json repeated", []string{"recommend", "--data-dir", dir, "--json", "--json"}},
		{"json empty", []string{"recommend", "--data-dir", dir, "--json="}},
		{"json invalid", []string{"recommend", "--data-dir", dir, "--json=maybe"}},
		{"unknown flag", []string{"recommend", "--data-dir", dir, "--wat"}},
		{"positional", []string{"recommend", "--data-dir", dir, "extra"}},
		{"positional before flags", []string{"recommend", "extra", "--data-dir", dir}},
		{"double dash positional", []string{"recommend", "--data-dir", dir, "--", "extra"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, stderr := run(t, tc.args...)
			if code != 2 {
				t.Fatalf("args=%v exit=%d stderr=%q", tc.args, code, stderr)
			}
			if out != "" {
				t.Fatalf("invalid args wrote stdout: %q", out)
			}
			if stderr == "" {
				t.Fatal("invalid args need a usage error")
			}
		})
	}
}

func TestRecommendAcceptsLimitBoundariesAndExplicitJSONFalse(t *testing.T) {
	dir := seedRecommendations(t,
		recommendationEvent{sensor: "http-decoy-1", class: event.ClassificationInteraction, observation: detectionObservation("PI-001")},
	)
	for _, args := range [][]string{
		{"recommend", "--data-dir", dir},
		{"recommend", "--data-dir", dir, "--limit", "1"},
		{"recommend", "--data-dir", dir, "--limit=1000"},
		{"recommend", "--data-dir", dir, "--json=false"},
	} {
		code, out, stderr := run(t, args...)
		if code != 0 || out == "" || stderr != "" {
			t.Fatalf("valid args=%v code=%d out=%q stderr=%q", args, code, out, stderr)
		}
	}
}

func TestRecommendFailsClosedOnCorruptAndInvalidEvidenceWithoutOutput(t *testing.T) {
	dir := seedRecommendations(t,
		recommendationEvent{sensor: "http-decoy-1", class: event.ClassificationInteraction, observation: detectionObservation("PI-001")},
	)
	segment := onlySegment(t, dir)
	raw, err := os.ReadFile(segment)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(segment, append(raw, []byte("{not-json}\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := run(t, "recommend", "--data-dir", dir)
	if code != 1 || out != "" || !strings.Contains(stderr, "malformed JSON") {
		t.Fatalf("corrupt evidence was not fatal: code=%d out=%q stderr=%q", code, out, stderr)
	}

	// Replace the segment with syntactically valid JSON whose envelope fails
	// structural validation. The recommendation command must not print the
	// earlier valid row before discovering this failure.
	var env event.Envelope
	if err := json.Unmarshal(bytes.TrimSpace(raw), &env); err != nil {
		t.Fatal(err)
	}
	env.Schema = "aegismesh.event/future"
	invalid, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(segment, append(invalid, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr = run(t, "recommend", "--data-dir", dir, "--json")
	if code != 1 || out != "" || !strings.Contains(stderr, "failed closed") {
		t.Fatalf("invalid envelope was not fatal: code=%d out=%q stderr=%q", code, out, stderr)
	}

	env.Schema = event.SchemaV1
	env.Integrity.PayloadSHA256 = strings.Repeat("0", 64)
	writeRecommendationEnvelope(t, segment, env)
	code, out, stderr = run(t, "recommend", "--data-dir", dir, "--json")
	if code != 1 || out != "" || !strings.Contains(stderr, "failed closed") {
		t.Fatalf("integrity mismatch was not fatal: code=%d out=%q stderr=%q", code, out, stderr)
	}

	if err := json.Unmarshal(bytes.TrimSpace(raw), &env); err != nil {
		t.Fatal(err)
	}
	valid, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := append(append(append([]byte(nil), valid...), '\n'), valid...)
	duplicate = append(duplicate, '\n')
	if err := os.WriteFile(segment, duplicate, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr = run(t, "recommend", "--data-dir", dir)
	if code != 1 || out != "" || !strings.Contains(stderr, "duplicate event identity") {
		t.Fatalf("duplicate identity was not fatal: code=%d out=%q stderr=%q", code, out, stderr)
	}

	env.Observation = []byte(`{"detection":{"action":"delete","findings":[]}}`)
	env.Integrity.PayloadSHA256 = event.SHA256Hex(env.Observation)
	writeRecommendationEnvelope(t, segment, env)
	code, out, stderr = run(t, "recommend", "--data-dir", dir)
	if code != 1 || out != "" || !strings.Contains(stderr, "generation failed closed") {
		t.Fatalf("malformed detection block was not fatal: code=%d out=%q stderr=%q", code, out, stderr)
	}
}

func TestRecommendFailsClosedAboveEvidenceCap(t *testing.T) {
	dir := seedRecommendations(t,
		recommendationEvent{sensor: "http-decoy-1", class: event.ClassificationInteraction, observation: detectionObservation("PI-001")},
	)
	segment := onlySegment(t, dir)
	line, err := os.ReadFile(segment)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(segment, bytes.Repeat(line, recommend.MaxEvidence+1), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := run(t, "recommend", "--data-dir", dir)
	if code != 1 || out != "" || !strings.Contains(stderr, "more than 4096 events") {
		t.Fatalf("evidence cap was not fatal: code=%d out=%q stderr=%q", code, out, stderr)
	}
}

func TestRecommendRegistrationHelpAndCompletion(t *testing.T) {
	code, out, stderr := run(t, "--help")
	if code != 0 || stderr != "" || !strings.Contains(out, "recommend") {
		t.Fatalf("top-level help missing recommend: code=%d stderr=%q out=%q", code, stderr, out)
	}
	code, out, stderr = run(t, "completion", "bash")
	if code != 0 || stderr != "" || !strings.Contains(out, "recommend") || !strings.Contains(out, "--classification") {
		t.Fatalf("bash completion missing recommendation flags: code=%d stderr=%q", code, stderr)
	}
	for _, shell := range []string{"zsh", "fish"} {
		code, out, stderr = run(t, "completion", shell)
		if code != 0 || stderr != "" || !strings.Contains(out, "recommend") {
			t.Fatalf("%s completion missing recommend: code=%d stderr=%q", shell, code, stderr)
		}
	}
}

type recommendationEvent struct {
	sensor      string
	class       string
	observation string
}

func seedRecommendations(t *testing.T, entries ...recommendationEvent) string {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.New(storage.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	seq := &event.Sequencer{}
	for i, entry := range entries {
		env, err := event.New(seq, "recommend-test", event.SensorRef{ID: entry.sensor, Kind: sensorKind(entry.sensor), Listen: "127.0.0.1:0"}, entry.class, []byte(entry.observation), nil)
		if err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
		if err := store.Append(context.Background(), env); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func detectionObservation(ruleID string) string {
	return fmt.Sprintf(`{"detection":{"action":"observe","findings":[{"rule_id":%q,"severity":"high","confidence":"high","reason":"static"}]}}`, ruleID)
}

func sensorKind(sensor string) string {
	if strings.HasPrefix(sensor, "tcp") {
		return "tcp"
	}
	if strings.HasPrefix(sensor, "mcp") {
		return "mcp"
	}
	return "http"
}

func onlySegment(t *testing.T, dir string) string {
	t.Helper()
	segments, err := filepath.Glob(filepath.Join(dir, "events-*.jsonl"))
	if err != nil || len(segments) != 1 {
		t.Fatalf("segments=%v err=%v", segments, err)
	}
	return segments[0]
}

func writeRecommendationEnvelope(t *testing.T, path string, env event.Envelope) {
	t.Helper()
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
