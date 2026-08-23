package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/storage"
)

func TestInspectExportRejectsUnexpectedArgumentsWithoutTouchingOutput(t *testing.T) {
	dir, _ := seedEvidence(t)
	outPath := filepath.Join(t.TempDir(), "export.ndjson")
	const sentinel = "existing export\n"
	if err := os.WriteFile(outPath, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := run(t, "inspect", "export", "--data-dir", dir, "--out", outPath, "unexpected")
	if code != 2 {
		t.Fatalf("exit = %d, want 2; stderr=%q", code, stderr)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != sentinel {
		t.Fatalf("invalid invocation changed output: %q", got)
	}
}

func TestInspectExportVerifyFailsClosedWithoutTouchingOutput(t *testing.T) {
	dir, _ := seedEvidence(t)
	segments, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil || len(segments) != 1 {
		t.Fatalf("segments = %v, err = %v", segments, err)
	}
	raw, err := os.ReadFile(segments[0])
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), "/admin/login", "/admin/panel", 1)
	if tampered == string(raw) {
		t.Fatal("test fixture did not contain observation to tamper")
	}
	if err := os.WriteFile(segments[0], []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(t.TempDir(), "export.ndjson")
	const sentinel = "existing export\n"
	if err := os.WriteFile(outPath, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := run(t, "inspect", "export", "--data-dir", dir, "--out", outPath, "--verify")
	if code != 1 || !strings.Contains(stderr, "integrity") {
		t.Fatalf("exit = %d, want 1 with integrity error; stderr=%q", code, stderr)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != sentinel {
		t.Fatalf("failed verified export changed output: %q", got)
	}
}

func TestInspectExportRejectsStructurallyInvalidNativeEnvelope(t *testing.T) {
	dir, _ := seedEvidence(t)
	segments, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil || len(segments) != 1 {
		t.Fatalf("segments = %v, err = %v", segments, err)
	}
	raw, err := os.ReadFile(segments[0])
	if err != nil {
		t.Fatal(err)
	}
	var env event.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	env.Schema = "aegismesh.event/future"
	raw, err = json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(segments[0], append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(t.TempDir(), "export.ndjson")
	const sentinel = "existing export\n"
	if err := os.WriteFile(outPath, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := run(t, "inspect", "export", "--data-dir", dir, "--out", outPath, "--verify")
	if code != 1 || !strings.Contains(stderr, "verification failed") {
		t.Fatalf("exit = %d, want 1 with verification error; stderr=%q", code, stderr)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != sentinel {
		t.Fatalf("structurally invalid export changed output: %q", got)
	}
}

func TestInspectExportRejectsEvidenceSegmentDestination(t *testing.T) {
	dir, _ := seedEvidence(t)
	segments, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil || len(segments) != 1 {
		t.Fatalf("segments = %v, err = %v", segments, err)
	}
	want, err := os.ReadFile(segments[0])
	if err != nil {
		t.Fatal(err)
	}

	linksDir := t.TempDir()
	symlink := filepath.Join(linksDir, "segment-symlink.jsonl")
	if err := os.Symlink(segments[0], symlink); err != nil {
		t.Fatal(err)
	}
	hardlink := filepath.Join(linksDir, "segment-hardlink.jsonl")
	if err := os.Link(segments[0], hardlink); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		path string
	}{{"direct", segments[0]}, {"symlink", symlink}, {"hardlink", hardlink}} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := run(t, "inspect", "export", "--data-dir", dir, "--out", tc.path, "--profile", "ecs")
			if code != 2 || !strings.Contains(stderr, "evidence segment") {
				t.Fatalf("exit = %d, want 2 with evidence-segment error; stderr=%q", code, stderr)
			}
			got, err := os.ReadFile(segments[0])
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Fatal("export modified its source evidence segment")
			}
		})
	}
}

func TestInspectExportFailsClosedOnSegmentReadError(t *testing.T) {
	dir, _ := seedEvidence(t)
	segments, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil || len(segments) != 1 {
		t.Fatalf("segments = %v, err = %v", segments, err)
	}
	if err := os.Remove(segments[0]); err != nil {
		t.Fatal(err)
	}
	unreadable := filepath.Join(t.TempDir(), "directory-not-jsonl")
	if err := os.Mkdir(unreadable, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(unreadable, segments[0]); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(t.TempDir(), "export.ndjson")
	const sentinel = "existing export\n"
	if err := os.WriteFile(outPath, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := run(t, "inspect", "export", "--data-dir", dir, "--out", outPath, "--verify")
	if code != 1 || !strings.Contains(stderr, "read segment") {
		t.Fatalf("exit = %d, want 1 with segment read error; stderr=%q", code, stderr)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != sentinel {
		t.Fatalf("segment read failure changed output: %q", got)
	}
}

func TestInspectExportNativeProfileOmittedIsByteCompatible(t *testing.T) {
	dir, env := seedEvidence(t)
	code, out, stderr := run(t, "inspect", "export", "--data-dir", dir, "--out", "-", "--verify")
	if code != 0 {
		t.Fatalf("exit = %d; stderr=%q", code, stderr)
	}
	want, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if out != string(want)+"\n" {
		t.Fatalf("native export changed\n got: %s\nwant: %s", out, want)
	}
}

func TestInspectExportECSProfile(t *testing.T) {
	dir, env := seedEvidence(t)
	code, out, stderr := run(t, "inspect", "export", "--data-dir", dir, "--out", "-", "--profile", "ecs", "--verify", "--json")
	if code != 0 {
		t.Fatalf("exit = %d; stderr=%q", code, stderr)
	}
	var got struct {
		ECS struct {
			Version string `json:"version"`
		} `json:"ecs"`
		Event struct {
			Action string `json:"action"`
			ID     string `json:"id"`
		} `json:"event"`
		Native struct {
			MappingVersion string         `json:"mapping_version"`
			Envelope       event.Envelope `json:"envelope"`
		} `json:"aegismesh"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not JSON: %v (%q)", err, out)
	}
	if got.ECS.Version != "9.4.0" || got.Event.Action != env.Classification || got.Event.ID != env.ID {
		t.Fatalf("unexpected mapping: %+v", got)
	}
	if got.Native.MappingVersion != "aegismesh.ecs/v1" || got.Native.Envelope.ID != env.ID {
		t.Fatalf("native envelope not preserved: %+v", got.Native)
	}
}

func TestInspectExportProfileUsageErrorsDoNotTouchOutput(t *testing.T) {
	dir, _ := seedEvidence(t)
	tests := []struct {
		name string
		args []string
	}{
		{"explicit empty", []string{"--profile="}},
		{"separate empty", []string{"--profile", ""}},
		{"whitespace", []string{"--profile", "   "}},
		{"padded", []string{"--profile", " ecs "}},
		{"repeated", []string{"--profile", "ecs", "--profile", "ecs"}},
		{"repeated different", []string{"--profile", "ecs", "--profile", "native"}},
		{"comma separated", []string{"--profile", "ecs,native"}},
		{"unknown", []string{"--profile", "native"}},
		{"missing value", []string{"--profile"}},
		{"unexpected limit", []string{"--limit", "1"}},
		{"unexpected positional", []string{"extra"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			outPath := filepath.Join(t.TempDir(), "export.ndjson")
			const sentinel = "existing export\n"
			if err := os.WriteFile(outPath, []byte(sentinel), 0o600); err != nil {
				t.Fatal(err)
			}
			args := append([]string{"inspect", "export", "--data-dir", dir, "--out", outPath}, tc.args...)
			code, _, stderr := run(t, args...)
			if code != 2 {
				t.Fatalf("exit = %d, want 2; stderr=%q", code, stderr)
			}
			got, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != sentinel {
				t.Fatalf("invalid invocation changed output: %q", got)
			}
		})
	}
}

func TestInspectShowRejectsUnexpectedArguments(t *testing.T) {
	dir, env := seedEvidence(t)
	code, _, stderr := run(t, "inspect", "show", "--data-dir", dir, "--id", env.ID, "unexpected")
	if code != 2 {
		t.Fatalf("exit = %d, want 2; stderr=%q", code, stderr)
	}
}

// appendClassified stores one envelope of the given classification and fails
// the test on any storage error.
func appendClassified(t *testing.T, st *storage.Store, seq *event.Sequencer, class, sensorID, kind, obs string) event.Envelope {
	t.Helper()
	env, err := event.New(seq, "test-instance",
		event.SensorRef{ID: sensorID, Kind: kind, Listen: "127.0.0.1:8081"},
		class, json.RawMessage(obs), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Append(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	return env
}

// seedClassifiedEvidence writes a fixed mixed stream in this order: two
// interaction events, one canary_invocation, one correlation_signal.
func seedClassifiedEvidence(t *testing.T) (string, []event.Envelope) {
	t.Helper()
	dir := t.TempDir()
	st, err := storage.New(storage.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	seq := &event.Sequencer{}
	envs := []event.Envelope{
		appendClassified(t, st, seq, event.ClassificationInteraction, "http-decoy-1", "http", `{"path":"/admin"}`),
		appendClassified(t, st, seq, event.ClassificationCanaryHit, "mcp-canary-1", "mcp", `{"tool":"canary_read"}`),
		appendClassified(t, st, seq, event.ClassificationInteraction, "tcp-decoy-1", "tcp", `{"banner":"login:"}`),
		appendClassified(t, st, seq, event.ClassificationCorrelationSignal, "correlator", "http", `{"signal_id":"COR-001"}`),
	}
	return dir, envs
}

type classifiedRow struct {
	ID             string `json:"id"`
	Classification string `json:"classification"`
	IntegrityOK    *bool  `json:"integrity_ok"`
}

type classifiedList struct {
	Events       []classifiedRow `json:"events"`
	CorruptLines int             `json:"corrupt_lines"`
}

func runListJSON(t *testing.T, dir string, extra ...string) (int, classifiedList) {
	t.Helper()
	args := append([]string{"inspect", "list", "--data-dir", dir, "--json"}, extra...)
	code, out, stderr := run(t, args...)
	if code != 0 {
		t.Fatalf("list %v: exit %d: %s", extra, code, stderr)
	}
	var payload classifiedList
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("not JSON: %v (%q)", err, out)
	}
	return code, payload
}

func ids(rows []classifiedRow) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.ID
	}
	return out
}

func TestInspectListClassificationSubsetsJSON(t *testing.T) {
	dir, envs := seedClassifiedEvidence(t)

	wantAll := []string{envs[0].ID, envs[1].ID, envs[2].ID, envs[3].ID}
	_, got := runListJSON(t, dir)
	if got := ids(got.Events); strings.Join(got, ",") != strings.Join(wantAll, ",") {
		t.Fatalf("unfiltered list changed order/content: %v", got)
	}
	if got.CorruptLines != 0 {
		t.Fatalf("unexpected corrupt count %d", got.CorruptLines)
	}

	for _, tc := range []struct {
		class string
		want  []string
	}{
		{event.ClassificationInteraction, []string{envs[0].ID, envs[2].ID}},
		{event.ClassificationCanaryHit, []string{envs[1].ID}},
		{event.ClassificationCorrelationSignal, []string{envs[3].ID}},
	} {
		_, payload := runListJSON(t, dir, "--classification", tc.class)
		if got := ids(payload.Events); strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Fatalf("%s: rows = %v, want %v (order preserved)", tc.class, got, tc.want)
		}
		for _, r := range payload.Events {
			if r.Classification != tc.class {
				t.Fatalf("%s: leaked row class %q", tc.class, r.Classification)
			}
		}
	}
}

func TestInspectListClassificationTextOutput(t *testing.T) {
	dir, envs := seedClassifiedEvidence(t)

	code, out, _ := run(t, "inspect", "list", "--data-dir", dir,
		"--classification", event.ClassificationCorrelationSignal)
	if code != 0 {
		t.Fatal(code)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 || strings.Join(strings.Fields(lines[0]), "|") != "TIME|ID|CLASS|SENSOR|KIND" {
		t.Fatalf("header changed: %q", out)
	}
	if !strings.Contains(lines[1], short(envs[3].ID)) ||
		strings.Contains(out, short(envs[0].ID)) || strings.Contains(out, short(envs[1].ID)) {
		t.Fatalf("expected only the signal row: %q", out)
	}
	if strings.Contains(out, "INTEGRITY") {
		t.Fatalf("--verify off must not add INTEGRITY column: %q", out)
	}

	code, out, _ = run(t, "inspect", "list", "--data-dir", dir,
		"--classification", event.ClassificationCanaryHit)
	if code != 0 || !strings.Contains(out, short(envs[1].ID)) || strings.Contains(out, short(envs[3].ID)) {
		t.Fatalf("canary text filter wrong: code=%d out=%q", code, out)
	}
}

// The seed interleaves classes: raw-first-2 would be interaction+canary, so
// two interaction rows under --limit 2 prove the filter runs before the limit.
func TestInspectListClassificationBeforeLimit(t *testing.T) {
	dir, envs := seedClassifiedEvidence(t)

	_, payload := runListJSON(t, dir, "--classification", event.ClassificationInteraction, "--limit", "2")
	got := ids(payload.Events)
	if len(got) != 2 || got[0] != envs[0].ID || got[1] != envs[2].ID {
		t.Fatalf("filter must precede limit; got %v", got)
	}

	_, payload = runListJSON(t, dir, "--classification", event.ClassificationCorrelationSignal, "--limit", "3")
	if n := len(payload.Events); n != 1 || payload.Events[0].ID != envs[3].ID {
		t.Fatalf("limit must still cap matches; got %d rows", n)
	}
}

func TestInspectListClassificationNoMatches(t *testing.T) {
	dir, _ := seedEvidence(t) // interaction-only store

	_, payload := runListJSON(t, dir, "--classification", event.ClassificationCorrelationSignal)
	if len(payload.Events) != 0 || payload.CorruptLines != 0 {
		t.Fatalf("expected empty result, got %+v", payload)
	}
	code, out, _ := run(t, "inspect", "list", "--data-dir", dir, "--classification", event.ClassificationCanaryHit)
	if code != 0 || !strings.Contains(out, "no events recorded yet") {
		t.Fatalf("no-match text output changed: code=%d out=%q", code, out)
	}
}

// Corruption is counted while scanning, independently of which rows match.
func TestInspectListClassificationCorruptAccounting(t *testing.T) {
	dir, _ := seedClassifiedEvidence(t)
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	f, err := os.OpenFile(files[0], os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("{broken json\n")
	f.Close()

	_, payload := runListJSON(t, dir, "--classification", event.ClassificationCorrelationSignal)
	if len(payload.Events) != 1 || payload.CorruptLines != 1 {
		t.Fatalf("signal filter: events=%d corrupt=%d", len(payload.Events), payload.CorruptLines)
	}
	_, payload = runListJSON(t, dir, "--classification", event.ClassificationInteraction)
	if len(payload.Events) != 2 || payload.CorruptLines != 1 {
		t.Fatalf("interaction filter: events=%d corrupt=%d", len(payload.Events), payload.CorruptLines)
	}
}

func TestInspectListClassificationVerifyAccurate(t *testing.T) {
	dir, envs := seedClassifiedEvidence(t)

	// A hand-written canary envelope whose stored hash does not match its
	// payload: --verify must flag exactly this row through the filter.
	tampered := event.Envelope{
		Schema:         event.SchemaV1,
		ID:             strings.Repeat("ab", 16),
		Time:           time.Now().UTC(),
		Instance:       "test-instance",
		Sensor:         event.SensorRef{ID: "tampered-canary", Kind: "mcp", Listen: "127.0.0.1:8090"},
		Classification: event.ClassificationCanaryHit,
		Integrity:      event.Integrity{PayloadSHA256: strings.Repeat("cd", 32), Algorithm: "sha256"},
		Observation:    json.RawMessage(`{"tool":"canary_write"}`),
	}
	line, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	f, err := os.OpenFile(files[0], os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(append(line, '\n'))
	f.Close()

	_, payload := runListJSON(t, dir, "--classification", event.ClassificationCanaryHit, "--verify")
	if len(payload.Events) != 2 {
		t.Fatalf("want both canary rows, got %d", len(payload.Events))
	}
	byID := map[string]*bool{}
	for _, r := range payload.Events {
		byID[r.ID] = r.IntegrityOK
	}
	if ok := byID[envs[1].ID]; ok == nil || !*ok {
		t.Fatalf("untampered event must verify true: %+v", byID)
	}
	if ok := byID[tampered.ID]; ok == nil || *ok {
		t.Fatalf("tampered event must verify false: %+v", byID)
	}

	code, out, _ := run(t, "inspect", "list", "--data-dir", dir,
		"--classification", event.ClassificationCanaryHit, "--verify")
	if code != 0 || !strings.Contains(out, "INTEGRITY") || !strings.Contains(out, "false") {
		t.Fatalf("text --verify output wrong: code=%d out=%q", code, out)
	}
}

func TestInspectListClassificationUsageErrors(t *testing.T) {
	dir, _ := seedClassifiedEvidence(t)
	accepted := "interaction|canary_invocation|correlation_signal"
	cases := []struct {
		name       string
		args       []string
		wantValues bool // classification-value errors must list accepted values
	}{
		{"unknown value", []string{"--classification", "bogus"}, true},
		{"explicit empty via equals", []string{"--classification="}, true},
		{"explicit empty via separate arg", []string{"--classification", ""}, true},
		{"whitespace-only value", []string{"--classification", " "}, true},
		{"padded value", []string{"--classification", " correlation_signal "}, true},
		{"comma-separated value", []string{"--classification", "interaction,correlation_signal"}, true},
		{"repeated identical", []string{"--classification", "interaction", "--classification", "interaction"}, true},
		{"repeated different", []string{"--classification", "interaction", "--classification", "correlation_signal"}, true},
		{"missing value", []string{"--classification"}, false},
		{"positional junk", []string{"junk"}, false},
		{"positional after flags", []string{"--classification", "interaction", "junk"}, false},
		{"unknown flag", []string{"--bogus"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"inspect", "list", "--data-dir", dir}, tc.args...)
			code, _, stderr := run(t, args...)
			if code != 2 {
				t.Fatalf("exit = %d, want 2 (stderr %q)", code, stderr)
			}
			if !strings.Contains(stderr, "usage:") {
				t.Fatalf("must render usage context: %q", stderr)
			}
			if tc.wantValues && !strings.Contains(stderr, accepted) {
				t.Fatalf("must list accepted values %q deterministically: %q", accepted, stderr)
			}
		})
	}
}
