package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/storage"
)

// newTestApp mirrors cmd/aegismesh wiring but captures output in buffers.
// An optional first argument injects the Env stdin stream for commands that
// consume it; omitting it leaves Stdin nil exactly like a non-wired process.
func newTestApp(stdin ...io.Reader) (*App, *bytes.Buffer, *bytes.Buffer) {
	var out, errB bytes.Buffer
	env := &Env{Out: &out, Err: &errB}
	if len(stdin) > 0 {
		env.Stdin = stdin[0]
	}
	app := NewApp("aegismesh", "local-first deception, detection, and evidence", &out, &errB)
	must(app.Register(
		NewInitCmd(env),
		NewDoctorCmd(env),
		NewValidateCmd(env),
		NewRunCmd(env),
		NewDemoCmd(env),
		NewInspectCmd(env),
		NewRecommendCmd(env),
		NewRulesCmd(env),
		NewMigrateCmd(env),
		NewExtCmd(env),
		NewVersionCmd(env),
		NewCompletionCmd(env),
	))
	return app, &out, &errB
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	app, out, errB := newTestApp()
	code := app.Run(context.Background(), args)
	return code, out.String(), errB.String()
}

func runWithStdin(t *testing.T, stdin io.Reader, args ...string) (int, string, string) {
	t.Helper()
	app, out, errB := newTestApp(stdin)
	code := app.Run(context.Background(), args)
	return code, out.String(), errB.String()
}

func scaffoldWorkspace(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	code, _, stderr := run(t, "init", "--dir", dir)
	if code != 0 {
		t.Fatalf("init failed: %s", stderr)
	}
	return dir
}

func TestAppExitCodesAndUsage(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no args", nil, 2},
		{"unknown command", []string{"frobnicate"}, 2},
		{"help", []string{"help"}, 0},
		{"version ok", []string{"version"}, 0},
		{"completion bad shell", []string{"completion", "tcsh"}, 2},
		{"validate missing config", []string{"validate", "--config", "/nonexistent/mesh.yaml"}, 1},
		{"inspect show without id", []string{"inspect", "show", "--data-dir", t.TempDir()}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, _ := run(t, tc.args...)
			if code != tc.want {
				t.Fatalf("args %v: exit = %d, want %d", tc.args, code, tc.want)
			}
		})
	}
}

func TestInitCreatesWorkspaceAndRefusesClobber(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ws")
	code, out, _ := run(t, "init", "--dir", dir)
	if code != 0 {
		t.Fatalf("init exit %d", code)
	}
	for _, f := range []string{"mesh.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("missing %s: %v", f, err)
		}
	}

	code, _, stderr := run(t, "init", "--dir", dir)
	if code == 0 {
		t.Fatal("second init without --force must refuse")
	}
	if !strings.Contains(stderr, "force") && !strings.Contains(stderr, "exist") {
		t.Fatalf("refusal should explain itself: %q", stderr)
	}

	code, _, _ = run(t, "init", "--dir", dir, "--force")
	if code != 0 {
		t.Fatal("init --force should overwrite")
	}
	if !strings.Contains(out, "mesh.yaml") {
		t.Fatalf("init output should list created files: %q", out)
	}
}

func TestValidateAcceptsScaffoldRejectsBadConfig(t *testing.T) {
	ws := scaffoldWorkspace(t)

	code, out, _ := run(t, "validate", "--config", filepath.Join(ws, "mesh.yaml"))
	if code != 0 || !strings.Contains(out, "ok") {
		t.Fatalf("scaffolded config must validate: code=%d out=%q", code, out)
	}

	bad := filepath.Join(t.TempDir(), "bad.yaml")
	os.WriteFile(bad, []byte("api_version: aegismesh.io/v1alpha1\nunknown_field: true\n"), 0o600)
	code, _, stderr := run(t, "validate", "--config", bad)
	if code != 1 || !strings.Contains(stderr, "unknown_field") {
		t.Fatalf("strict decode failure must name the field: code=%d err=%q", code, stderr)
	}
}

func TestDoctorReportsChecksHumanAndJSON(t *testing.T) {
	ws := scaffoldWorkspace(t)
	cfg := filepath.Join(ws, "mesh.yaml")

	code, out, _ := run(t, "doctor", "--config", cfg)
	if code != 0 {
		t.Fatalf("doctor failed: %q", out)
	}

	// JSON path via the --json flag:
	var outB, errB strings.Builder
	env := &Env{Out: &outB, Err: &errB}
	app := NewApp("aegismesh", "s", &outB, &errB)
	must(app.Register(NewDoctorCmd(env)))
	code = app.Run(context.Background(), []string{"doctor", "--config", cfg, "--json"})
	if code != 0 {
		t.Fatalf("doctor --json failed: %q", errB.String())
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(outB.String())), &report); err != nil {
		t.Fatalf("doctor --json output is not JSON: %q", outB.String())
	}
	checks, _ := report["checks"].([]any)
	if len(checks) == 0 {
		t.Fatal("doctor report must contain checks")
	}
}

func seedEvidence(t *testing.T) (string, event.Envelope) {
	t.Helper()
	dir := t.TempDir()
	st, err := storage.New(storage.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	seq := &event.Sequencer{}
	env, err := event.New(seq, "test-instance",
		event.SensorRef{ID: "http-decoy-1", Kind: "http", Listen: "127.0.0.1:8081"},
		event.ClassificationInteraction,
		json.RawMessage(`{"path":"/admin/login"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Append(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, env
}

func TestInspectListShowExportRoundTrip(t *testing.T) {
	dir, env := seedEvidence(t)

	code, out, _ := run(t, "inspect", "list", "--data-dir", dir, "--verify")
	if code != 0 || !strings.Contains(out, env.ID[:8]) || !strings.Contains(out, "true") {
		t.Fatalf("list output wrong: %q", out)
	}

	code, out, _ = run(t, "inspect", "list", "--data-dir", dir, "--json")
	if code != 0 {
		t.Fatal(code)
	}
	var payload struct {
		Events       []map[string]any `json:"events"`
		CorruptLines int              `json:"corrupt_lines"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("--json not valid JSON: %q", out)
	}
	if len(payload.Events) != 1 || payload.CorruptLines != 0 {
		t.Fatalf("json list wrong: %+v", payload)
	}

	code, out, _ = run(t, "inspect", "show", "--data-dir", dir, "--id", env.ID[:12])
	if code != 0 || !strings.Contains(out, "http-decoy-1") {
		t.Fatalf("show with id prefix failed: %q", out)
	}

	exportPath := filepath.Join(t.TempDir(), "export.ndjson")
	code, _, stderr := run(t, "inspect", "export", "--data-dir", dir, "--out", exportPath, "--verify")
	if code != 0 {
		t.Fatalf("export failed: %s", stderr)
	}
	raw, _ := os.ReadFile(exportPath)
	if !strings.Contains(string(raw), env.ID) {
		t.Fatal("exported file missing the event")
	}
}

func TestInspectFlagsCorruptEvidence(t *testing.T) {
	dir, env := seedEvidence(t)
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if len(files) == 0 {
		t.Fatal("no evidence file created by store")
	}
	f, err := os.OpenFile(files[0], os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("{broken json\n")
	f.Close()

	code, out, _ := run(t, "inspect", "list", "--data-dir", dir, "--json")
	if code != 0 {
		t.Fatal(code)
	}
	var payload struct {
		CorruptLines int `json:"corrupt_lines"`
	}
	json.Unmarshal([]byte(out), &payload)
	if payload.CorruptLines != 1 {
		t.Fatalf("corrupt line must be counted, got %d (%q)", payload.CorruptLines, out)
	}

	_ = env
}

func TestMigrateDryRunDefaultAndWrite(t *testing.T) {
	src := filepath.Join(t.TempDir(), "beelzebub-http.yaml")
	os.WriteFile(src, []byte("protocol: http\naddress: ':8080'\ncommands:\n  - regex: '^/x$'\n    handler: 'hi'\n"), 0o600)

	outDir := filepath.Join(t.TempDir(), "migrated")

	// Default is dry-run: no files may appear.
	code, out, _ := run(t, "migrate", "beelzebub", src, "--out", outDir)
	if code != 0 {
		t.Fatalf("migrate failed: %q", out)
	}
	if entries, _ := os.ReadDir(outDir); len(entries) != 0 {
		t.Fatal("dry-run must not write files")
	}
	if !strings.Contains(out, "listen") || !strings.Contains(out, "127.0.0.1") {
		t.Fatalf("dry-run report should show the translation: %q", out)
	}

	code, _, _ = run(t, "migrate", "beelzebub", src, "--out", outDir, "--write")
	if code != 0 {
		t.Fatal("migrate --write failed")
	}
	generated := filepath.Join(outDir, "beelzebub-http.aegismesh.yaml")
	if _, err := os.Stat(generated); err != nil {
		t.Fatalf("generated file missing: %v", err)
	}

	// Second write without --force refuses to clobber.
	code, _, stderr := run(t, "migrate", "beelzebub", src, "--out", outDir, "--write")
	if code == 0 || !strings.Contains(stderr+out, "force") {
		t.Fatalf("overwrite requires --force: code=%d", code)
	}
}

func TestExtVerifyDigestMatchAndMismatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping go build in -short mode")
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "ext")
	build := exec.Command("go", "build", "-o", exe, "../../examples/extensions/echo-responder")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build example extension: %v\n%s", err, b)
	}
	sum := sha256.Sum256(readFile(t, exe))

	manifest := filepath.Join(dir, "manifest.json")
	writeManifestFile(t, manifest, fmt.Sprintf(`{
	  "api_version": "ext.aegismesh.io/v1alpha1",
	  "name": "echo-responder",
	  "version": "0.1.0",
	  "permissions": ["observe"],
	  "transport": {"kind":"subprocess-ndjson","command":["./ext"],
	                "handshake_timeout_ms":5000,"call_timeout_ms":5000,"max_output_bytes":1048576},
	  "digest": {"algorithm":"sha256","value":"%s"}
	}`, hex.EncodeToString(sum[:])))

	code, out, _ := run(t, "ext", "verify", "--manifest", manifest)
	if code != 0 || !strings.Contains(out, "verified") {
		t.Fatalf("digest match must verify: code=%d out=%q", code, out)
	}
	code, out, stderr := run(t, "ext", "run", "--manifest", manifest, "--input", `{"synthetic":true}`)
	if code != 0 || !strings.Contains(out, `"accepted": true`) || !strings.Contains(out, `"applied": false`) || strings.Contains(out, `"result"`) {
		t.Fatalf("observe probe must return only core-owned non-applied metadata: code=%d out=%q err=%q", code, out, stderr)
	}
	code, out, stderr = run(t, "ext", "run", "--manifest", manifest)
	wantJSON := "{\n  \"accepted\": true,\n  \"applied\": false,\n  \"event_id\": \"extension-probe\",\n  \"extension\": \"echo-responder\",\n  \"version\": \"0.1.0\"\n}\n"
	if code != 0 || out != wantJSON {
		t.Fatalf("omitted input must run the deterministic default probe: code=%d out=%q err=%q", code, out, stderr)
	}
	for _, input := range []string{`null`, `true`, `[]`, `"synthetic"`} {
		code, out, stderr = run(t, "ext", "run", "--manifest", manifest, "--input", input)
		if code != 0 || out != wantJSON {
			t.Fatalf("valid JSON value %s rejected: code=%d out=%q err=%q", input, code, out, stderr)
		}
	}

	corrupt := append(readFile(t, exe), '\n')
	replacement := filepath.Join(dir, "corrupt-ext")
	if err := os.WriteFile(replacement, corrupt, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, exe); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = run(t, "ext", "verify", "--manifest", manifest)
	if code == 0 || !strings.Contains(stderr, "mismatch") {
		t.Fatalf("modified artifact must fail verification: code=%d err=%q", code, stderr)
	}
}

func TestExtCLIStrictFlags(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"manifest omitted", []string{"ext", "verify"}, "--manifest is required"},
		{"manifest empty", []string{"ext", "verify", "--manifest="}, "must be one non-empty path"},
		{"manifest whitespace", []string{"ext", "verify", "--manifest", "  "}, "must be one non-empty path"},
		{"manifest padded", []string{"ext", "verify", "--manifest", " manifest.json "}, "must be one non-empty path"},
		{"manifest repeated", []string{"ext", "verify", "--manifest", "a", "--manifest", "b"}, "flag given more than once"},
		{"manifest comma", []string{"ext", "verify", "--manifest", "a,b"}, "must be one non-empty path"},
		{"manifest leading dash", []string{"ext", "verify", "--manifest=-a"}, "leading '-"},
		{"delimiter positional", []string{"ext", "verify", "--manifest", "a", "--", "extra"}, "unexpected argument"},
		{"unexpected positional", []string{"ext", "verify", "--manifest", "a", "extra"}, "unexpected argument"},
		{"unknown flag", []string{"ext", "verify", "--manifest", "a", "--unknown"}, "flag provided but not defined"},
		{"input empty", []string{"ext", "run", "--manifest", "a", "--input="}, "--input must not be empty"},
		{"input whitespace", []string{"ext", "run", "--manifest", "a", "--input", "  "}, "--input must not be empty"},
		{"input malformed", []string{"ext", "run", "--manifest", "a", "--input", "{"}, "--input must be one valid JSON value"},
		{"input repeated", []string{"ext", "run", "--manifest", "a", "--input", `{}`, "--input", `{}`}, "flag given more than once"},
		{"pubkey empty", []string{"ext", "verify", "--manifest", "a", "--pubkey="}, "must be one non-empty path"},
		{"pubkey whitespace", []string{"ext", "verify", "--manifest", "a", "--pubkey", "  "}, "must be one non-empty path"},
		{"pubkey padded", []string{"ext", "verify", "--manifest", "a", "--pubkey", " key.hex "}, "must be one non-empty path"},
		{"pubkey comma", []string{"ext", "verify", "--manifest", "a", "--pubkey", "a,b"}, "must be one non-empty path"},
		{"pubkey repeated", []string{"ext", "verify", "--manifest", "a", "--pubkey", "a", "--pubkey", "b"}, "flag given more than once"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := run(t, tc.args...)
			if code == 0 || !strings.Contains(stderr, tc.want) {
				t.Fatalf("code=%d stderr=%q, want error containing %q", code, stderr, tc.want)
			}
		})
	}

	code, _, stderr := run(t, "ext", "run", "--manifest", "missing.json", "--input", ` {"padded":true} `)
	if code == 0 || strings.Contains(stderr, "--input") || !strings.Contains(stderr, "missing.json") {
		t.Fatalf("padded valid JSON must pass input validation: code=%d stderr=%q", code, stderr)
	}
}

func TestExtensionPublicKeyFileBounds(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "valid.hex")
	if err := os.WriteFile(valid, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readExtensionPublicKey(valid)
	if err != nil || got != strings.Repeat("a", 64) {
		t.Fatalf("valid public key file: got=%q err=%v", got, err)
	}
	if _, err := readExtensionPublicKey(dir); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory public key must fail, got %v", err)
	}
	over := filepath.Join(dir, "oversized.hex")
	f, err := os.OpenFile(over, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxExtensionPublicKeyFileBytes + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readExtensionPublicKey(over); err == nil || !strings.Contains(err.Error(), "no larger") {
		t.Fatalf("oversized public key must fail, got %v", err)
	}
}

func TestVersionAndCompletionOutputs(t *testing.T) {
	code, out, _ := run(t, "version")
	if code != 0 || len(strings.TrimSpace(out)) == 0 {
		t.Fatal("version must print something")
	}
	for _, shell := range []string{"bash", "zsh", "fish"} {
		code, out, _ = run(t, "completion", shell)
		if code != 0 || len(out) < 40 {
			t.Fatalf("completion %s too small: %q", shell, out)
		}
	}
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeManifestFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
