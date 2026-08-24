package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/demo"
)

func TestDemoGoldenOutputs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		args   []string
		golden string
	}{
		{name: "human", args: nil, golden: "demo.golden.txt"},
		{name: "json", args: []string{"--json"}, golden: "demo.golden.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, got, stderr := runInjectedDemo(context.Background(), successfulDemo, tc.args...)
			if code != 0 || stderr != "" {
				t.Fatalf("demo failed: code=%d stderr=%q", code, stderr)
			}
			want, err := os.ReadFile(filepath.Join("testdata", tc.golden))
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Fatalf("output drifted from %s:\n--- got ---\n%s\n--- want ---\n%s", tc.golden, got, want)
			}
			code, again, _ := runInjectedDemo(context.Background(), successfulDemo, tc.args...)
			if code != 0 || again != got {
				t.Fatalf("output is not byte-stable:\nfirst=%s\nsecond=%s", got, again)
			}
		})
	}
}

func TestDemoStrictArgumentMatrix(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "explicit empty", args: []string{"--json="}},
		{name: "whitespace", args: []string{"--json", " "}},
		{name: "padded value", args: []string{"--json= true "}},
		{name: "repeated", args: []string{"--json", "--json"}},
		{name: "comma", args: []string{"--json=true,false"}},
		{name: "invalid boolean", args: []string{"--json=maybe"}},
		{name: "unknown", args: []string{"--unknown"}},
		{name: "positional", args: []string{"unexpected"}},
		{name: "separator positional", args: []string{"--", "unexpected"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			code, stdout, stderr := runInjectedDemo(context.Background(), func(context.Context) (demo.Summary, error) {
				called = true
				return successfulDemo(context.Background())
			}, tc.args...)
			if code != 2 || stdout != "" || stderr == "" || called {
				t.Fatalf("code=%d stdout=%q stderr=%q called=%v", code, stdout, stderr, called)
			}
		})
	}
}

func TestDemoExplicitBooleans(t *testing.T) {
	for _, tc := range []struct {
		arg      string
		wantJSON bool
	}{
		{arg: "--json=true", wantJSON: true},
		{arg: "--json=false", wantJSON: false},
	} {
		code, stdout, stderr := runInjectedDemo(context.Background(), successfulDemo, tc.arg)
		if code != 0 || stderr != "" {
			t.Fatalf("%s failed: code=%d stderr=%q", tc.arg, code, stderr)
		}
		if gotJSON := strings.HasPrefix(stdout, "{"); gotJSON != tc.wantJSON {
			t.Fatalf("%s JSON=%v, want %v", tc.arg, gotJSON, tc.wantJSON)
		}
	}
}

func TestDemoFailureAndCancellationWriteNoStdout(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctx  func() context.Context
		run  func(context.Context) (demo.Summary, error)
	}{
		{name: "late failure", ctx: context.Background, run: func(context.Context) (demo.Summary, error) {
			return demo.Summary{}, errors.New("synthetic failure")
		}},
		{name: "canceled", ctx: canceledContext, run: func(ctx context.Context) (demo.Summary, error) {
			return demo.Summary{}, ctx.Err()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runInjectedDemo(tc.ctx(), tc.run)
			if code != 1 || stdout != "" || stderr == "" {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestDemoCommandEndToEnd(t *testing.T) {
	code, stdout, stderr := run(t, "demo", "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("real demo failed: code=%d stderr=%q", code, stderr)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "demo.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if stdout != string(want) {
		t.Fatalf("real demo output drifted:\n%s", stdout)
	}
}

func runInjectedDemo(ctx context.Context, runner func(context.Context) (demo.Summary, error), args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	env := &Env{Out: &stdout, Err: &stderr}
	app := NewApp("aegismesh", "test", &stdout, &stderr)
	cmd := newDemoCmd(env)
	cmd.run = runner
	must(app.Register(cmd))
	code := app.Run(ctx, append([]string{"demo"}, args...))
	return code, stdout.String(), stderr.String()
}

func successfulDemo(context.Context) (demo.Summary, error) {
	return demo.Summary{
		Schema: "aegismesh.demo/v1", Mode: "synthetic", Network: "loopback-only", Egress: "none",
		Sensors: []string{"http", "tcp", "mcp", "ssh"}, Events: 4, Interactions: 3, CanaryInvocations: 1,
		IntegrityVerified: true, Recommendations: 1, DryRun: true, Enforcement: false,
		SignalNotIncident: true, ListenersReleased: true, CleanupComplete: true,
	}, nil
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
