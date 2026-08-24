package demo

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/runtime"
)

func TestRunEndToEnd(t *testing.T) {
	got, err := Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := expectedSummary()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("summary = %+v, want %+v", got, want)
	}
}

func TestRunParallelIsIsolated(t *testing.T) {
	const runs = 3
	start := make(chan struct{})
	results := make(chan Summary, runs)
	errs := make(chan error, runs)
	var callers sync.WaitGroup
	for i := 0; i < runs; i++ {
		callers.Add(1)
		go func() {
			defer callers.Done()
			<-start
			result, err := Run(context.Background())
			if err != nil {
				errs <- err
				return
			}
			results <- result
		}()
	}
	close(start)
	callers.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	for result := range results {
		if !reflect.DeepEqual(result, expectedSummary()) {
			t.Errorf("parallel summary = %+v", result)
		}
	}
}

func TestRunHonorsPreCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx); err == nil {
		t.Fatal("pre-canceled context must fail before creating the demo")
	}
}

func TestRunCancellationRemovesPrivateWorkspace(t *testing.T) {
	tempRoot := t.TempDir()
	t.Setenv("TMPDIR", tempRoot)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := Run(ctx)
		done <- err
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		entries, err := os.ReadDir(tempRoot)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) > 0 {
			cancel()
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("demo workspace did not appear before the cancellation deadline")
		}
		time.Sleep(time.Millisecond)
	}
	if err := <-done; err == nil {
		t.Fatal("mid-run cancellation must not report success")
	}
	entries, err := os.ReadDir(tempRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("demo left temporary state after cancellation: %v", entries)
	}
}

func TestRequestRejectsRedirectBeforeFollowingLocation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.invalid/egress-must-not-happen", http.StatusFound)
	})}
	go server.Serve(ln)
	t.Cleanup(func() { _ = server.Close() })

	_, _, err = request(context.Background(), http.MethodGet, "http://"+ln.Addr().String(), nil)
	if err == nil || !strings.Contains(err.Error(), "redirects are disabled") {
		t.Fatalf("redirect error = %v", err)
	}
}

func TestRequestRejectsOversizedBody(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("R", maxReplyBytes+1))
	})}
	go server.Serve(ln)
	t.Cleanup(func() { _ = server.Close() })

	_, _, err = request(context.Background(), http.MethodGet, "http://"+ln.Addr().String(), nil)
	if err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("oversized response error = %v", err)
	}
}

func TestInteractTCPRejectsOversizedLines(t *testing.T) {
	for _, tc := range []struct {
		name  string
		serve func(net.Conn)
		want  string
	}{
		{name: "banner", serve: func(conn net.Conn) {
			_, _ = io.WriteString(conn, strings.Repeat("B", maxTCPLineBytes+1)+"\n")
		}, want: "banner"},
		{name: "reply", serve: func(conn net.Conn) {
			_, _ = io.WriteString(conn, "AEGISMESH DEMO\n")
			_, _ = bufio.NewReader(conn).ReadString('\n')
			_, _ = io.WriteString(conn, strings.Repeat("R", maxTCPLineBytes+1)+"\n")
		}, want: "response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := startTCPServer(t, tc.serve)
			err := interactTCP(context.Background(), addr)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func startTCPServer(t *testing.T, serve func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		serve(conn)
	}()
	return ln.Addr().String()
}

func TestValidatedAddressesRejectsUnexpectedOrUnsafeEndpoints(t *testing.T) {
	valid := []runtime.Endpoint{
		{ID: "demo-http", Kind: "http", Addr: "127.0.0.1:20001"},
		{ID: "demo-tcp", Kind: "tcp", Addr: "127.0.0.1:20002"},
		{ID: "demo-mcp", Kind: "mcp", Addr: "127.0.0.1:20003"},
		{ID: "demo-ssh", Kind: "ssh", Addr: "127.0.0.1:20004"},
	}
	if _, err := validatedAddresses(valid); err != nil {
		t.Fatalf("valid endpoints rejected: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func([]runtime.Endpoint)
		want   string
	}{
		{name: "public", mutate: func(e []runtime.Endpoint) { e[0].Addr = "192.0.2.1:20001" }, want: "not an IP loopback"},
		{name: "privileged", mutate: func(e []runtime.Endpoint) { e[0].Addr = "127.0.0.1:22" }, want: "unprivileged"},
		{name: "unassigned", mutate: func(e []runtime.Endpoint) { e[0].Addr = "127.0.0.1:0" }, want: "unprivileged"},
		{name: "wrong order", mutate: func(e []runtime.Endpoint) { e[0], e[1] = e[1], e[0] }, want: "unexpected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			endpoints := append([]runtime.Endpoint(nil), valid...)
			tc.mutate(endpoints)
			_, err := validatedAddresses(endpoints)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func expectedSummary() Summary {
	return Summary{
		Schema:            schema,
		Mode:              "synthetic",
		Network:           "loopback-only",
		Egress:            "none",
		Sensors:           []string{"http", "tcp", "mcp", "ssh"},
		Events:            4,
		Interactions:      3,
		CanaryInvocations: 1,
		IntegrityVerified: true,
		Recommendations:   1,
		DryRun:            true,
		Enforcement:       false,
		SignalNotIncident: true,
		ListenersReleased: true,
		CleanupComplete:   true,
	}
}
