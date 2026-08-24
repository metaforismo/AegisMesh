package runtime

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/sensor"
)

func TestSystemEndpointsAreLoopbackAndConfiguredOrder(t *testing.T) {
	sys, err := Build(testConfig(t), quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer sys.Stop(context.Background())

	if _, err := sys.Endpoints(); err == nil || !errors.Is(err, errRuntime) {
		t.Fatalf("pre-start endpoint discovery error = %v, want runtime error", err)
	}
	if err := sys.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	adminAddr, err := sys.AdminAddr()
	if err != nil {
		t.Fatal(err)
	}
	adminConn, err := net.DialTimeout("tcp", adminAddr, time.Second)
	if err != nil {
		t.Fatalf("dial admin endpoint %q: %v", adminAddr, err)
	}
	_ = adminConn.Close()

	got, err := sys.Endpoints()
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		id   string
		kind string
	}{
		{"http-decoy", "http"},
		{"tcp-decoy", "tcp"},
		{"mcp-decoy", "mcp"},
		{"ssh-decoy", "ssh"},
	}
	if len(got) != len(want) {
		t.Fatalf("endpoint count = %d, want %d: %+v", len(got), len(want), got)
	}
	for i, endpoint := range got {
		if endpoint.ID != want[i].id || endpoint.Kind != want[i].kind {
			t.Fatalf("endpoint %d = %+v, want %s/%s", i, endpoint, want[i].id, want[i].kind)
		}
		host, _, err := net.SplitHostPort(endpoint.Addr)
		if err != nil || host != "127.0.0.1" {
			t.Fatalf("endpoint %q is not a loopback host: %v", endpoint.Addr, err)
		}
		conn, err := net.DialTimeout("tcp", endpoint.Addr, time.Second)
		if err != nil {
			t.Fatalf("dial %s endpoint %q: %v", endpoint.ID, endpoint.Addr, err)
		}
		_ = conn.Close()
	}
}

func TestSystemEndpointsReturnFreshCopiesAndDisappearAfterStop(t *testing.T) {
	sys, err := Build(testConfig(t), quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := sys.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer sys.Stop(context.Background())

	first, err := sys.Endpoints()
	if err != nil {
		t.Fatal(err)
	}
	original := first[0]
	first[0] = Endpoint{ID: "changed", Kind: "changed", Addr: "127.0.0.1:1"}
	first = append(first, Endpoint{ID: "extra"})
	second, err := sys.Endpoints()
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 4 || second[0] != original {
		t.Fatalf("endpoint discovery did not return a fresh copy: first=%+v second=%+v", first, second)
	}

	sys.Stop(context.Background())
	if _, err := sys.Endpoints(); err == nil || !strings.Contains(err.Error(), "after stop") {
		t.Fatalf("post-stop endpoint discovery error = %v, want stale-address refusal", err)
	}
	if _, err := sys.AdminAddr(); err == nil || !strings.Contains(err.Error(), "stopped") {
		t.Fatalf("post-stop admin discovery error = %v, want stale-address refusal", err)
	}
}

func TestSystemAdminAddrDisabled(t *testing.T) {
	cfg := testConfig(t)
	disabled := false
	cfg.Admin.Enabled = &disabled
	sys, err := Build(cfg, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	sys.Stop(context.Background())
	addr, err := sys.AdminAddr()
	if err == nil || addr != "" || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("disabled admin discovery = %q, %v; want actionable disabled error", addr, err)
	}
}

func TestSystemEndpointsRejectSensorWithoutAddress(t *testing.T) {
	sys := &System{
		sensors: []sensor.Sensor{endpointTestSensor{id: "no-address", kind: "test"}},
	}
	sys.started.Store(1)

	if _, err := sys.Endpoints(); err == nil || !strings.Contains(err.Error(), "does not expose a bound address") {
		t.Fatalf("address-less sensor discovery = %v, want actionable failure", err)
	}
}

type endpointTestSensor struct {
	id   string
	kind string
}

func (s endpointTestSensor) ID() string                             { return s.id }
func (s endpointTestSensor) Kind() string                           { return s.kind }
func (endpointTestSensor) Start(context.Context, sensor.Deps) error { return nil }
func (endpointTestSensor) Done() <-chan error                       { return nil }
func (endpointTestSensor) Close(context.Context) error              { return nil }
