package console_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/console"
	"github.com/metaforismo/aegismesh/internal/observe"
)

func TestSSECapacityAndShutdown(t *testing.T) {
	var meter *observe.Registry
	harness := newConsoleHarness(t, func(opts *console.Options) {
		meter = opts.Meter.(*observe.Registry)
	})
	var streams []*http.Response
	defer func() {
		for _, stream := range streams {
			stream.Body.Close()
		}
	}()
	for range 16 {
		req, err := http.NewRequest("GET", harness.base+"/api/v1/events/stream", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer synthetic-admin")
		stream, err := harness.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if stream.StatusCode != 200 {
			stream.Body.Close()
			t.Fatalf("stream rejected before cap: %d", stream.StatusCode)
		}
		streams = append(streams, stream)
	}
	requireStatus(t, harness.request(t, apiRequest{
		method: "GET",
		path:   "/api/v1/events/stream",
		token:  "synthetic-admin",
	}), 503)
	if !strings.Contains(meter.WritePrometheus(), "aegismesh_console_sse_clients 16") {
		t.Fatal("SSE gauge missing")
	}
	if err := harness.server.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, stream := range streams {
		if _, err := io.ReadAll(stream.Body); err != nil {
			t.Fatalf("stream did not end at shutdown: %v", err)
		}
	}
}
