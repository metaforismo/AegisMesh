package console_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/console"
	"github.com/metaforismo/aegismesh/internal/event"
)

func TestCursorIsolation(t *testing.T) {
	harness := newConsoleHarness(t, func(opts *console.Options) {
		for sequence := range 3 {
			envelope, err := event.New(
				&event.Sequencer{}, fmt.Sprint(sequence), event.SensorRef{
					ID:   "web",
					Kind: "http",
				}, "interaction",
				json.RawMessage(`{"remote_host":"127.0.0.1"}`), nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			opts.Index.Add(envelope)
		}
	})
	harness.login(t, nil)
	harness.login(t, nil)
	cursors := map[string]string{}
	for _, endpoint := range []string{
		"/api/v1/events",
		"/api/v1/audit",
		"/api/v1/sources/127.0.0.1",
	} {
		response := harness.request(t, apiRequest{
			method: "GET",
			path:   endpoint + "?limit=1",
			token:  "synthetic-admin",
		})
		requireStatus(t, response, 200)
		var page struct {
			Cursor string `json:"next_cursor"`
		}
		if err := json.Unmarshal(response.body, &page); err != nil {
			t.Fatal(err)
		}
		if page.Cursor == "" {
			t.Fatalf("no cursor for %s", endpoint)
		}
		cursors[endpoint] = page.Cursor
	}
	for endpoint, cursor := range cursors {
		for _, change := range []string{
			"tampered",
			"truncated",
			"cross endpoint",
		} {
			t.Run(endpoint+"/"+change, func(t *testing.T) {
				invalid := cursor
				switch change {
				case "tampered":
					prefix := "A"
					if strings.HasPrefix(invalid, prefix) {
						prefix = "B"
					}
					invalid = prefix + invalid[1:]
				case "truncated":
					invalid = invalid[:len(invalid)/2]
				case "cross endpoint":
					if endpoint == "/api/v1/audit" {
						invalid = cursors["/api/v1/events"]
					} else {
						invalid = cursors["/api/v1/audit"]
					}
				}
				requireStatus(t, harness.request(t, apiRequest{
					method: "GET",
					path:   endpoint + "?limit=1&cursor=" + invalid,
					token:  "synthetic-admin",
				}), 400)
			})
		}
	}
	// Source cursors carry their source filter and cannot be reused for the unfiltered events endpoint.
	requireStatus(t, harness.request(t, apiRequest{
		method: "GET",
		path:   "/api/v1/events?cursor=" + cursors["/api/v1/sources/127.0.0.1"],
		token:  "synthetic-admin",
	}), 400)
}

func TestCrossEndpointCursorWithMatchingFilters(t *testing.T) {
	harness := newConsoleHarness(t, func(opts *console.Options) {
		for range 2 {
			envelope, err := event.New(
				&event.Sequencer{}, "synthetic", event.SensorRef{
					ID:   "web",
					Kind: "http",
				}, "interaction",
				json.RawMessage(`{"remote_host":"127.0.0.1"}`), nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			opts.Index.Add(envelope)
		}
	})
	endpoints := []string{
		"/api/v1/events?source=127.0.0.1&limit=1",
		"/api/v1/sources/127.0.0.1?limit=1",
	}
	for index, endpoint := range endpoints {
		response := harness.request(t, apiRequest{
			method: "GET",
			path:   endpoint,
			token:  "synthetic-admin",
		})
		requireStatus(t, response, 200)
		var page struct {
			Cursor string `json:"next_cursor"`
		}
		if err := json.Unmarshal(response.body, &page); err != nil {
			t.Fatal(err)
		}
		if page.Cursor == "" {
			t.Fatal("missing pagination fixture")
		}
		requireStatus(t, harness.request(t, apiRequest{
			method: "GET",
			path:   endpoint + "&cursor=" + page.Cursor,
			token:  "synthetic-admin",
		}), 200)
		requireStatus(t, harness.request(t, apiRequest{
			method: "GET",
			path:   endpoints[1-index] + "&cursor=" + page.Cursor,
			token:  "synthetic-admin",
		}), 400)
	}
}
