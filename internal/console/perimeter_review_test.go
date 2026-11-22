package console_test

import (
	"strings"
	"testing"
)

func TestBearerFailuresAreRateLimited(t *testing.T) {
	h := newConsoleHarness(t, nil)
	for i := 0; i < 10; i++ {
		requireStatus(t, h.request(t, apiRequest{
			method: "GET",
			path:   "/api/v1/overview",
			token:  "invalid-synthetic",
		}), 401)
	}
	response := h.request(t, apiRequest{
		method: "GET",
		path:   "/api/v1/overview",
		token:  "invalid-synthetic",
	})
	requireStatus(t, response, 429)
	if response.header.Get("Retry-After") == "" || response.header.Get("Cache-Control") != "no-store" {
		t.Fatal(response.header)
	}
	h.clock.advance(61e9)
	requireStatus(t, h.request(t, apiRequest{
		method: "GET",
		path:   "/api/v1/overview",
		token:  "synthetic-viewer",
	}), 200)
}

func TestRawEventReadRequiresAuditBeforeDisclosure(t *testing.T) {
	h := newConsoleHarness(t, nil)
	h.server.CloseAuditForTest()
	response := h.request(t, apiRequest{
		method: "GET",
		path:   "/api/v1/events/" + h.eventID,
		token:  "synthetic-viewer",
	})
	requireStatus(t, response, 503)
	if strings.Contains(string(response.body), `"envelope"`) {
		t.Fatal("raw evidence disclosed without audit")
	}
}
