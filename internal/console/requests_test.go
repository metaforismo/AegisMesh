package console_test

import (
	"strings"
	"testing"
)

func TestBodyValidation(t *testing.T) {
	harness := newConsoleHarness(t, nil)
	cases := []struct {
		name        string
		method      string
		body        string
		contentType string
	}{
		{
			name:   "64 KiB plus one",
			method: "POST",
			body:   `{"title":"x"}` + strings.Repeat(" ", (64<<10)+1-len(`{"title":"x"}`)),
		},
		{
			name:   "unknown field",
			method: "POST",
			body:   `{"title":"x","unknown":1}`,
		},
		{
			name:   "duplicate key",
			method: "POST",
			body:   `{"title":"x","title":"y"}`,
		},
		{
			name:   "nested duplicate",
			method: "POST",
			body:   `{"title":"x","unknown":{"a":1,"a":2}}`,
		},
		{
			name:   "trailing data",
			method: "POST",
			body:   `{"title":"x"} {}`,
		},
		{
			name:        "wrong content type",
			method:      "POST",
			body:        `{"title":"x"}`,
			contentType: "text/plain",
		},
		{
			name:   "null",
			method: "POST",
			body:   `null`,
		},
		{
			name:   "get body",
			method: "GET",
			body:   `{}`,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.name == "64 KiB plus one" && len(testCase.body) != (64<<10)+1 {
				t.Fatalf("body limit fixture = %d bytes", len(testCase.body))
			}
			requireStatus(t, harness.request(t, apiRequest{
				method:      testCase.method,
				path:        "/api/v1/investigations",
				token:       "synthetic-admin",
				body:        testCase.body,
				contentType: testCase.contentType,
			}), 400)
		})
	}
}

func TestExactly64KiBBody(t *testing.T) {
	harness := newConsoleHarness(t, nil)
	const object = `{"title":"Within byte budget"}`
	body := object + strings.Repeat(" ", (64<<10)-len(object))
	requireStatus(t, harness.request(t, apiRequest{
		method: "POST",
		path:   "/api/v1/investigations",
		token:  "synthetic-admin",
		body:   body,
	}), 201)
}

func TestInvalidQueries(t *testing.T) {
	harness := newConsoleHarness(t, nil)
	for _, path := range []string{
		"/api/v1/events?limit=201",
		"/api/v1/events?unknown=x",
		"/api/v1/events?source=a&source=b",
		"/api/v1/node?typo=1",
		"/api/v1/sources?window=nope",
	} {
		t.Run(path, func(t *testing.T) {
			requireStatus(t, harness.request(t, apiRequest{
				method: "GET",
				path:   path,
				token:  "synthetic-admin",
			}), 400)
		})
	}
}

func TestForwardingReadAuthorizationMatrix(t *testing.T) {
	harness := newConsoleHarness(t, nil)
	for _, path := range []string{
		"/api/v1/events?node=local",
		"/api/v1/events/" + harness.eventID + "?node=local",
		"/api/v1/events/stream?node=local",
		"/api/v1/overview",
		"/api/v1/fleet",
		"/api/v1/fleet/nodes",
	} {
		for _, role := range []string{"none", "viewer", "analyst", "admin"} {
			t.Run(path+"/"+role, func(t *testing.T) {
				token := ""
				want := 401
				if role != "none" {
					token = "synthetic-" + role
					want = 200
					if path == "/api/v1/fleet/nodes" {
						want = 503
					}
				}
				requireStatus(t, harness.request(t, apiRequest{method: "GET", path: path, token: token}), want)
			})
		}
	}
}
