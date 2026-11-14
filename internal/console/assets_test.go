package console_test

import (
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/console"
)

func TestStaticManifestAndHeaders(t *testing.T) {
	harness := newConsoleHarness(t, nil)
	cases := []struct {
		path        string
		status      int
		contentType string
		cache       string
	}{
		{
			path:        "/",
			status:      200,
			contentType: "text/html",
			cache:       "no-store",
		},
		{
			path:        "/assets/app.js",
			status:      200,
			contentType: "javascript",
			cache:       "public",
		},
		{
			path:        "/assets/style.css",
			status:      200,
			contentType: "text/css",
			cache:       "public",
		},
		{
			path:        "/index.html",
			status:      404,
			contentType: "application/json",
		},
		{
			path:        "/assets/",
			status:      404,
			contentType: "application/json",
		},
		{
			path:        "/missing",
			status:      404,
			contentType: "application/json",
		},
		{
			path:        "/../secret",
			status:      404,
			contentType: "application/json",
		},
		{
			path:        "/assets/../app.js",
			status:      404,
			contentType: "application/json",
		},
		{
			path:        "/%2e%2e/secret",
			status:      404,
			contentType: "application/json",
		},
		{
			path:        "/nested/",
			status:      404,
			contentType: "application/json",
		},
		{
			path:        "/nested/index.html",
			status:      404,
			contentType: "application/json",
		},
		{
			path:        "/api/v1/session",
			status:      401,
			contentType: "application/json",
			cache:       "no-store",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.path, func(t *testing.T) {
			response := harness.request(t, apiRequest{
				method: "GET",
				path:   testCase.path,
			})
			requireStatus(t, response, testCase.status)
			if !strings.Contains(response.header.Get("Content-Type"), testCase.contentType) {
				t.Fatalf("content type: %v", response.header)
			}
			if !strings.Contains(response.header.Get("Cache-Control"), testCase.cache) {
				t.Fatalf("cache policy: %v", response.header)
			}
			for header, want := range map[string]string{
				"Content-Security-Policy": console.CSP,
				"Referrer-Policy":         "no-referrer",
				"X-Content-Type-Options":  "nosniff",
				"X-Frame-Options":         "DENY",
			} {
				if response.header.Get(header) != want {
					t.Fatalf("%s = %q", header, response.header.Get(header))
				}
			}
		})
	}
}
