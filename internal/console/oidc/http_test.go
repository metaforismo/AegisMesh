package oidc

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/config"
)

func TestProviderHTTPBoundary(t *testing.T) {
	for _, mode := range []string{"oversized", "redirect", "foreign-endpoint"} {
		t.Run(mode, func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "oversized":
					_, _ = io.WriteString(w, strings.Repeat("x", ResponseBytes+1))
				case "redirect":
					http.Redirect(w, r, "http://localhost:1/keys", 302)
				case "foreign-endpoint":
					_, _ = io.WriteString(w, `{"issuer":"`+server.URL+`","authorization_endpoint":"http://localhost:1/auth"}`)
				}
			}))
			defer server.Close()
			cfg := config.OIDC{Issuer: server.URL}
			client, transport, err := providerClient(cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			if transport.base.(*http.Transport).Proxy != nil {
				t.Fatal("proxy enabled")
			}
			if transport.allowed("http://localhost:1/token") || transport.allowed("http://169.254.169.254/token") {
				t.Fatal("provider changed destination")
			}
			request, _ := http.NewRequestWithContext(context.Background(), "GET", server.URL, nil)
			response, err := client.Do(request)
			if response != nil {
				response.Body.Close()
			}
			if mode == "oversized" && err == nil {
				t.Fatal("unbounded response accepted")
			}
			if mode == "redirect" && (err != nil || response.StatusCode != 302) {
				t.Fatal("redirect was followed")
			}
			if mode == "foreign-endpoint" {
				m := &Manager{cfg: cfg, client: client, transport: transport}
				if m.discover(context.Background()) == nil {
					t.Fatal("foreign endpoint accepted")
				}
			}
		})
	}
}
