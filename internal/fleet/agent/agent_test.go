package agent_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/fleet/agent"
	"github.com/metaforismo/aegismesh/internal/fleet/hub"
	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
)

func tlsFiles(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Synthetic fleet test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, public, private)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    ca.NotBefore,
		NotAfter:     ca.NotAfter,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, leafPublic, private)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafPrivate)
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{filepath.Join(dir, "ca.pem"), filepath.Join(dir, "leaf.pem"), filepath.Join(dir, "key.pem")}
	blocks := []*pem.Block{
		{
			Type:  "CERTIFICATE",
			Bytes: caDER,
		},
		{
			Type:  "CERTIFICATE",
			Bytes: der,
		},
		{
			Type:  "PRIVATE KEY",
			Bytes: keyDER,
		},
	}
	for i, path := range paths {
		if err := os.WriteFile(path, pem.EncodeToMemory(blocks[i]), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return paths[0], paths[1], paths[2]
}

func options(t *testing.T, url string) agent.Options {
	t.Helper()
	return agent.Options{
		HubURL:   url,
		StateDir: filepath.Join(t.TempDir(), "agent"),
		Name:     "test-node",
		Interval: 10 * time.Second,
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Snapshot: func() protocol.Heartbeat {
			return protocol.Heartbeat{
				Name:           "test-node",
				Sensors:        []protocol.Sensor{},
				StorageHealthy: true,
			}
		},
	}
}

func TestTLSRoundTripAndUntrustedCA(t *testing.T) {
	caFile, certFile, keyFile := tlsFiles(t)
	registry, err := hub.New(hub.Options{StateDir: filepath.Join(t.TempDir(), "hub")})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	server, err := hub.Listen("127.0.0.1:0", certFile, keyFile, registry)
	if err != nil {
		t.Fatal(err)
	}
	server.Start()
	defer server.Close(context.Background())
	token, err := registry.Mint(0, "synthetic")
	if err != nil {
		t.Fatal(err)
	}
	opts := options(t, "https://"+server.Addr())
	opts.Token = token.Token
	reporter, err := agent.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := reporter.Step(context.Background()); err == nil {
		t.Fatal("trusted unknown CA")
	}
	reporter.Close()
	opts.CAFile = caFile
	reporter, err = agent.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer reporter.Close()
	if err := reporter.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	nodes, err := registry.Nodes("online")
	if err != nil || len(nodes) != 1 {
		t.Fatalf("TLS inventory: %v", err)
	}
}

func TestRedirectRefusalAndResponseBounds(t *testing.T) {
	var reached atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		w.WriteHeader(200)
	}))
	defer target.Close()
	for _, mode := range []string{"redirect", "oversized", "forged"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "redirect":
					http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
				case "oversized":
					_, _ = io.WriteString(w, strings.Repeat("x", protocol.MaxBodyBytes+1))
				case "forged":
					_, _ = io.WriteString(w, `{"node_id":"wrong","command":"ignored"}`)
				}
			}))
			defer server.Close()
			reporter, err := agent.New(options(t, server.URL))
			if err != nil {
				t.Fatal(err)
			}
			defer reporter.Close()
			if err := reporter.Step(context.Background()); err == nil {
				t.Fatal("accepted invalid response")
			}
			if reached.Load() != 0 {
				t.Fatal("followed redirect")
			}
		})
	}
}

func TestSafePreflightAndProxyRefusal(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	registry, err := hub.New(hub.Options{StateDir: filepath.Join(t.TempDir(), "hub")})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	server := httptest.NewServer(registry)
	defer server.Close()
	minted, err := registry.Mint(0, "")
	if err != nil {
		t.Fatal(err)
	}
	opts := options(t, server.URL)
	opts.Token = minted.Token
	reporter, err := agent.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer reporter.Close()
	if err := reporter.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, url := range []string{
		"http://example.com", "https://169.254.169.254", "https://10.0.0.1", "https://[fe80::1]",
		"https://user:secret@example.com", "https://example.com/path", "https://example.com?",
	} {
		if invalid, err := agent.New(options(t, url)); err == nil {
			invalid.Close()
			t.Fatalf("accepted unsafe URL %s", url)
		}
	}
	opts.CAFile = filepath.Join(t.TempDir(), "missing.pem")
	if invalid, err := agent.New(opts); err == nil {
		invalid.Close()
		t.Fatal("accepted missing CA")
	}
}
