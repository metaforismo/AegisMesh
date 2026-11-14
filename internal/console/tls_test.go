package console_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"

	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/console"
)

func TestConsoleTLSCookieAndOrigin(t *testing.T) {
	certificatePath := filepath.Join(t.TempDir(), "cert.pem")
	keyPath := filepath.Join(filepath.Dir(certificatePath), "key.pem")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "synthetic-loopback"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})
	if err = os.WriteFile(certificatePath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}

	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}), 0600); err != nil {
		t.Fatal(err)
	}

	harness := newConsoleHarness(t, func(opts *console.Options) {
		opts.Config.TLSCertFile = certificatePath
		opts.Config.TLSKeyFile = keyPath
	})
	addr := harness.server.Addr()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:    roots,
			MinVersion: tls.VersionTLS12,
		}},
	}

	harness.base = "https://" + addr
	harness.client = client
	t.Cleanup(client.CloseIdleConnections)
	cookie, session := harness.login(t, nil)
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" {
		t.Fatalf("unsafe TLS cookie: %+v", cookie)
	}
	for _, testCase := range []struct {
		name   string
		origin string
		status int
	}{
		{name: "TLS origin", origin: harness.base, status: 200},
		{name: "wrong scheme", origin: "http://" + addr, status: 403},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			requireStatus(t, harness.request(t, apiRequest{
				method: "POST",
				path:   "/api/v1/session",
				body:   `{"token":"synthetic-admin"}`,
				origin: testCase.origin,
			}), testCase.status)
		})
	}
	requireStatus(t, harness.request(t, apiRequest{method: "GET", path: "/"}), 200)
	logout := harness.request(t, apiRequest{
		method: "DELETE",
		path:   "/api/v1/session",
		cookie: cookie,
		csrf:   session.CSRFToken,
		origin: harness.base,
	})
	requireStatus(t, logout, 204)
	if len(logout.cookies) != 1 || !logout.cookies[0].Secure || logout.cookies[0].MaxAge != -1 {
		t.Fatalf("TLS logout cookie: %+v", logout.cookies)
	}
	requireStatus(t, harness.request(t, apiRequest{method: "GET", path: "/api/v1/session", cookie: cookie}), 401)
}
