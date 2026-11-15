package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/metaforismo/aegismesh/internal/egress"
)

func newClient(endpoint *url.URL, allowPrivate bool, caFile string) (*http.Client, error) {
	policy := egress.Policy{
		AllowLoopback: true,
		AllowPrivate:  allowPrivate,
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		file, err := os.Open(caFile)
		if err != nil {
			return nil, errors.New("fleet agent: cannot open hub CA file")
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return nil, errors.New("fleet agent: hub CA must be a regular PEM file")
		}
		pem, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
		if err != nil || len(pem) > 1<<20 {
			return nil, errors.New("fleet agent: hub CA exceeds 1 MiB or is unreadable")
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("fleet agent: hub CA contains no certificates")
		}
		tlsConfig.RootCAs = roots
	}
	dialer := egress.NewDialer(policy, 5*time.Second)
	transport := &http.Transport{
		Proxy:                  nil,
		TLSClientConfig:        tlsConfig,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  5 * time.Second,
		MaxResponseHeaderBytes: 8 << 10,
		MaxIdleConns:           1,
		MaxConnsPerHost:        1,
		IdleConnTimeout:        30 * time.Second,
		DisableCompression:     true,
		DialContext: func(ctx context.Context, network, authority string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(authority)
			if err != nil {
				return nil, err
			}
			addresses := []net.IPAddr{}
			if ip := net.ParseIP(host); ip != nil {
				addresses = append(addresses, net.IPAddr{IP: ip})
			} else {
				addresses, err = net.DefaultResolver.LookupIPAddr(ctx, host)
				if err != nil {
					return nil, err
				}
			}
			for _, address := range addresses {
				if egress.Classify(address.IP, policy) != "" || endpoint.Scheme == "http" && !address.IP.IsLoopback() {
					continue
				}
				connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(address.IP.String(), port))
				if err == nil {
					return connection, nil
				}
			}
			return nil, errors.New("fleet agent: no reachable policy-compliant hub address")
		},
	}
	return &http.Client{
		Transport:     transport,
		CheckRedirect: egress.RefuseAllRedirects,
		Timeout:       10 * time.Second,
	}, nil
}
