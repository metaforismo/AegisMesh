package oidc

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/egress"
)

// ResponseBytes caps every decoded provider response, including token and JWKS data.
const ResponseBytes = 256 << 10

type boundedTransport struct {
	base   http.RoundTripper
	issuer *url.URL
	policy egress.Policy
}

func (t boundedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if !t.allowed(r.URL.String()) {
		return nil, ErrUnavailable
	}
	response, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, ResponseBytes+1))
	if err != nil || len(body) > ResponseBytes {
		return nil, ErrUnavailable
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}

func (t boundedTransport) allowed(raw string) bool {
	u, err := egress.ValidateURL(t.policy, raw)
	return err == nil && !u.ForceQuery && u.RawPath == "" &&
		u.Scheme == t.issuer.Scheme && strings.EqualFold(u.Host, t.issuer.Host)
}

func providerClient(cfg config.OIDC, base http.RoundTripper) (*http.Client, boundedTransport, error) {
	issuer, err := egress.ValidateURL(cfg.EgressPolicy(), cfg.Issuer)
	if err != nil {
		return nil, boundedTransport{}, errors.New("OIDC: invalid issuer")
	}
	if base == nil {
		base = &http.Transport{
			Proxy:                  nil,
			DialContext:            egress.NewDialer(cfg.EgressPolicy(), 3*time.Second).DialContext,
			TLSHandshakeTimeout:    3 * time.Second,
			ResponseHeaderTimeout:  3 * time.Second,
			MaxResponseHeaderBytes: 16 << 10,
			MaxIdleConns:           4,
			MaxConnsPerHost:        4,
			IdleConnTimeout:        30 * time.Second,
		}
	}
	transport := boundedTransport{base: base, issuer: issuer, policy: cfg.EgressPolicy()}
	return &http.Client{Timeout: 5 * time.Second, Transport: transport, CheckRedirect: egress.RefuseAllRedirects}, transport, nil
}
