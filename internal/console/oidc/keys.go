package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
)

const keyTTL = 5 * time.Minute
const refreshInterval = 5 * time.Second

var algorithms = []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.EdDSA}

type keyCache struct {
	mu        sync.Mutex
	client    *http.Client
	url       string
	now       func() time.Time
	keys      []jose.JSONWebKey
	refreshed time.Time
	attempted time.Time
}

func (k *keyCache) matching(kid, alg string) []crypto.PublicKey {
	keys := []crypto.PublicKey{}
	for _, key := range k.keys {
		if key.KeyID != kid || key.Use != "" && key.Use != "sig" || key.Algorithm != "" && key.Algorithm != alg {
			continue
		}
		switch public := key.Key.(type) {
		case *rsa.PublicKey:
			if alg == "RS256" && public.N.BitLen() >= 2048 && public.N.BitLen() <= 8192 {
				keys = append(keys, public)
			}
		case *ecdsa.PublicKey:
			if alg == "ES256" && public.Curve.Params().BitSize == 256 {
				keys = append(keys, public)
			}
		case ed25519.PublicKey:
			if alg == "EdDSA" {
				keys = append(keys, public)
			}
		}
	}
	return keys
}

// VerifySignature delegates JOSE parsing and cryptography to vetted libraries.
func (k *keyCache) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	signed, err := jose.ParseSigned(raw, algorithms)
	if err != nil || len(signed.Signatures) != 1 {
		return nil, ErrToken
	}
	header := signed.Signatures[0].Header
	if len(header.KeyID) == 0 || len(header.KeyID) > 128 {
		return nil, ErrToken
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	keys := k.matching(header.KeyID, header.Algorithm)
	if len(keys) == 0 || now.Sub(k.refreshed) >= keyTTL {
		if !k.attempted.IsZero() && now.Sub(k.attempted) < refreshInterval {
			return nil, ErrToken
		}
		k.attempted = now
		req, err := http.NewRequestWithContext(ctx, "GET", k.url, nil)
		if err != nil {
			return nil, ErrUnavailable
		}
		response, err := k.client.Do(req)
		if err != nil {
			return nil, ErrUnavailable
		}
		defer response.Body.Close()
		var set jose.JSONWebKeySet
		if response.StatusCode != 200 || json.NewDecoder(response.Body).Decode(&set) != nil ||
			len(set.Keys) == 0 || len(set.Keys) > 32 {
			return nil, ErrToken
		}
		for _, key := range set.Keys {
			if !key.IsPublic() || !key.Valid() || len(key.KeyID) > 128 {
				return nil, ErrToken
			}
		}
		k.keys, k.refreshed = set.Keys, now
		keys = k.matching(header.KeyID, header.Algorithm)
	}
	return (&coreoidc.StaticKeySet{PublicKeys: keys}).VerifySignature(ctx, raw)
}
