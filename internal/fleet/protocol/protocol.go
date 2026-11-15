// Package protocol defines the inventory-only fleet wire contract.
// All incoming bytes are untrusted data; no field selects behavior or a filesystem path.
package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// MaxBodyBytes bounds every machine request and response.
const MaxBodyBytes = 32 << 10

// EnrollPath is the versioned proof-of-possession enrollment endpoint.
const EnrollPath = "/fleet/v1/enroll"

// HeartbeatPath is the only authenticated status submission endpoint.
const HeartbeatPath = "/fleet/v1/heartbeat"

// Window bounds accepted request clock skew in either direction.
const Window = 120 * time.Second

// ErrInvalid marks malformed or noncanonical protocol input.
var ErrInvalid = errors.New("fleet: invalid protocol input")

// Authentication is the strictly parsed request signing envelope.
type Authentication struct {
	// NodeID binds the signing envelope to the public-key-derived identity.
	NodeID string
	// Timestamp is the exact canonical Unix-seconds header.
	Timestamp string
	// Nonce is a fresh 128-bit random value encoded as lowercase hex.
	Nonce string
	// Signature contains the decoded Ed25519 signature bytes.
	Signature []byte
	// Time is the parsed timestamp used for clock-skew checks.
	Time time.Time
}

// ID derives a stable 128-bit node identifier from a public key.
func ID(public ed25519.PublicKey) string {
	digest := sha256.Sum256(public)
	return hex.EncodeToString(digest[:16])
}

// Digest returns a lowercase SHA-256 hex digest.
func Digest(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

// Hex accepts only a lowercase, fixed-length hex encoding.
func Hex(value string, size int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == size && hex.EncodeToString(decoded) == value
}

// Random returns a cryptographically random lowercase hex string.
func Random(size int) (string, error) {
	body := make([]byte, size)
	if _, err := rand.Read(body); err != nil {
		return "", err
	}
	return hex.EncodeToString(body), nil
}

// Canonical returns the exact domain-separated ASCII signing string, without a final newline.
func Canonical(method, path string, body []byte, auth Authentication) (string, error) {
	if method != http.MethodPost || (path != EnrollPath && path != HeartbeatPath) ||
		!Hex(auth.NodeID, 16) || !Hex(auth.Nonce, 16) || len(body) > MaxBodyBytes {
		return "", ErrInvalid
	}
	seconds, err := strconv.ParseInt(auth.Timestamp, 10, 64)
	if err != nil || seconds <= 0 || strconv.FormatInt(seconds, 10) != auth.Timestamp || len(auth.Timestamp) > 12 {
		return "", ErrInvalid
	}
	return strings.Join([]string{
		"AEGISMESH-FLEET/1",
		auth.NodeID,
		method,
		path,
		Digest(body),
		auth.Timestamp,
		auth.Nonce,
	}, "\n"), nil
}

// Parse rejects duplicate, malformed and noncanonical authentication headers.
func Parse(r *http.Request, body []byte) (Authentication, string, error) {
	names := []string{"X-AegisMesh-Node", "X-AegisMesh-Time", "X-AegisMesh-Nonce", "X-AegisMesh-Signature"}
	for _, name := range names {
		if len(r.Header.Values(name)) != 1 {
			return Authentication{}, "", ErrInvalid
		}
	}
	signature := r.Header.Get(names[3])
	if !Hex(signature, ed25519.SignatureSize) || r.URL.RawQuery != "" || r.URL.ForceQuery ||
		r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path {
		return Authentication{}, "", ErrInvalid
	}
	decoded, _ := hex.DecodeString(signature)
	auth := Authentication{
		NodeID:    r.Header.Get(names[0]),
		Timestamp: r.Header.Get(names[1]),
		Nonce:     r.Header.Get(names[2]),
		Signature: decoded,
	}
	canonical, err := Canonical(r.Method, r.URL.Path, body, auth)
	seconds, _ := strconv.ParseInt(auth.Timestamp, 10, 64)
	auth.Time = time.Unix(seconds, 0)
	return auth, canonical, err
}

// Sign supplies a fresh nonce, timestamp and Ed25519 signature for the exact request body.
func Sign(r *http.Request, body []byte, key ed25519.PrivateKey, now time.Time) error {
	nonce, err := Random(16)
	if err != nil {
		return err
	}
	auth := Authentication{
		NodeID:    ID(key.Public().(ed25519.PublicKey)),
		Timestamp: strconv.FormatInt(now.Unix(), 10),
		Nonce:     nonce,
	}
	canonical, err := Canonical(r.Method, r.URL.Path, body, auth)
	if err != nil {
		return err
	}
	r.Header.Set("X-AegisMesh-Node", auth.NodeID)
	r.Header.Set("X-AegisMesh-Time", auth.Timestamp)
	r.Header.Set("X-AegisMesh-Nonce", nonce)
	r.Header.Set("X-AegisMesh-Signature", hex.EncodeToString(ed25519.Sign(key, []byte(canonical))))
	return nil
}
