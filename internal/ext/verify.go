package ext

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// VerifyResult reports the outcome of manifest verification.
type VerifyResult struct {
	ManifestPath     string   `json:"manifest_path"`
	Status           string   `json:"status"` // verified | failed
	Name             string   `json:"name,omitempty"`
	Version          string   `json:"version,omitempty"`
	Permissions      []string `json:"permissions,omitempty"`
	DigestMatched    bool     `json:"digest_matched"`
	SignatureChecked bool     `json:"signature_checked"`
	Warnings         []string `json:"warnings,omitempty"`
	Error            string   `json:"error,omitempty"`
}

// LoadManifest reads and validates a manifest file (JSON or YAML).
func LoadManifest(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // explicit operator path
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %v", errManifest, path, err)
	}
	var m Manifest
	switch filepath.Ext(path) {
	case ".json":
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", errManifest, path, err)
		}
	default:
		if err := yaml.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", errManifest, path, err)
		}
	}
	m.Dir = filepath.Dir(absClean(path))
	m.Path = absClean(path)
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Verify checks the artifact digest (required) and, when a public key is
// provided, the optional ed25519 signature over the digest value.
func Verify(m *Manifest, pubKeyHex string) (*VerifyResult, error) {
	res := &VerifyResult{
		ManifestPath: m.Path,
		Name:         m.Name,
		Version:      m.Version,
		Permissions:  m.Permissions,
	}
	exe, err := m.ExecutablePath()
	if err != nil {
		res.Status = "failed"
		res.Error = err.Error()
		return res, err
	}
	b, err := os.ReadFile(exe) //nolint:gosec // path validated by ExecutablePath containment
	if err != nil {
		res.Status = "failed"
		res.Error = fmt.Sprintf("read extension binary: %v", err)
		return res, err
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(b))
	if sum != m.Digest.Value {
		res.Status = "failed"
		res.Error = fmt.Sprintf("digest mismatch: manifest says %s, artifact hashes to %s — refuse to run", m.Digest.Value, sum)
		return res, fmt.Errorf("%w: digest mismatch for %s", errManifest, m.Name)
	}
	res.DigestMatched = true

	if pubKeyHex != "" {
		pub, err := hex.DecodeString(pubKeyHex)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return res, fmt.Errorf("%w: pubkey must be %d hex chars (ed25519)", errManifest, ed25519.PublicKeySize)
		}
		// Check presence BEFORE touching Signature.Value: an unsigned manifest
		// under pubkey enforcement is a hard failure, not a panic.
		if m.Signature == nil {
			res.Status = "failed"
			res.Error = "signature missing but verification public key was provided"
			return res, fmt.Errorf("%w: signature verification failed", errManifest)
		}
		sig, err := hex.DecodeString(m.Signature.Value)
		if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), []byte(m.Digest.Value), sig) {
			res.Status = "failed"
			res.Error = "signature invalid for the provided public key"
			return res, fmt.Errorf("%w: signature verification failed", errManifest)
		}
		res.SignatureChecked = true
	} else {
		if m.Signature == nil {
			res.Warnings = append(res.Warnings, "no signature present")
		} else {
			res.Warnings = append(res.Warnings, "signature present but no pubkey supplied; digest-only verification")
		}
	}

	res.Status = "verified"
	return res, nil
}

func absClean(p string) string {
	a, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return filepath.Clean(p)
	}
	return a
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
