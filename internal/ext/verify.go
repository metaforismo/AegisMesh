package ext

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const (
	maxManifestBytes = 1 << 20
	maxJSONDepth     = 32
	maxArtifactBytes = 256 << 20
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
	f, err := os.Open(path) //nolint:gosec // explicit operator path
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %v", errManifest, path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: inspect %s: %v", errManifest, path, err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxManifestBytes {
		return nil, fmt.Errorf("%w: %s must be a regular file no larger than %d bytes", errManifest, path, maxManifestBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxManifestBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %v", errManifest, path, err)
	}
	if len(raw) > maxManifestBytes {
		return nil, fmt.Errorf("%w: %s exceeds the %d-byte limit", errManifest, path, maxManifestBytes)
	}
	var m Manifest
	switch filepath.Ext(path) {
	case ".json":
		if err := rejectDuplicateJSONKeys(raw); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", errManifest, path, err)
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&m); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", errManifest, path, err)
		}
		if err := requireJSONEOF(dec); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", errManifest, path, err)
		}
	default:
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		dec.KnownFields(true)
		if err := dec.Decode(&m); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", errManifest, path, err)
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			if err == nil {
				err = fmt.Errorf("multiple YAML documents are not allowed")
			}
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

func rejectDuplicateJSONKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := scanUniqueJSONValue(dec, 0); err != nil {
		return err
	}
	return requireJSONEOF(dec)
}

func scanUniqueJSONValue(dec *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("JSON nesting exceeds %d", maxJSONDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyToken, err := dec.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return fmt.Errorf("object key is invalid")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := scanUniqueJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
		if end, err := dec.Token(); err != nil || end != json.Delim('}') {
			return fmt.Errorf("object is not closed")
		}
	case '[':
		for dec.More() {
			if err := scanUniqueJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
		if end, err := dec.Token(); err != nil || end != json.Delim(']') {
			return fmt.Errorf("array is not closed")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	return nil
}

func requireJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
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
	f, err := os.Open(exe) //nolint:gosec // path validated by ExecutablePath containment
	if err != nil {
		res.Status = "failed"
		res.Error = fmt.Sprintf("read extension binary: %v", err)
		return res, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		res.Status = "failed"
		res.Error = fmt.Sprintf("inspect extension artifact: %v", err)
		return res, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxArtifactBytes {
		res.Status = "failed"
		res.Error = fmt.Sprintf("extension artifact must be a regular file no larger than %d bytes", maxArtifactBytes)
		return res, fmt.Errorf("%w: invalid artifact for %s", errManifest, m.Name)
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxArtifactBytes+1))
	if err != nil {
		res.Status = "failed"
		res.Error = fmt.Sprintf("hash extension artifact: %v", err)
		return res, err
	}
	if n > maxArtifactBytes {
		res.Status = "failed"
		res.Error = fmt.Sprintf("extension artifact exceeds %d bytes", maxArtifactBytes)
		return res, fmt.Errorf("%w: artifact for %s grew beyond its size cap", errManifest, m.Name)
	}
	sum := hex.EncodeToString(h.Sum(nil))
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
