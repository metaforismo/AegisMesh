// Package ext implements the capability-safe extension model: manifests,
// digest/signature verification, and an out-of-process reference host.
//
// Security posture (ADR-0006): extension code is untrusted. It never links
// into this process. The host spawns it as a separate OS process speaking
// newline-delimited JSON over stdio, enforces handshake/deadline/output caps,
// and revokes (kills) on any violation.
package ext

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
)

const (
	// APIVersionV1Alpha1 is the supported manifest schema version.
	APIVersionV1Alpha1 = "ext.aegismesh.io/v1alpha1"

	// TransportSubprocessNDJSON is the only transport kind in v1alpha1.
	TransportSubprocessNDJSON = "subprocess-ndjson"

	// ProtocolVersion is the wire protocol revision for the handshake.
	ProtocolVersion = 1

	maxCommandArgs = 16
	maxArgLen      = 4096
	maxTimeoutMS   = 60000
	minTimeoutMS   = 100
	maxOutputBytes = 4 << 20
)

var (
	nameRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)
	versionRe   = regexp.MustCompile(`^\d+\.\d+\.\d+(-[\w.-]+)?$`)
	errManifest = errors.New("ext manifest")
)

// Permissions allowed in v1alpha1:
//   - respond: extension may contribute response text (not wired into the
//     runtime yet; reserved by the schema)
//   - observe: extension receives observation envelopes (data-only; its
//     replies carry acks/errors and can never influence behavior)
//
// Anything more requires a new schema version and ADR.
var allowedPermissions = map[string]bool{
	"respond": true,
	"observe": true,
}

type Manifest struct {
	APIVersion  string     `json:"api_version"`
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Description string     `json:"description,omitempty"`
	Permissions []string   `json:"permissions"`
	Transport   Transport  `json:"transport"`
	Digest      Digest     `json:"digest"`
	Signature   *Signature `json:"signature,omitempty"`

	// Dir is the directory containing the manifest file; resolved by Load.
	Dir string `json:"-"`
	// Path is the manifest file path; resolved by LoadManifest.
	Path string `json:"-"`
}

type Transport struct {
	Kind               string   `json:"kind"`
	Command            []string `json:"command"`
	HandshakeTimeoutMS int      `json:"handshake_timeout_ms"`
	CallTimeoutMS      int      `json:"call_timeout_ms"`
	MaxOutputBytes     int      `json:"max_output_bytes"`
}

type Digest struct {
	Algorithm string `json:"algorithm"` // sha256
	Value     string `json:"value"`     // lowercase hex
}

type Signature struct {
	Algorithm string `json:"algorithm"` // ed25519
	Value     string `json:"value"`     // hex signature over digest.Value
}

func (m *Manifest) Validate() error {
	if m.APIVersion != APIVersionV1Alpha1 {
		return fmt.Errorf("%w: api_version %q unsupported (want %q)", errManifest, m.APIVersion, APIVersionV1Alpha1)
	}
	if !nameRe.MatchString(m.Name) {
		return fmt.Errorf("%w: name %q must match %s", errManifest, m.Name, nameRe)
	}
	if !versionRe.MatchString(m.Version) {
		return fmt.Errorf("%w: version %q must be semver (MAJOR.MINOR.PATCH)", errManifest, m.Version)
	}
	if len(m.Permissions) == 0 {
		return fmt.Errorf("%w: permissions must be non-empty (use [\"respond\"]) so grants stay explicit", errManifest)
	}
	if len(m.Permissions) > 8 {
		return fmt.Errorf("%w: too many permissions", errManifest)
	}
	for _, p := range m.Permissions {
		if !allowedPermissions[p] {
			return fmt.Errorf("%w: permission %q not recognized (allowed: observe|respond)", errManifest, p)
		}
	}
	t := &m.Transport
	if t.Kind != TransportSubprocessNDJSON {
		return fmt.Errorf("%w: transport.kind %q unsupported (want %q)", errManifest, t.Kind, TransportSubprocessNDJSON)
	}
	if n := len(t.Command); n == 0 || n > maxCommandArgs {
		return fmt.Errorf("%w: transport.command must have 1..%d elements", errManifest, maxCommandArgs)
	}
	for i, a := range t.Command {
		if a == "" || len(a) > maxArgLen {
			return fmt.Errorf("%w: transport.command[%d] empty or over-long", errManifest, i)
		}
	}
	if t.HandshakeTimeoutMS < minTimeoutMS || t.HandshakeTimeoutMS > maxTimeoutMS {
		return fmt.Errorf("%w: handshake_timeout_ms must be %d..%d", errManifest, minTimeoutMS, maxTimeoutMS)
	}
	if t.CallTimeoutMS < minTimeoutMS || t.CallTimeoutMS > maxTimeoutMS {
		return fmt.Errorf("%w: call_timeout_ms must be %d..%d", errManifest, minTimeoutMS, maxTimeoutMS)
	}
	if t.MaxOutputBytes <= 0 || t.MaxOutputBytes > maxOutputBytes {
		return fmt.Errorf("%w: max_output_bytes must be 1..%d", errManifest, maxOutputBytes)
	}
	if m.Digest.Algorithm != "sha256" {
		return fmt.Errorf("%w: digest.algorithm must be sha256", errManifest)
	}
	if len(m.Digest.Value) != 64 || !isHex(m.Digest.Value) {
		return fmt.Errorf("%w: digest.value must be 64 hex chars", errManifest)
	}
	if m.Signature != nil {
		if m.Signature.Algorithm != "ed25519" {
			return fmt.Errorf("%w: signature.algorithm must be ed25519", errManifest)
		}
		if len(m.Signature.Value) != 128 || !isHex(m.Signature.Value) {
			return fmt.Errorf("%w: signature.value must be 128 hex chars", errManifest)
		}
	}
	return nil
}

// ExecutablePath resolves the extension binary path relative to the manifest
// directory with traversal protection.
func (m *Manifest) ExecutablePath() (string, error) {
	raw := m.Transport.Command[0]
	var p string
	if filepath.IsAbs(raw) {
		p = filepath.Clean(raw)
	} else {
		p = filepath.Join(m.Dir, filepath.Clean(raw))
	}
	if !withinDir(m.Dir, p) {
		return "", fmt.Errorf("%w: command resolves outside the manifest directory", errManifest)
	}
	return p, nil
}

func withinDir(base, target string) bool {
	baseAbs := absClean(base)
	targetAbs := absClean(target)
	return targetAbs == baseAbs || len(targetAbs) > len(baseAbs)+1 && targetAbs[:len(baseAbs)] == baseAbs && targetAbs[len(baseAbs)] == filepath.Separator
}
