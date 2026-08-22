package ext

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validManifest() Manifest {
	return Manifest{
		APIVersion:  APIVersionV1Alpha1,
		Name:        "echo-responder",
		Version:     "0.1.0",
		Description: "reference extension",
		Permissions: []string{"respond"},
		Transport: Transport{
			Kind:               TransportSubprocessNDJSON,
			Command:            []string{"./echo-responder"},
			HandshakeTimeoutMS: 5000,
			CallTimeoutMS:      5000,
			MaxOutputBytes:     1 << 20,
		},
		Digest: Digest{Algorithm: "sha256", Value: strings.Repeat("ab", 32)},
	}
}

func TestManifestValidateTable(t *testing.T) {
	base := validManifest()
	mut := func(f func(*Manifest)) Manifest {
		m := base
		f(&m)
		return m
	}
	cases := []struct {
		name    string
		m       Manifest
		wantErr string
	}{
		{"valid", mut(func(m *Manifest) {}), ""},
		{"bad api version", mut(func(m *Manifest) { m.APIVersion = "ext.aegismesh.io/v1beta2" }), "api_version"},
		{"bad name", mut(func(m *Manifest) { m.Name = "Bad Name" }), "name"},
		{"short name", mut(func(m *Manifest) { m.Name = "ab" }), "name"},
		{"bad semver", mut(func(m *Manifest) { m.Version = "1.0" }), "semver"},
		{"empty permissions", mut(func(m *Manifest) { m.Permissions = nil }), "permissions"},
		{"unknown permission", mut(func(m *Manifest) { m.Permissions = []string{"exec"} }), "not recognized"},
		{"too many permissions", mut(func(m *Manifest) {
			m.Permissions = make([]string, 9)
			for i := range m.Permissions {
				m.Permissions[i] = "respond"
			}
		}), "too many"},
		{"wrong transport", mut(func(m *Manifest) { m.Transport.Kind = "in-proc" }), "transport.kind"},
		{"no command", mut(func(m *Manifest) { m.Transport.Command = nil }), "command"},
		{"empty arg", mut(func(m *Manifest) { m.Transport.Command = []string{"x", ""} }), "empty or over-long"},
		{"handshake timeout too low", mut(func(m *Manifest) { m.Transport.HandshakeTimeoutMS = 50 }), "handshake_timeout_ms"},
		{"call timeout too high", mut(func(m *Manifest) { m.Transport.CallTimeoutMS = 60001 }), "call_timeout_ms"},
		{"output cap zero", mut(func(m *Manifest) { m.Transport.MaxOutputBytes = 0 }), "max_output_bytes"},
		{"digest algorithm", mut(func(m *Manifest) { m.Digest.Algorithm = "md5" }), "sha256"},
		{"digest not hex", mut(func(m *Manifest) { m.Digest.Value = strings.Repeat("zz", 32) }), "64 hex"},
		{"signature algorithm", mut(func(m *Manifest) {
			m.Signature = &Signature{Algorithm: "rsa", Value: strings.Repeat("ab", 64)}
		}), "ed25519"},
		{"signature length", mut(func(m *Manifest) {
			m.Signature = &Signature{Algorithm: "ed25519", Value: "abcd"}
		}), "128 hex"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.m.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func writeManifest(t *testing.T, dir string, m Manifest) string {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExecutablePathContainment(t *testing.T) {
	dir := t.TempDir()
	m := validManifest()
	m.Dir = dir

	cases := []struct {
		cmd     string
		wantErr bool
	}{
		{"./echo-responder", false},
		{"sub/dir/ext", false},
		{"../outside", true},
		{"/etc/passwd", true},
		{"/bin/sh", true},
		{"a/../b", false},
		{"../../..", true},
	}
	for _, tc := range cases {
		m.Transport.Command = []string{tc.cmd}
		p, err := m.ExecutablePath()
		if tc.wantErr && err == nil {
			t.Errorf("cmd %q: want containment error, got %q", tc.cmd, p)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("cmd %q: unexpected error %v", tc.cmd, err)
		}
	}
}

func signDigest(t *testing.T, digestHex string) (pubHex, sigHex string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, []byte(digestHex))
	return hex.EncodeToString(pub), hex.EncodeToString(sig)
}

func buildEchoExtension(t *testing.T) (dir, exeName string, sum string) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping go build in -short mode")
	}
	dir = t.TempDir()
	src := filepath.Join(dir, "main.go")
	goMod := filepath.Join(dir, "go.mod")
	mainSrc, err := os.ReadFile(filepath.Join("..", "..", "examples", "extensions", "echo-responder", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, mainSrc, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goMod, []byte("module echo-responder\n\ngo 1.25\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exeName = "echo-responder"
	out := filepath.Join(dir, exeName)
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = dir
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, b)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	sum = fmt.Sprintf("%x", sha256.Sum256(b))
	return dir, "./" + exeName, sum
}

func TestLoadVerifyAndRunEchoExtension(t *testing.T) {
	dir, relExe, sum := buildEchoExtension(t)

	m := validManifest()
	m.Dir = dir
	m.Path = writeManifest(t, dir, m)
	m.Transport.Command = []string{relExe}
	m.Digest.Value = sum

	pubHex, sigHex := signDigest(t, sum)
	m.Signature = &Signature{Algorithm: "ed25519", Value: sigHex}

	// Rewrite manifest now that signature exists.
	m.Path = writeManifest(t, dir, m)

	loaded, err := LoadManifest(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Verify(loaded, pubHex)
	if err != nil {
		t.Fatalf("verify with signature: %v (%+v)", err, res)
	}
	if !res.DigestMatched || !res.SignatureChecked || res.Status != "verified" {
		t.Fatalf("verify result wrong: %+v", res)
	}

	h, err := Start(context.Background(), loaded, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := h.Call(ctx, "respond", json.RawMessage(`{"text":"hi"}`))
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("result not JSON: %s", out)
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected result: %s", out)
	}
}

func TestVerifyDigestMismatchRefuses(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "ext")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	m := validManifest()
	m.Dir = dir
	m.Transport.Command = []string{"./ext"}
	m.Digest.Value = strings.Repeat("00", 32)
	writeManifest(t, dir, m)

	res, err := Verify(&m, "")
	if err == nil || res.Status != "failed" {
		t.Fatalf("digest mismatch must fail: %+v", res)
	}
	if !strings.Contains(res.Error, "refuse to run") {
		t.Fatalf("error should be explicit about refusal: %s", res.Error)
	}
}

func TestVerifyUnsignedWithPubkeyFailsNotPanics(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "ext")
	if err := os.WriteFile(exe, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("binary"))
	m := validManifest()
	m.Dir = dir
	m.Transport.Command = []string{"./ext"}
	m.Digest.Value = hex.EncodeToString(sum[:])
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Regression guard: pubkey provided + no signature must return an error,
	// never panic on a nil Signature dereference.
	_, verr := Verify(&m, hex.EncodeToString(pub))
	if verr == nil || !strings.Contains(verr.Error(), "signature") {
		t.Fatalf("want signature failure, got %v", verr)
	}
}

// writeShim places a tiny executable shim inside dir that execs a system
// binary. Copying Apple-signed system binaries directly breaks their code
// signature (SIGKILL on launch), so tests proxy through a two-line script.
func writeShim(t *testing.T, dir, file, bin string, args ...string) {
	t.Helper()
	script := "#!/bin/sh\nexec " + bin
	for _, a := range args {
		script += " " + a
	}
	script += "\n"
	if err := os.WriteFile(filepath.Join(dir, file), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestHostHandshakeFailures(t *testing.T) {
	dir := t.TempDir()
	writeShim(t, dir, "false-ext", "/usr/bin/false")
	writeShim(t, dir, "cat-ext", "/bin/cat")
	writeShim(t, dir, "sleep-ext", "/bin/sleep", "30")
	cases := []struct {
		name    string
		command []string
		hsMS    int
		wantErr string
	}{
		{"exits immediately", []string{"./false-ext"}, 2000, "handshake"},
		{"echoes wrong frame type", []string{"./cat-ext"}, 2000, "bad handshake"},
		{"never responds", []string{"./sleep-ext"}, 300, "timed out"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validManifest()
			m.Dir = dir
			m.Transport.Command = tc.command
			m.Transport.HandshakeTimeoutMS = tc.hsMS
			h, err := Start(context.Background(), &m, nil)
			if err == nil {
				h.Stop()
				t.Fatalf("want handshake failure containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want %q in error, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestHostCallDeadlineRevokesProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping go build in -short mode")
	}
	dir := t.TempDir()
	src := `package main

import (
	"bufio"
	"encoding/json"
	"os"
)

type frame struct {
	Type     string          ` + "`json:\"type\"`" + `
	Protocol int             ` + "`json:\"protocol,omitempty\"`" + `
	ID       string          ` + "`json:\"id,omitempty\"`" + `
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	out := json.NewEncoder(os.Stdout)
	for in.Scan() {
		var f frame
		_ = json.Unmarshal(in.Bytes(), &f)
		if f.Type == "hello" {
			_ = out.Encode(frame{Type: "hello_ok", Protocol: 1})
		}
		// Requests are deliberately never answered.
	}
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module silent\n\ngo 1.25\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", filepath.Join(dir, "silent"), ".")
	cmd.Dir = dir
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}

	m := validManifest()
	m.Dir = dir
	m.Transport.Command = []string{"./silent"}
	m.Transport.CallTimeoutMS = 400

	h, err := Start(context.Background(), &m, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, cerr := h.Call(ctx, "respond", nil)
	if cerr == nil || !strings.Contains(cerr.Error(), "revoked") {
		t.Fatalf("call deadline must revoke the process, got %v", cerr)
	}
}

func TestLoadManifestRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(p); err == nil {
		t.Fatal("garbage manifest must not load")
	}
}
