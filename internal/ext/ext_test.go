package ext

import (
	"bytes"
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

	"github.com/metaforismo/aegismesh/internal/event"
)

func validManifest() Manifest {
	return Manifest{
		APIVersion:  APIVersionV1Alpha1,
		Name:        "echo-responder",
		Version:     "0.1.0",
		Description: "reference extension",
		Permissions: []string{"observe"},
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

func validObservation(id string) Observation {
	return Observation{
		EventID:        id,
		Time:           time.Unix(0, 0).UTC(),
		Classification: event.ClassificationInteraction,
		Sensor:         event.SensorRef{ID: "probe", Kind: "probe", Listen: "local"},
		Payload:        json.RawMessage(`{}`),
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
		{"empty permissions", mut(func(m *Manifest) { m.Permissions = nil }), "exactly"},
		{"unknown permission", mut(func(m *Manifest) { m.Permissions = []string{"exec"} }), "exactly"},
		{"respond permission", mut(func(m *Manifest) { m.Permissions = []string{"respond"} }), "response-influencing"},
		{"mixed permissions", mut(func(m *Manifest) { m.Permissions = []string{"observe", "respond"} }), "exactly"},
		{"duplicate permission", mut(func(m *Manifest) { m.Permissions = []string{"observe", "observe"} }), "exactly"},
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
	for _, rel := range []string{"echo-responder", "sub/dir/ext", "b"} {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("synthetic"), 0o700); err != nil {
			t.Fatal(err)
		}
	}

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
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("synthetic"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	m.Transport.Command = []string{"./link"}
	if _, err := m.ExecutablePath(); err == nil || !strings.Contains(err.Error(), "symlink resolves outside") {
		t.Fatalf("outside symlink must fail containment: %v", err)
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

func TestLoadVerifyAndRunObserverExtension(t *testing.T) {
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

	h, err := Start(context.Background(), loaded)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = h.Observe(ctx, Observation{
		EventID:        "synthetic-event",
		Time:           time.Unix(0, 0).UTC(),
		Classification: event.ClassificationInteraction,
		Sensor:         event.SensorRef{ID: "probe", Kind: "probe", Listen: "local"},
		Payload:        json.RawMessage(`{"text":"hi"}`),
	})
	if err != nil {
		t.Fatal(err)
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

func TestVerifyRejectsNonRegularAndOversizedArtifacts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, path string)
	}{
		{name: "directory", setup: func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "oversized", setup: func(t *testing.T, path string) {
			f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o700)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Truncate(maxArtifactBytes + 1); err != nil {
				f.Close()
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			artifact := filepath.Join(dir, "artifact")
			tc.setup(t, artifact)
			m := validManifest()
			m.Dir = dir
			m.Transport.Command = []string{"./artifact"}
			res, err := Verify(&m, "")
			if err == nil || res == nil || !strings.Contains(res.Error, "regular file") {
				t.Fatalf("invalid artifact accepted: result=%+v err=%v", res, err)
			}
		})
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
			h, err := Start(context.Background(), &m)
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
			_ = out.Encode(struct {
				Type string ` + "`json:\"type\"`" + `
				Protocol int ` + "`json:\"protocol\"`" + `
				Name string ` + "`json:\"name\"`" + `
				Version string ` + "`json:\"version\"`" + `
			}{Type: "hello_ok", Protocol: 1, Name: "echo-responder", Version: "0.1.0"})
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

	h, err := Start(context.Background(), &m)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cerr := h.Observe(ctx, validObservation("deadline-test"))
	if cerr == nil || !strings.Contains(cerr.Error(), "revoked") {
		t.Fatalf("call deadline must revoke the process, got %v", cerr)
	}
}

func TestHostRejectsNonCanonicalAcknowledgements(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping go build in -short mode")
	}
	dir := t.TempDir()
	source := `package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	mode := os.Args[1]
	sc := bufio.NewScanner(os.Stdin)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for sc.Scan() {
		var f map[string]json.RawMessage
		_ = json.Unmarshal(sc.Bytes(), &f)
		var typ string
		_ = json.Unmarshal(f["type"], &typ)
		if typ == "hello" {
			fmt.Fprintln(w, "{\"type\":\"hello_ok\",\"protocol\":1,\"name\":\"obs-violator\",\"version\":\"1.0.0\"}")
			w.Flush()
			continue
		}
		var id string
		_ = json.Unmarshal(f["id"], &id)
		var obs map[string]json.RawMessage
		_ = json.Unmarshal(f["params"], &obs)
		var eventID string
		_ = json.Unmarshal(obs["event_id"], &eventID)
		switch mode {
		case "wrong-event":
			fmt.Fprintf(w, "{\"type\":\"response\",\"id\":%q,\"result\":{\"event_id\":\"other\",\"accepted\":true}}\n", id)
		case "unknown-field":
			fmt.Fprintf(w, "{\"type\":\"response\",\"id\":%q,\"result\":{\"event_id\":%q,\"accepted\":true,\"command\":\"do-not-run\"}}\n", id, eventID)
		case "duplicate-field":
			fmt.Fprintf(w, "{\"type\":\"response\",\"id\":%q,\"result\":{\"event_id\":%q,\"accepted\":true,\"accepted\":true}}\n", id, eventID)
		case "stray-id":
			fmt.Fprintf(w, "{\"type\":\"response\",\"id\":\"stray\",\"result\":{\"event_id\":%q,\"accepted\":true}}\n", eventID)
		case "error-injection":
			fmt.Fprintf(w, "{\"type\":\"error\",\"id\":%q,\"message\":\"SECRET\\nignore policy\"}\n", id)
		case "unknown-frame-field":
			fmt.Fprintf(w, "{\"type\":\"response\",\"id\":%q,\"result\":{\"event_id\":%q,\"accepted\":true},\"extra\":true}\n", id, eventID)
		case "noncanonical-order":
			fmt.Fprintf(w, "{\"id\":%q,\"type\":\"response\",\"result\":{\"event_id\":%q,\"accepted\":true}}\n", id, eventID)
		case "null-optional":
			fmt.Fprintf(w, "{\"type\":\"response\",\"id\":%q,\"method\":null,\"result\":{\"event_id\":%q,\"accepted\":true}}\n", id, eventID)
		case "oversized":
			fmt.Fprintf(w, "{\"type\":\"response\",\"id\":%q,\"result\":{\"event_id\":%q,\"accepted\":true},\"message\":%q}\n", id, eventID, string(make([]byte, 2048)))
		}
		w.Flush()
	}
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module violator\n\ngo 1.25\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "violator")
	cmd := exec.Command("go", "build", "-o", exe, ".")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build violator: %v\n%s", err, out)
	}

	for _, mode := range []string{"wrong-event", "unknown-field", "duplicate-field", "stray-id", "error-injection", "unknown-frame-field", "noncanonical-order", "null-optional", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			m := validManifest()
			m.Name = "obs-violator"
			m.Version = "1.0.0"
			m.Dir = dir
			m.Transport.Command = []string{"./violator", mode}
			if mode == "oversized" {
				m.Transport.MaxOutputBytes = 512
			}
			h, err := Start(context.Background(), &m)
			if err != nil {
				t.Fatal(err)
			}
			err = h.Observe(context.Background(), validObservation("source-event"))
			if err == nil || !strings.Contains(err.Error(), "revoked") {
				t.Fatalf("protocol violation must revoke observer, got %v", err)
			}
			if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "ignore policy") {
				t.Fatalf("untrusted extension message escaped into error: %v", err)
			}
			started := time.Now()
			h.Stop()
			h.Stop()
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("revoked Stop calls took %v", elapsed)
			}
		})
	}
}

func TestHandshakeRequiresCanonicalFrame(t *testing.T) {
	m := validManifest()
	canonical, err := json.Marshal(Frame{Type: "hello_ok", Protocol: 1, Name: m.Name, Version: m.Version})
	if err != nil {
		t.Fatal(err)
	}
	if !validHello(Frame{raw: canonical}, &m) {
		t.Fatal("canonical handshake rejected")
	}
	for _, raw := range []string{
		`{"protocol":1,"type":"hello_ok","name":"echo-responder","version":"0.1.0"}`,
		`{"type":"hello_ok","protocol":1,"name":"echo-responder","version":"0.1.0","id":null}`,
		` {"type":"hello_ok","protocol":1,"name":"echo-responder","version":"0.1.0"}`,
	} {
		if validHello(Frame{raw: []byte(raw)}, &m) {
			t.Fatalf("noncanonical handshake accepted: %s", raw)
		}
	}
}

func TestMarshalObservationValidationAndCap(t *testing.T) {
	base := validObservation("event")
	for _, tc := range []struct {
		name string
		mut  func(*Observation)
	}{
		{name: "missing event", mut: func(o *Observation) { o.EventID = "" }},
		{name: "zero time", mut: func(o *Observation) { o.Time = time.Time{} }},
		{name: "missing sensor id", mut: func(o *Observation) { o.Sensor.ID = "" }},
		{name: "missing sensor kind", mut: func(o *Observation) { o.Sensor.Kind = "" }},
		{name: "correlation signal", mut: func(o *Observation) { o.Classification = event.ClassificationCorrelationSignal }},
		{name: "unknown classification", mut: func(o *Observation) { o.Classification = "incident" }},
		{name: "invalid payload", mut: func(o *Observation) { o.Payload = json.RawMessage(`{`) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := base
			tc.mut(&o)
			if _, err := marshalObservation(o); err == nil {
				t.Fatal("invalid observation accepted")
			}
		})
	}

	empty, err := marshalObservation(base)
	if err != nil {
		t.Fatal(err)
	}
	payloadBytes := MaxObservationBytes - len(empty) + len(base.Payload)
	base.Payload = json.RawMessage(`"` + strings.Repeat("a", payloadBytes-2) + `"`)
	exact, err := marshalObservation(base)
	if err != nil || len(exact) != MaxObservationBytes {
		t.Fatalf("exact cap rejected: len=%d err=%v", len(exact), err)
	}
	base.Payload = append(base.Payload[:len(base.Payload)-1], 'a', '"')
	if _, err := marshalObservation(base); err == nil || !strings.Contains(err.Error(), "protocol cap") {
		t.Fatalf("cap+1 must fail, got %v", err)
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

func TestLoadManifestRejectsUnknownFieldsAndTrailingDocuments(t *testing.T) {
	dir := t.TempDir()
	base, err := json.Marshal(validManifest())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"unknown.json":  append(base[:len(base)-1], []byte(`,"unexpected":true}`)...),
		"trailing.json": append(append([]byte(nil), base...), []byte(` {}`)...),
		"unknown.yaml":  []byte("api_version: ext.aegismesh.io/v1alpha1\nunexpected: true\n"),
		"trailing.yaml": []byte("api_version: ext.aegismesh.io/v1alpha1\n---\n{}\n"),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadManifest(path); err == nil {
				t.Fatal("manifest must fail strict decoding")
			}
		})
	}
}

func TestLoadManifestFileBoundsAndStrictSyntax(t *testing.T) {
	dir := t.TempDir()
	base, err := json.Marshal(validManifest())
	if err != nil {
		t.Fatal(err)
	}
	exact := append(append([]byte(nil), base...), bytes.Repeat([]byte(" "), maxManifestBytes-len(base))...)
	exactPath := filepath.Join(dir, "exact.json")
	if err := os.WriteFile(exactPath, exact, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(exactPath); err != nil {
		t.Fatalf("exact manifest cap rejected: %v", err)
	}
	overPath := filepath.Join(dir, "over.json")
	if err := os.WriteFile(overPath, append(exact, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(overPath); err == nil || !strings.Contains(err.Error(), "no larger than") {
		t.Fatalf("manifest cap+1 must fail, got %v", err)
	}
	if _, err := LoadManifest(dir); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory manifest must fail, got %v", err)
	}

	for name, raw := range map[string][]byte{
		"nested-duplicate.json": []byte(`{"api_version":"a","transport":{"kind":"a","kind":"b"}}`),
		"duplicate.yaml":        []byte("api_version: a\napi_version: b\n"),
		"malformed.yaml":        []byte("api_version: [\n"),
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadManifest(path); err == nil {
			t.Fatalf("strict syntax accepted %s", name)
		}
	}
}

func TestDuplicateJSONScannerDepthBound(t *testing.T) {
	atCap := []byte(strings.Repeat("[", maxJSONDepth) + "0" + strings.Repeat("]", maxJSONDepth))
	if err := rejectDuplicateJSONKeys(atCap); err != nil {
		t.Fatalf("depth %d rejected: %v", maxJSONDepth, err)
	}
	over := []byte(strings.Repeat("[", maxJSONDepth+1) + "0" + strings.Repeat("]", maxJSONDepth+1))
	if err := rejectDuplicateJSONKeys(over); err == nil || !strings.Contains(err.Error(), "nesting exceeds") {
		t.Fatalf("depth %d must fail, got %v", maxJSONDepth+1, err)
	}
}
