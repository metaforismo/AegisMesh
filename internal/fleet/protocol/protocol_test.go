package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCanonicalAndParser(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"name":"node"}`)
	request := httptest.NewRequest("POST", HeartbeatPath, nil)
	if err := Sign(request, body, private, time.Unix(1800000000, 0)); err != nil {
		t.Fatal(err)
	}
	auth, canonical, err := Parse(request, body)
	if err != nil || !ed25519.Verify(public, []byte(canonical), auth.Signature) {
		t.Fatalf("parse/sign: %v", err)
	}
	want := strings.Join([]string{
		"AEGISMESH-FLEET/1", ID(public), "POST", HeartbeatPath, Digest(body), "1800000000", auth.Nonce,
	}, "\n")
	if canonical != want {
		t.Fatalf("canonical = %q", canonical)
	}
	for _, test := range []struct {
		name   string
		mutate func()
	}{
		{
			name:   "duplicate nonce",
			mutate: func() { request.Header.Add("X-AegisMesh-Nonce", auth.Nonce) },
		},
		{
			name:   "noncanonical timestamp",
			mutate: func() { request.Header.Set("X-AegisMesh-Time", "01800000000") },
		},
		{
			name:   "upper hex",
			mutate: func() { request.Header.Set("X-AegisMesh-Node", strings.Repeat("A", 32)) },
		},
		{
			name:   "encoded path",
			mutate: func() { request.URL.RawPath = "/fleet/v1/%68eartbeat" },
		},
		{
			name:   "query",
			mutate: func() { request.URL.RawQuery = "a=b" },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request = httptest.NewRequest("POST", HeartbeatPath, nil)
			if err := Sign(request, body, private, time.Now()); err != nil {
				t.Fatal(err)
			}
			test.mutate()
			if _, _, err := Parse(request, body); err == nil {
				t.Fatal("accepted noncanonical input")
			}
		})
	}
}

func TestStrictDecode(t *testing.T) {
	for _, body := range []string{
		`null`, `{} {}`, `{"name":"aaa","name":"bbb"}`, `{"unknown":true}`, strings.Repeat("[", 64),
		`{"name":"aaa","sensors":[{"id":"abc","id":"def"}]}`,
	} {
		var heartbeat Heartbeat
		if Decode([]byte(body), &heartbeat) == nil {
			t.Fatalf("accepted %s", body)
		}
	}
}

func FuzzFleetProtocol(f *testing.F) {
	f.Add("POST", HeartbeatPath, "1800000000", strings.Repeat("0", 32), []byte(`{"name":"node"}`))
	f.Add("GET", EnrollPath, "-1", "\n", []byte(`{"name":"a","name":"b"}`))
	f.Fuzz(func(t *testing.T, method, path, timestamp, nonce string, body []byte) {
		if len(method)+len(path)+len(timestamp)+len(nonce)+len(body) > MaxBodyBytes+1024 {
			return
		}
		request := httptest.NewRequest("POST", HeartbeatPath, nil)
		request.Method = method
		request.URL.Path = path
		request.Header.Set("X-AegisMesh-Node", strings.Repeat("0", 32))
		request.Header.Set("X-AegisMesh-Time", timestamp)
		request.Header.Set("X-AegisMesh-Nonce", nonce)
		request.Header.Set("X-AegisMesh-Signature", strings.Repeat("0", 128))
		auth, canonical, err := Parse(request, body)
		if err == nil {
			again, err := Canonical(method, path, body, auth)
			if err != nil || again != canonical || strings.HasSuffix(canonical, "\n") {
				t.Fatal("noncanonical accepted request")
			}
		}
		var enrollment Enrollment
		_ = Decode(body, &enrollment)
		var heartbeat Heartbeat
		_ = Decode(body, &heartbeat)
	})
}
