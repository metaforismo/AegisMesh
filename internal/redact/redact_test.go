package redact

import (
	"strings"
	"testing"
)

func TestScrubCredentialPatterns(t *testing.T) {
	cases := []struct{ in, mustNotContain string }{
		{"user=admin password=hunter2 rest", "hunter2"},
		{"Authorization: Bearer abc.def", "abc.def"},
		{"token=abcdef123456; path=/", "abcdef123456"},
		{"api_key: sk-1234567890abcdef", "sk-1234567890"},
		{"pass=secret123 end", "secret123"},
		{"Cookie: sessionid=zzz; other=1", "sessionid=zzz"},
		{`{"password":"hunter2","run_id":1234}`, "hunter2"},
		{`{"api_key": "sk-1234567890abcdef"}`, "sk-1234567890abcdef"},
		{`{"client_secret":"abc","n":1}`, "abc"},
		{`{"token":tok_abc123}`, "tok_abc123"},
	}
	for _, tc := range cases {
		got := Scrub(tc.in)
		if strings.Contains(got, tc.mustNotContain) {
			t.Errorf("Scrub(%q) = %q, still contains %q", tc.in, got, tc.mustNotContain)
		}
		if !strings.Contains(got, "[redacted]") {
			t.Errorf("Scrub(%q) = %q, want a [redacted] marker", tc.in, got)
		}
	}
}

func TestScrubPrivateKey(t *testing.T) {
	// Synthetic fixture: not a real key, exercises the PEM rule.
	in := "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\ndef\n-----END RSA PRIVATE KEY----- trailing" // secret-scan:allow
	got := Scrub(in)
	if strings.Contains(got, "MIIabc") {
		t.Fatalf("private key body survived: %q", got)
	}
}

func TestPreviewBoundedAndEscaped(t *testing.T) {
	long := strings.Repeat("A", 2000)
	out, truncated := Preview([]byte(long), MaxPreviewBytes)
	if !truncated || len(out) > MaxPreviewBytes+len(TruncationMarker)+16 {
		t.Fatalf("truncation broken: truncated=%v len=%d", truncated, len(out))
	}
	ctrl, _ := Preview([]byte("a\x00\x01b"), 100)
	if ctrl != "a??b" {
		t.Fatalf("control chars not neutralized: %q", ctrl)
	}
	nl, _ := Preview([]byte("line1\r\nline2\tend"), 100)
	if nl != `line1\r\nline2\tend` {
		t.Fatalf("escape wrong: %q", nl)
	}
	bad, _ := Preview([]byte{0xff, 0xfe, 'o', 'k'}, 100)
	if !strings.Contains(bad, `\xff`) || !strings.Contains(bad, "ok") {
		t.Fatalf("invalid utf8 handling: %q", bad)
	}
}

func TestPreviewScrubsCredentials(t *testing.T) {
	out, _ := Preview([]byte("POST user=x pass=secret123 end"), 512)
	if strings.Contains(out, "secret123") {
		t.Fatalf("credential leaked through preview: %q", out)
	}
}

func TestHeaderPolicy(t *testing.T) {
	p := DefaultHeaderPolicy()
	if got := p.Header("User-Agent", "curl/8.4"); got != "curl/8.4" {
		t.Fatalf("user-agent should be kept: %q", got)
	}
	if got := p.Header("X-Custom-Auth", "super-secret-value"); got == "super-secret-value" || !strings.Contains(got, "[redacted:") {
		t.Fatalf("unknown header must be redacted with length: %q", got)
	}
	longUA := strings.Repeat("u", 500)
	got := p.Header("User-Agent", longUA)
	if !strings.Contains(got, TruncationMarker) {
		t.Fatalf("kept header values must be length-capped: %d", len(got))
	}
}

func TestSHA256HexKnownVector(t *testing.T) {
	// sha256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := SHA256Hex([]byte("abc")); got != want {
		t.Fatalf("SHA256Hex(abc) = %s", got)
	}
}

func TestProviderShapesAndMemoryOnlyAuthDigests(t *testing.T) {
	for _, key := range []string{"sk-synthetic-example", "sk-ant-synthetic-example", "ghp_synthetic_example", "AKIA-SYNTHETIC-EXAMPLE"} {
		if strings.Contains(Scrub("/path/"+key), key) {
			t.Fatal("provider shape leaked")
		}
	}
	a := AuthDigest("password", "ab", "c")
	b := AuthDigest("password", "a", "bc")
	if a == b || len(a) != 64 {
		t.Fatal("digest framing is ambiguous")
	}
	headers := map[string][]string{"authorization": {"Basic YWI6Yw==", "Basic invalid!"}, "x-api-key": {"synthetic-key-example"}}
	got := HTTPAuthAttempts(headers)
	if len(got) != 2 || got[0] != a || got[1] != AuthDigest("key", "", "synthetic-key-example") {
		t.Fatal("HTTP/SSH distinctness mismatch")
	}
}

func FuzzHTTPAuthAttempts(f *testing.F) {
	f.Add("Basic c3ludGhldGljOnR5cG8=")
	f.Add("Bearer sk-synthetic-example")
	f.Add("Basic invalid!")
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 16385 {
			return
		}
		attempts := HTTPAuthAttempts(map[string][]string{"authorization": {value}})
		if len(attempts) > 1 {
			t.Fatal("one header produced several attempts")
		}
		for _, digest := range attempts {
			if len(digest) != 64 {
				t.Fatal("unbounded digest")
			}
			for _, c := range digest {
				if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
					t.Fatal("raw credential content escaped")
				}
			}
		}
	})
}

func TestPresentedKeyContextsRemoveWholeValues(t *testing.T) {
	longKey := "sk-" + strings.Repeat("q", 400)
	for _, tc := range []struct{ input, value string }{
		{"AUTH ollama", "ollama"}, {" AUTH EMPTY ", "EMPTY"}, {"AUTH synthetic-user sk-xxxx", "sk-xxxx"},
		{`{"key":"EMPTY"}`, "EMPTY"}, {"ollama", "ollama"}, {"AUTH " + longKey, longKey}, {longKey, longKey},
	} {
		scrubbed := Scrub(tc.input)
		if strings.Contains(scrubbed, tc.value) {
			t.Errorf("presented credential context was not fully scrubbed")
		}
	}
}
