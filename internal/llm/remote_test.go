package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/metaforismo/aegismesh/internal/egress"
)

func completionBody(text string) string {
	return `{"choices":[{"message":{"role":"assistant","content":` + quoteJSON(text) + `}}]}`
}

func quoteJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestRemoteHappyPathAndRequestShape(t *testing.T) {
	var gotAuth, gotUA, gotPath, gotModel string
	var gotMessages int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotUA = r.Header.Get("User-Agent")
		gotPath = r.URL.Path
		var req chatRequest
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &req)
		gotModel = req.Model
		gotMessages = len(req.Messages)
		if req.Stream {
			t.Error("stream must be false")
		}
		w.Write([]byte(completionBody("synthetic reply"))) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	r, err := NewRemote(RemoteConfig{
		Name: "ollama", BaseURL: srv.URL, Model: "llama3",
		APIKey: "sk-test-123", AllowLoopback: true,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewRemote: %v", err)
	}
	resp, err := r.Complete(context.Background(), Request{
		SystemPrompt: "be a decoy",
		Messages:     []Message{{Role: "user", Content: "hello"}},
		MaxChars:     512,
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Text != "synthetic reply" || resp.Provider != "ollama" || resp.Model != "llama3" {
		t.Fatalf("response metadata wrong: %+v", resp)
	}
	if gotPath != "/chat/completions" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuth != "Bearer sk-test-123" {
		t.Fatalf("auth header = %q", gotAuth)
	}
	if !strings.Contains(gotUA, "aegismesh") {
		t.Fatalf("user-agent = %q", gotUA)
	}
	if gotModel != "llama3" || gotMessages != 2 { // system + user
		t.Fatalf("model=%q messages=%d", gotModel, gotMessages)
	}
}

func TestRemoteOmitsAuthorizationWithoutKey(t *testing.T) {
	sawAuth := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			sawAuth = true
		}
		w.Write([]byte(completionBody("ok"))) //nolint:errcheck // test handler
	}))
	defer srv.Close()
	r, err := NewRemote(RemoteConfig{BaseURL: srv.URL, Model: "m", AllowLoopback: true, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Complete(context.Background(), Request{MaxChars: 16}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if sawAuth {
		t.Fatal("Authorization sent without a key configured")
	}
}

func TestRemoteContextCancellationHonored(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // park until the test cancels
	}))
	defer srv.Close()
	defer close(release)

	r, err := NewRemote(RemoteConfig{BaseURL: srv.URL, Model: "m", AllowLoopback: true, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := r.Complete(ctx, Request{MaxChars: 32})
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.Canceled) {
			t.Fatalf("want wrapped context.Canceled via ErrUnavailable, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not interrupt the in-flight request")
	}
}

func TestRemoteFailureModesTyped(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		wantErr error
	}{
		{
			"server 500",
			func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) },
			ErrUnavailable,
		},
		{
			"rate limited 429",
			func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTooManyRequests) },
			ErrUnavailable,
		},
		{
			"unauthorized 401",
			func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) },
			ErrBadResponse,
		},
		{
			"malformed json",
			func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "{not json") },
			ErrBadResponse,
		},
		{
			"no choices",
			func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, `{"choices":[]}`) },
			ErrBadResponse,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			r, err := NewRemote(RemoteConfig{BaseURL: srv.URL, Model: "m", AllowLoopback: true, HTTPClient: srv.Client()})
			if err != nil {
				t.Fatal(err)
			}
			_, cerr := r.Complete(context.Background(), Request{MaxChars: 64})
			if !errors.Is(cerr, tc.wantErr) {
				t.Fatalf("err = %v, want wrapping %v", cerr, tc.wantErr)
			}
		})
	}
}

// Provider error text can echo prompt content back; the client must not pass
// it through — both on the 4xx status path (body ignored entirely) and on the
// 2xx-with-error-object path (shape reported, detail withheld).
func TestRemoteProviderErrorDetailWithheld(t *testing.T) {
	t.Run("4xx body ignored", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnprocessableEntity)
			io.WriteString(w, `{"error":{"message":"cannot process CANARY-PAYLOAD-XYZ"}}`)
		}))
		defer srv.Close()
		r, err := NewRemote(RemoteConfig{BaseURL: srv.URL, Model: "m", AllowLoopback: true, HTTPClient: srv.Client()})
		if err != nil {
			t.Fatal(err)
		}
		_, cerr := r.Complete(context.Background(), Request{})
		if !errors.Is(cerr, ErrBadResponse) || strings.Contains(cerr.Error(), "CANARY-PAYLOAD") {
			t.Fatalf("provider detail leaked or wrong type: %v", cerr)
		}
	})
	t.Run("2xx error object withheld", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, `{"error":{"message":"upstream says CANARY-PAYLOAD-XYZ"},"choices":[]}`)
		}))
		defer srv.Close()
		r, err := NewRemote(RemoteConfig{BaseURL: srv.URL, Model: "m", AllowLoopback: true, HTTPClient: srv.Client()})
		if err != nil {
			t.Fatal(err)
		}
		_, cerr := r.Complete(context.Background(), Request{})
		if !strings.Contains(cerr.Error(), "withheld") || strings.Contains(cerr.Error(), "CANARY-PAYLOAD") {
			t.Fatalf("provider detail leaked or wrong shape: %v", cerr)
		}
	})
}

func TestRemoteResponseTooLarge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(bytes.Repeat([]byte("a"), 4096)) //nolint:errcheck // test handler
	}))
	defer srv.Close()
	r, err := NewRemote(RemoteConfig{BaseURL: srv.URL, Model: "m", AllowLoopback: true,
		HTTPClient: srv.Client(), MaxResponseBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	_, cerr := r.Complete(context.Background(), Request{})
	if !errors.Is(cerr, ErrResponseTooLarge) {
		t.Fatalf("err = %v, want ErrResponseTooLarge", cerr)
	}
}

// No retries is policy: one failed attempt means exactly one request.
func TestRemoteNeverRetries(t *testing.T) {
	count := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	r, err := NewRemote(RemoteConfig{BaseURL: srv.URL, Model: "m", AllowLoopback: true, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = r.Complete(context.Background(), Request{})
	if count != 1 {
		t.Fatalf("requests = %d, want exactly 1 (no retry policy)", count)
	}
}

func TestNewRemoteFailsClosedOnPolicyViolations(t *testing.T) {
	cases := []struct {
		name   string
		cfg    RemoteConfig
		wantEr error
	}{
		{"metadata endpoint", RemoteConfig{Name: "openai", BaseURL: "http://169.254.169.254/v1", Model: "m"}, ErrBadEndpoint},
		{"cleartext public", RemoteConfig{Name: "openai", BaseURL: "http://api.openai.com/v1", Model: "m"}, ErrBadEndpoint},
		{"ftp scheme", RemoteConfig{Name: "openai", BaseURL: "ftp://api.example.com", Model: "m"}, ErrBadEndpoint},
		{"empty model", RemoteConfig{Name: "openai", BaseURL: "https://api.example.com/v1"}, ErrBadEndpoint},
		{"loopback needs opt-in", RemoteConfig{Name: "openai", BaseURL: "http://127.0.0.1:11434/v1", Model: "m"}, ErrBadEndpoint},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewRemote(tc.cfg)
			if !errors.Is(err, tc.wantEr) {
				t.Fatalf("err = %v, want %v", err, tc.wantEr)
			}
		})
	}
	_, err := NewRemote(RemoteConfig{Name: "openai", BaseURL: "http://169.254.169.254/v1", Model: "m"})
	if !egress.IsDenied(err) {
		t.Fatalf("endpoint denial should carry egress typing: %v", err)
	}
}

func TestCharsToTokensBounds(t *testing.T) {
	if got := charsToTokens(0); got != 256 {
		t.Fatalf("zero chars → %d tokens", got)
	}
	if got := charsToTokens(8); got != 16 {
		t.Fatalf("tiny budget → %d tokens, want floor 16", got)
	}
	if got := charsToTokens(1 << 20); got != maxCompletionTokensCap {
		t.Fatalf("huge budget not capped: %d", got)
	}
	if got := charsToTokens(400); got != 100 {
		t.Fatalf("400 chars → %d tokens, want 100", got)
	}
}

func TestPromptCharBudgetTruncatesBeforeSend(t *testing.T) {
	var gotLen int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req chatRequest
		json.Unmarshal(raw, &req)
		for _, m := range req.Messages {
			gotLen += len(m.Content)
		}
		w.Write([]byte(completionBody("ok"))) //nolint:errcheck // test handler
	}))
	defer srv.Close()
	r, err := NewRemote(RemoteConfig{BaseURL: srv.URL, Model: "m", AllowLoopback: true, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	huge := strings.Repeat("x", maxPromptChars+5000)
	_, err = r.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: huge}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotLen > maxPromptChars {
		t.Fatalf("sent %d prompt chars, cap is %d", gotLen, maxPromptChars)
	}
}
