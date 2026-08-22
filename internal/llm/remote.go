package llm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/metaforismo/aegismesh/internal/egress"
)

// Typed provider errors. Callers branch on these with errors.Is; every error
// returned by Remote wraps exactly one of them plus actionable context.
var (
	// ErrBadEndpoint: the configured base URL violated the egress policy.
	ErrBadEndpoint = errors.New("llm: endpoint rejected")
	// ErrUnavailable: transport-level failure (connection, timeout, 5xx).
	ErrUnavailable = errors.New("llm: provider unavailable")
	// ErrBadResponse: a response arrived but is not a usable completion.
	ErrBadResponse = errors.New("llm: malformed provider response")
	// ErrResponseTooLarge: body exceeded max_response_bytes.
	ErrResponseTooLarge = errors.New("llm: provider response exceeded limit")
)

const (
	defaultRemoteTimeout   = 20 * time.Second
	defaultMaxRespBytes    = int64(1 << 20)
	dialTimeout            = 10 * time.Second
	maxCompletionTokensCap = 2048
)

// RemoteConfig constructs an OpenAI-compatible chat-completions client.
//
// The same wire format serves both named providers: "openai" (any generic
// OpenAI-compatible endpoint) and "ollama" (which exposes one at
// http://127.0.0.1:11434/v1). The distinction is deliberate policy, not
// duplication: ollama implies loopback/cleartext permission, openai implies
// none.
type RemoteConfig struct {
	Name             string // evidence label: "ollama" | "openai"
	BaseURL          string // validated through internal/egress before use
	Model            string
	APIKey           string // resolved secret; empty omits Authorization entirely
	AllowLoopback    bool   // egress opt-in for loopback destinations
	AllowPrivate     bool   // egress opt-in for RFC1918/ULA gateways
	Timeout          time.Duration
	MaxResponseBytes int64

	// HTTPClient replaces the constructed transport entirely. Tests inject
	// httptest clients here; production leaves it nil so the guarded
	// transport (egress dialer, no proxies, TLS 1.2+) is used.
	HTTPClient *http.Client
}

// Remote is a guarded OpenAI-compatible provider. It implements Provider.
type Remote struct {
	name    string
	model   string
	apiKey  string
	base    *string // normalized base URL without trailing slash
	maxBody int64
	client  *http.Client
}

var _ Provider = (*Remote)(nil)

// NewRemote validates the endpoint against the egress policy and builds the
// client. Construction fails closed: an unusable endpoint is a configuration
// error, not something to discover mid-attack-capture.
func NewRemote(cfg RemoteConfig) (*Remote, error) {
	pol := egress.Policy{AllowLoopback: cfg.AllowLoopback, AllowPrivate: cfg.AllowPrivate}
	u, err := egress.ValidateURL(pol, cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrBadEndpoint, cfg.Name, err)
	}
	if strings.TrimSpace(cfg.Model) == "" {
		return nil, fmt.Errorf("%w: model name is required", ErrBadEndpoint)
	}
	name := cfg.Name
	if name == "" {
		name = "openai"
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultRemoteTimeout
	}
	maxBody := cfg.MaxResponseBytes
	if maxBody <= 0 {
		maxBody = defaultMaxRespBytes
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				// Deliberately NOT ProxyFromEnvironment: proxy variables would
				// silently reroute captured attacker traffic through another
				// host outside this package's control.
				Proxy:       nil,
				DialContext: egress.NewDialer(pol, dialTimeout).DialContext,
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
				MaxIdleConns:        4,
				MaxConnsPerHost:     4,
				IdleConnTimeout:     30 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
			},
			CheckRedirect: egress.RefuseAllRedirects,
		}
	}
	base := strings.TrimRight(u.String(), "/")
	return &Remote{
		name:    name,
		model:   cfg.Model,
		apiKey:  cfg.APIKey,
		base:    &base,
		maxBody: maxBody,
		client:  client,
	}, nil
}

func (r *Remote) Name() string { return r.name }

// chatRequest/chatResponse are the OpenAI-compatible wire shapes we rely on.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model     string        `json:"model"`
	Messages  []chatMessage `json:"messages"`
	MaxTokens int           `json:"max_tokens"`
	Stream    bool          `json:"stream"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

const maxPromptChars = 32 << 10

// Complete calls POST {base}/chat/completions.
//
// NO RETRIES, deliberately: this path carries attacker-influenced prompts to
// possibly-metered endpoints, where blind retries duplicate spend and add
// latency to a decoy answer nobody is waiting for. Gates already degrade to
// static responses when the provider errors; that is the retry policy.
//
// CONTEXT CONTRACT: honored — cancellation interrupts the in-flight request.
func (r *Remote) Complete(ctx context.Context, req Request) (Response, error) {
	start := time.Now()
	msgs := make([]chatMessage, 0, len(req.Messages)+1)
	if req.SystemPrompt != "" {
		msgs = append(msgs, chatMessage{Role: "system", Content: req.SystemPrompt})
	}
	totalChars := len(req.SystemPrompt)
	for _, m := range req.Messages {
		c := m.Content
		if totalChars+len(c) > maxPromptChars {
			c = c[:maxInt(0, maxPromptChars-totalChars)]
		}
		totalChars += len(c)
		msgs = append(msgs, chatMessage{Role: m.Role, Content: c})
		if totalChars >= maxPromptChars {
			break
		}
	}
	payload, err := json.Marshal(chatRequest{
		Model:     r.model,
		Messages:  msgs,
		MaxTokens: charsToTokens(req.MaxChars),
		Stream:    false,
	})
	if err != nil {
		return Response{}, fmt.Errorf("%w: encode request: %v", ErrBadResponse, err)
	}
	endpoint := *r.base + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return Response{}, fmt.Errorf("%w: build request for %s: %v", ErrBadEndpoint, endpoint, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "aegismesh-decoy/1")
	if r.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+r.apiKey)
	}
	resp, err := r.client.Do(httpReq)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Response{}, fmt.Errorf("%w: %w", ErrUnavailable, ctxErr)
		}
		return Response{}, fmt.Errorf("%w: POST %s: %v", ErrUnavailable, endpoint, err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		// fall through to decode below
	case resp.StatusCode == 429 || resp.StatusCode >= 500:
		return Response{}, fmt.Errorf("%w: status %d from %s", ErrUnavailable, resp.StatusCode, r.name)
	default:
		// 4xx others (401/403/404/422...): configuration-shaped failures. The
		// body is intentionally NOT included — it can echo prompt content.
		return Response{}, fmt.Errorf("%w: status %d from %s (check endpoint/model/credentials)", ErrBadResponse, resp.StatusCode, r.name)
	}

	body := io.LimitReader(resp.Body, r.maxBody+1)
	raw, err := io.ReadAll(body)
	if err != nil {
		return Response{}, fmt.Errorf("%w: read body: %v", ErrUnavailable, err)
	}
	if int64(len(raw)) > r.maxBody {
		return Response{}, fmt.Errorf("%w: cap is %d bytes", ErrResponseTooLarge, r.maxBody)
	}
	var cr chatResponse
	if err := json.Unmarshal(raw, &cr); err != nil {
		return Response{}, fmt.Errorf("%w: not JSON: %v", ErrBadResponse, err)
	}
	if cr.Error != nil && cr.Error.Message != "" {
		// Provider-side error text may quote user content; report shape only.
		return Response{}, fmt.Errorf("%w: provider reported an error (%d chars of detail withheld)", ErrBadResponse, len(cr.Error.Message))
	}
	if len(cr.Choices) == 0 || cr.Choices[0].Message.Content == "" {
		return Response{}, fmt.Errorf("%w: no completion choices returned", ErrBadResponse)
	}
	text := cr.Choices[0].Message.Content
	if req.MaxChars > 0 && len(text) > req.MaxChars {
		text = text[:req.MaxChars]
	}
	return Response{
		Text:      text,
		Provider:  r.name,
		Model:     r.model,
		LatencyMS: time.Since(start).Milliseconds(),
	}, nil
}

// charsToTokens maps our char budget onto the API's token budget at roughly
// 4 chars/token. An honest approximation: providers clamp independently and
// the caller re-applies its own char cap to the result regardless.
func charsToTokens(chars int) int {
	if chars <= 0 {
		return 256
	}
	tokens := int(math.Ceil(float64(chars) / 4))
	if tokens < 16 {
		tokens = 16
	}
	if tokens > maxCompletionTokensCap {
		tokens = maxCompletionTokensCap
	}
	return tokens
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
