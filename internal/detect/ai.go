package detect

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/metaforismo/aegismesh/internal/honeytoken"
)

const (
	RuleAISurface    RuleID = "LLM-001"
	RuleMinimalProbe RuleID = "LLM-002"
	RuleAIManagement RuleID = "LLM-003"
	RuleProviderKey  RuleID = "LLM-004"
	RuleHoneytoken   RuleID = "HT-001"
	RuleAgentCanary  RuleID = "AGT-001"
)

type AIFamily string

const (
	FamilyOllama  AIFamily = "ollama"
	FamilyOpenAI  AIFamily = "openai_compatible"
	FamilyLiteLLM AIFamily = "litellm"
	FamilyVLLM    AIFamily = "vllm"
	FamilyMCP     AIFamily = "mcp_http"
)

// SurfaceFamily uses request structure, never prose mentions or user-agent.
// Shared /v1 paths default to openai_compatible; they cannot identify a server.
func SurfaceFamily(in Input) AIFamily {
	path := requestPath(in.Path)
	if in.Protocol == "mcp" {
		return FamilyMCP
	}
	if strings.HasPrefix(path, "/v1/models/") {
		return FamilyOpenAI
	}
	switch path {
	case "/api/version", "/api/tags", "/api/ps", "/api/generate", "/api/chat", "/api/show", "/api/pull", "/api/push", "/api/create", "/api/delete", "/api/copy", "/api/embed", "/api/embeddings":
		return FamilyOllama
	case "/v1/models", "/v1/chat/completions", "/v1/completions", "/v1/embeddings":
		return FamilyOpenAI
	case "/health/liveliness", "/health/readiness", "/model/info", "/model/new", "/model/delete", "/model/update", "/key/info", "/key/generate", "/key/delete", "/key/update":
		return FamilyLiteLLM
	case "/version", "/metrics":
		return FamilyVLLM
	case "/mcp", "/sse":
		return FamilyMCP
	}
	return ""
}

func aiManagement(in Input) bool {
	if in.Method != "POST" && in.Method != "DELETE" && in.Method != "PUT" {
		return false
	}
	path := requestPath(in.Path)
	if in.Method == "DELETE" && strings.HasPrefix(path, "/v1/models/") && len(path) > len("/v1/models/") {
		return true
	}
	switch path {
	case "/api/pull", "/api/push", "/api/create", "/api/delete", "/api/copy", "/key/generate", "/key/delete", "/key/update", "/model/new", "/model/delete", "/model/update":
		return true
	}
	return false
}

// minimalProbe parses only bounded completion-shaped JSON. No content is
// returned. Unknown fields are allowed as real inference clients add options.
func minimalProbe(in Input) bool {
	if in.Method != "POST" || len(in.Body) == 0 || len(in.Body) > hardMaxScanBytes {
		return false
	}
	path := requestPath(in.Path)
	switch path {
	case "/api/generate", "/api/chat", "/v1/completions", "/v1/chat/completions":
	default:
		return false
	}
	var v struct {
		Prompt     string `json:"prompt"`
		MaxTokens  *int   `json:"max_tokens"`
		NumPredict *int   `json:"num_predict"`
		Options    struct {
			NumPredict *int `json:"num_predict"`
		} `json:"options"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if json.Unmarshal([]byte(in.Body), &v) != nil {
		return false
	}
	tiny := false
	for _, n := range []*int{v.MaxTokens, v.NumPredict, v.Options.NumPredict} {
		if n != nil {
			if *n < 0 || *n > 5 {
				return false
			}
			tiny = true
		}
	}
	if !tiny {
		return false
	}
	chars := len(strings.TrimSpace(v.Prompt))
	if len(v.Messages) > 2 {
		return false
	}
	user := chars > 0
	for _, msg := range v.Messages {
		if msg.Role != "user" && msg.Role != "system" {
			return false
		}
		chars += len(strings.TrimSpace(msg.Content))
		user = user || msg.Role == "user" && strings.TrimSpace(msg.Content) != ""
	}
	return user && chars > 0 && chars <= 32
}

// CredentialClass returns a format label only. Values never leave this seam.
func CredentialClass(headers map[string][]string) string {
	for _, name := range []string{"authorization", "proxy-authorization", "x-api-key", "api-key"} {
		for _, v := range headers[name] {
			v = strings.TrimSpace(v)
			if name == "authorization" || name == "proxy-authorization" {
				scheme, value, ok := strings.Cut(v, " ")
				if !ok || !strings.EqualFold(scheme, "bearer") {
					continue
				}
				v = strings.TrimSpace(value)
			}
			if len(v) > 512 {
				continue
			}
			switch {
			case strings.EqualFold(v, "EMPTY"), strings.EqualFold(v, "ollama"), v == "sk-xxxx":
				return "placeholder"
			case strings.HasPrefix(v, "sk-ant-"):
				return "anthropic_like"
			case strings.HasPrefix(v, "sk-") && len(v) >= 7:
				return "openai_like"
			case strings.HasPrefix(v, "AKIA") && len(v) >= 16:
				return "aws_like"
			case strings.HasPrefix(v, "ghp_") || strings.HasPrefix(v, "github_pat_"):
				return "github_like"
			}
		}
	}
	return ""
}

func tokenKind(in Input, kind string) bool {
	for _, m := range in.TokenMatches {
		if m.Kind == kind {
			return true
		}
	}
	return false
}

func aiRules() []rule {
	return []rule{
		{RuleAISurface, SevLow, ConfHigh, "request targeted a known AI inference or management API surface", func(in Input, _ string) bool { return SurfaceFamily(in) != "" }},
		{RuleMinimalProbe, SevMedium, ConfMedium, "short completion request with a tiny token budget; consistent with minimal-cost credential validation", func(in Input, _ string) bool { return minimalProbe(in) }},
		{RuleAIManagement, SevMedium, ConfMedium, "model or key management attempt on an AI surface; consistent with resource hijacking", func(in Input, _ string) bool { return aiManagement(in) }},
		{RuleProviderKey, SevLow, ConfMedium, "a provider-shaped API key or known placeholder was presented to a decoy", func(in Input, _ string) bool { return presentedKeyClass(in) != "" }},
		{RuleHoneytoken, SevCritical, ConfHigh, "a credential that exists only in decoy material was presented", func(in Input, _ string) bool { return tokenKind(in, honeytoken.Credential) }},
		{RuleAgentCanary, SevHigh, ConfMedium, "interaction followed an instruction embedded in decoy content; consistent with an LLM-driven client", func(in Input, _ string) bool { return tokenKind(in, honeytoken.AgentCanary) }},
	}
}

// ObserveOnly keeps new observations out of existing response enforcement.
func ObserveOnly(id RuleID) bool {
	switch id {
	case RuleAISurface, RuleMinimalProbe, RuleAIManagement, RuleProviderKey, RuleHoneytoken, RuleAgentCanary:
		return true
	}
	return false
}

func requestPath(target string) string {
	path, _, _ := strings.Cut(target, "?")
	if decoded, err := url.PathUnescape(path); err == nil {
		return decoded
	}
	return path
}

// Only credential contexts are inspected: arbitrary mentions in prose are
// not presentations. Every parser receives an independently bounded field.
func presentedKeyClass(in Input) string {
	if class := CredentialClass(in.Headers); class != "" {
		return class
	}
	values := []string{}
	if len(in.Body) > 0 && len(in.Body) <= hardMaxScanBytes {
		var fields struct {
			APIKey string `json:"api_key"`
			Key    string `json:"key"`
			Token  string `json:"token"`
		}
		if json.Unmarshal([]byte(in.Body), &fields) == nil {
			values = append(values, fields.APIKey, fields.Key, fields.Token)
		}
	}
	if _, query, ok := strings.Cut(in.Path, "?"); ok {
		if parsed, err := url.ParseQuery(query); err == nil {
			for _, name := range []string{"api_key", "key", "token"} {
				v := parsed[name]
				values = append(values, v[:min(len(v), 16)]...)
			}
		}
	}
	if in.Protocol == "tcp" {
		fields := strings.Fields(in.Text)
		if len(fields) == 1 {
			values = append(values, fields[0])
		}
		if (len(fields) == 2 || len(fields) == 3) && strings.EqualFold(fields[0], "AUTH") {
			values = append(values, fields[len(fields)-1])
		}
	}
	return CredentialClass(map[string][]string{"x-api-key": values})
}

func keyCharacters(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range []byte(value) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
