package evidenceindex

// Client families form a closed vocabulary derived from a self-reported,
// attacker-controlled User-Agent. The raw value is never retained by the
// projection: only one of these constants is, so it cannot carry text into
// responses. A family is a claim made by the client, not an identification.
const (
	ClientOpenAISDK    = "openai_sdk"
	ClientAnthropicSDK = "anthropic_sdk"
	ClientLangChain    = "langchain"
	ClientLlamaIndex   = "llamaindex"
	ClientLiteLLM      = "litellm"
	ClientOllama       = "ollama_client"
	ClientMCPClient    = "mcp_client"
	ClientScanner      = "scanner"
	ClientBrowser      = "browser"
	ClientCLI          = "cli_http"
	ClientLibrary      = "http_library"
	ClientOther        = "other"
)

// clientMarkers is evaluated in order; the first matching marker wins. Markers
// are lowercase ASCII and compared case-insensitively without allocation.
var clientMarkers = []struct{ marker, family string }{
	{"openai/python", ClientOpenAISDK},
	{"openai/js", ClientOpenAISDK},
	{"openai-python", ClientOpenAISDK},
	{"openai-node", ClientOpenAISDK},
	{"anthropic/python", ClientAnthropicSDK},
	{"anthropic/js", ClientAnthropicSDK},
	{"anthropic-sdk", ClientAnthropicSDK},
	{"langchain", ClientLangChain},
	{"llama-index", ClientLlamaIndex},
	{"llamaindex", ClientLlamaIndex},
	{"litellm", ClientLiteLLM},
	{"ollama-python", ClientOllama},
	{"ollama-js", ClientOllama},
	{"mcp-client", ClientMCPClient},
	{"modelcontextprotocol", ClientMCPClient},
	{"nuclei", ClientScanner},
	{"zgrab", ClientScanner},
	{"masscan", ClientScanner},
	{"nmap", ClientScanner},
	{"sqlmap", ClientScanner},
	{"nikto", ClientScanner},
	{"gobuster", ClientScanner},
	{"fuzz faster u fool", ClientScanner},
	{"ffuf", ClientScanner},
	{"curl/", ClientCLI},
	{"wget/", ClientCLI},
	{"httpie/", ClientCLI},
	{"python-requests", ClientLibrary},
	{"python-httpx", ClientLibrary},
	{"python-urllib", ClientLibrary},
	{"aiohttp", ClientLibrary},
	{"go-http-client", ClientLibrary},
	{"node-fetch", ClientLibrary},
	{"undici", ClientLibrary},
	{"axios", ClientLibrary},
	{"okhttp", ClientLibrary},
	{"mozilla/", ClientBrowser},
}

// SDKClient reports families that self-identify as an LLM SDK or agent framework.
func SDKClient(family string) bool {
	switch family {
	case ClientOpenAISDK, ClientAnthropicSDK, ClientLangChain, ClientLlamaIndex, ClientLiteLLM, ClientOllama, ClientMCPClient:
		return true
	}
	return false
}

// ClientFamily maps a stored User-Agent to the closed family vocabulary. Empty
// input returns "", unmatched input returns ClientOther. Only the first 256
// bytes are examined.
func ClientFamily(userAgent string) string {
	if userAgent == "" {
		return ""
	}
	if len(userAgent) > 256 {
		userAgent = userAgent[:256]
	}
	for _, candidate := range clientMarkers {
		if containsFold(userAgent, candidate.marker) {
			return candidate.family
		}
	}
	return ClientOther
}

// containsFold reports whether lower (lowercase ASCII) occurs in value under
// ASCII case folding. Non-ASCII bytes never match an ASCII marker byte.
func containsFold(value, lower string) bool {
	if len(lower) == 0 {
		return true
	}
	for i := 0; i+len(lower) <= len(value); i++ {
		match := true
		for j := 0; j < len(lower); j++ {
			c := value[i+j]
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != lower[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
