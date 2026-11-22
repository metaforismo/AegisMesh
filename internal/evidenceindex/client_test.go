package evidenceindex

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/event"
)

func TestClientFamily(t *testing.T) {
	for _, tc := range []struct {
		ua, want string
		sdk      bool
	}{
		{"", "", false},
		{"OpenAI/Python 1.54.0", ClientOpenAISDK, true},
		{"openai/js 4.70.0", ClientOpenAISDK, true},
		{"Anthropic/Python 0.39.0", ClientAnthropicSDK, true},
		{"python-requests/2.32 langchain/0.3", ClientLangChain, true},
		{"llama-index/0.11", ClientLlamaIndex, true},
		{"litellm/1.50", ClientLiteLLM, true},
		{"ollama-python/0.3.3", ClientOllama, true},
		{"Mozilla/5.0 (compatible; Nuclei - Open-source project)", ClientScanner, false},
		{"curl/8.7.1", ClientCLI, false},
		{"python-requests/2.32.3", ClientLibrary, false},
		{"Go-http-client/1.1", ClientLibrary, false},
		{"Mozilla/5.0 (X11; Linux x86_64)", ClientBrowser, false},
		{"synthetic-agent/0.1", ClientOther, false},
		{strings.Repeat("x", 300) + "openai/python", ClientOther, false},
		{"ＯｐｅｎＡＩ/Python", ClientOther, false},
	} {
		if got := ClientFamily(tc.ua); got != tc.want || SDKClient(got) != tc.sdk {
			t.Fatalf("%q -> %q (sdk %t), want %q", tc.ua, got, SDKClient(got), tc.want)
		}
	}
}

func TestProjectionClientFamilyAndStatus(t *testing.T) {
	for _, tc := range []struct {
		kind, class, observation, client string
		status                           int
	}{
		{"http", "interaction", `{"method":"GET","path":"/v1/models","user_agent":"OpenAI/Python 1.0","response":{"status":200},"remote_host":"192.0.2.1"}`, ClientOpenAISDK, 200},
		{"http", "interaction", `{"method":"GET","path":"/x","response":{"status":999}}`, "", 0},
		{"http", "interaction", `{"path":"/x","user_agent":"curl/8","response":{"status":404}}`, ClientCLI, 0},
		{"mcp", "interaction", `{"method":"tools/list","user_agent":"OpenAI/Python 1.0"}`, "", 0},
		{"http", "correlation_signal", `{"rule_id":"COR-005","summary":"x","source_key":"192.0.2.1","user_agent":"OpenAI/Python 1.0"}`, "", 0},
	} {
		envelope, err := event.New(&event.Sequencer{}, "synthetic", event.SensorRef{ID: "s", Kind: tc.kind}, tc.class, json.RawMessage(tc.observation), nil)
		if err != nil {
			t.Fatal(err)
		}
		summary, _, _ := Project(envelope)
		if summary.ClientFamily != tc.client || summary.HTTPStatus != tc.status {
			t.Fatalf("%s: client %q status %d", tc.observation, summary.ClientFamily, summary.HTTPStatus)
		}
		body, _ := json.Marshal(summary)
		if strings.Contains(string(body), "OpenAI") || strings.Contains(string(body), "client") {
			t.Fatalf("raw or derived client data serialized: %s", body)
		}
	}
}
