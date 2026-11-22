package mcpsensor

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/honeytoken"
	"github.com/metaforismo/aegismesh/internal/observe"
	"github.com/metaforismo/aegismesh/internal/policy"
)

func TestSequenceRedactsBeforeTruncation(t *testing.T) {
	token := honeytoken.Token{
		ID:    "long-marker",
		Kind:  honeytoken.Credential,
		Value: strings.Repeat("synthetic-", 24),
	}
	cfg := mcpCfg()
	cfg.Environment = workspace()
	h := &handler{
		cfg: &cfg,
		enf: policy.NewEnforcer(config.Detection{}, observe.NewRegistry(), token),
	}
	params, _ := json.Marshal(map[string]any{"name": token.Value, "arguments": map[string]string{}})
	request := httptest.NewRequest("POST", "http://127.0.0.1/mcp", nil)
	request = request.WithContext(context.WithValue(request.Context(), connectionKey{}, &exploration{}))
	if !h.advance(request, rpcRequest{Method: "tools/call", Params: params}) {
		t.Fatal("advance")
	}
	if len(h.sequence) != 1 || h.sequence[0] != "[honeytoken:long-marker]" {
		t.Fatal("sequence retained a marker prefix")
	}
}
