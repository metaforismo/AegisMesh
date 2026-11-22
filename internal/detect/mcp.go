package detect

// MCP observation identifiers append to the detection registry.
const (
	RuleMCPSecret RuleID = "MCP-001"
	RuleMCPDepth  RuleID = "MCP-002"
	RuleMCPWrite  RuleID = "MCP-003"
)

func mcpRules() []rule {
	return []rule{
		{
			id:         RuleMCPSecret,
			severity:   SevMedium,
			confidence: ConfHigh,
			reason:     "declared synthetic credential content was requested",
			match:      func(in Input, _ string) bool { return in.Protocol == "mcp" && in.MCPSecretRead },
		},
		{
			id:         RuleMCPDepth,
			severity:   SevLow,
			confidence: ConfMedium,
			reason:     "connection reached the configured MCP exploration depth",
			match:      func(in Input, _ string) bool { return in.Protocol == "mcp" && in.MCPDepth },
		},
		{
			id:         RuleMCPWrite,
			severity:   SevMedium,
			confidence: ConfMedium,
			reason:     "write or execution shaped MCP tool was requested; nothing was executed",
			match:      func(in Input, _ string) bool { return in.Protocol == "mcp" && in.MCPWriteAttempt },
		},
	}
}
