package correlate

// SignalInfo is static operator-facing metadata for one correlation rule,
// derived from the same summaries that fired signals carry.
type SignalInfo struct {
	ID      RuleID
	Summary string
}

// SignalCatalog derives static metadata from the rule registry. Enum order is
// preserved (COR-001..COR-004); it is part of the published contract and must
// stay stable across releases (append new rules at the end).
func SignalCatalog() []SignalInfo {
	ids := []RuleID{RuleRepeatedInjection, RuleProtocolHopping, RuleToolProbing, RuleSustainedRecon}
	out := make([]SignalInfo, 0, len(ids))
	for _, id := range ids {
		out = append(out, SignalInfo{ID: id, Summary: ruleSummaries[id]})
	}
	return out
}
