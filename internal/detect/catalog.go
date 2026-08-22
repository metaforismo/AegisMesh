package detect

// RuleInfo is static operator-facing metadata for one detection rule. It is
// derived from the same registry that powers evaluation, so summary text and
// severity can never drift from what findings actually carry.
type RuleInfo struct {
	ID       RuleID
	Severity Severity
	Summary  string
}

// RuleCatalog derives static metadata from the active rule registry.
// Registration order is preserved; it is part of the published contract and
// must stay stable across releases (append new rules at the end).
func RuleCatalog() []RuleInfo {
	rules := allRules(DefaultMaxInputBytes)
	out := make([]RuleInfo, 0, len(rules))
	for _, r := range rules {
		out = append(out, RuleInfo{ID: r.id, Severity: r.severity, Summary: r.reason})
	}
	return out
}
