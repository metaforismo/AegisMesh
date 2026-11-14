package evidenceindex

import (
	"encoding/json"
	"fmt"

	"github.com/metaforismo/aegismesh/internal/event"
)

func observationSummary(kind, classification string, fields map[string]json.RawMessage) string {
	fallback := kind + " observation"
	if classification == event.ClassificationCorrelationSignal {
		ruleID := text(fields, "rule_id", 32)
		storedSummary := text(fields, "summary", 160)
		if ruleID != "" && storedSummary != "" {
			return Bound(ruleID+" · "+storedSummary, 160)
		}
		return fallback
	}

	var summary string
	switch kind {
	case "http":
		method := text(fields, "method", 16)
		path := text(fields, "path", 128)
		status, valid := nonnegativeInteger(object(fields["response"]), "status")
		if method != "" && path != "" {
			summary = method + " " + path
			if valid && status >= 100 && status <= 599 {
				summary += fmt.Sprintf(" → %d", status)
			}
		}
	case "mcp":
		summary = text(fields, "method", 64)
		if summary != "" {
			if tool := text(fields, "tool_name", 128); tool != "" {
				summary += " " + tool
			}
		}
	case "ssh":
		outcome := text(fields, "outcome", 64)
		method := text(fields, "auth_method", 32)
		if method == "" {
			method = text(fields, "last_auth_method", 32)
		}
		attempts, valid := nonnegativeInteger(fields, "auth_attempts")
		if outcome != "" && method != "" && valid {
			summary = fmt.Sprintf("auth %s · %d attempts · %s", method, attempts, outcome)
		}
	case "tcp":
		lines, linesValid := nonnegativeInteger(fields, "lines_exchanged")
		bytes, bytesValid := nonnegativeInteger(fields, "bytes_total")
		if linesValid && bytesValid {
			summary = fmt.Sprintf("%d lines · %d B", lines, bytes)
			if ruleID := text(object(fields["response"]), "rule_id", 64); ruleID != "" {
				summary += " · rule " + ruleID
			}
		}
	}

	if summary == "" {
		return fallback
	}
	// All display text is taken from already stored fields and bounded again after joining.
	return Bound(summary, 160)
}

func nonnegativeInteger(fields map[string]json.RawMessage, key string) (int64, bool) {
	var value int64
	raw := fields[key]
	if string(raw) == "null" || len(raw) == 0 {
		return 0, false
	}
	err := json.Unmarshal(raw, &value)
	return value, err == nil && value >= 0
}
