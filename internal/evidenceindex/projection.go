// Package evidenceindex owns a bounded, disposable projection of stored evidence.
// Observation fields remain untrusted display data; projections never become runtime behavior.
package evidenceindex

import (
	"encoding/json"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/metaforismo/aegismesh/internal/event"
	"github.com/metaforismo/aegismesh/internal/rulecatalog"
)

// Node identifies the authenticated origin outside the native envelope bytes.
type Node struct {
	// ID is the cryptographic fleet identity.
	ID string `json:"id"`
	// Name is resolved from the current registry at read time.
	Name string `json:"name"`
}

// Summary is bounded display metadata derived only from an already stored observation.
type Summary struct {
	// TokenIDs are bounded finding references used for configured marker counts only.
	TokenIDs []string `json:"-"`
	// Node is absent for locally observed events.
	Node *Node `json:"node,omitempty"`
	// ID references the stored envelope.
	ID string `json:"id"`
	// Time is its canonical UTC observation time.
	Time string `json:"time"`
	// Seq is its stored sequence number.
	Seq uint64 `json:"seq"`
	// Sensor identifies the originating sensor using bounded fields.
	Sensor event.SensorRef `json:"sensor"`
	// Classification is the bounded stored observation classification.
	Classification string `json:"classification"`
	// Source is the bounded stored peer or correlation source key.
	Source string `json:"source"`
	// Summary is a sanitized one-line projection of at most 160 characters.
	Summary string `json:"summary"`
	// Severity is the highest associated catalog detection severity.
	Severity string `json:"severity"`
	// RuleIDs contains bounded, deduplicated catalog rule references.
	RuleIDs []string `json:"rule_ids"`
	// Action is a recognized stored detection action; it triggers no enforcement.
	Action string `json:"action"`
}

// Finding contains catalog-authored detection metadata, never attacker-authored explanations.
type Finding struct {
	// RuleID references a known detection rule.
	RuleID string `json:"rule_id"`
	// Severity comes from the trusted rule catalog.
	Severity string `json:"severity"`
	// Confidence is a recognized stored confidence label.
	Confidence string `json:"confidence"`
	// Reason is the catalog summary, never a stored free-text reason.
	Reason string `json:"reason"`
}

// ValidID accepts exactly 16 bytes represented by 32 hexadecimal characters.
func ValidID(value string) bool {
	if len(value) != 32 {
		return false
	}

	for i := range len(value) {
		c := value[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// Bound repairs UTF-8, replaces control characters, and limits text to maxRunes characters.
func Bound(value string, maxRunes int) string {
	// Most stored display fields already satisfy the projection bounds.
	if maxRunes >= 0 && utf8.ValidString(value) {
		count := 0
		clean := true
		for _, c := range value {
			count++
			if count > maxRunes || unicode.IsControl(c) {
				clean = false
				break
			}
		}
		if clean {
			return value
		}
	}
	if len(value) > maxRunes*utf8.UTFMax {
		value = value[:maxRunes*utf8.UTFMax]
	}

	value = strings.ToValidUTF8(value, "")
	var body strings.Builder
	i := 0
	for _, character := range value {
		if i >= maxRunes {
			break
		}
		if unicode.IsControl(character) {
			character = ' '
		}
		body.WriteRune(character)
		i++
	}

	return body.String()
}

// Rank returns the fixed severity ordering; unknown severities rank below info.
func Rank(value string) int {
	switch value {
	case "info":
		return 1
	case "low":
		return 2
	case "medium":
		return 3
	case "high":
		return 4
	case "critical":
		return 5
	}

	return 0
}

func text(fields map[string]json.RawMessage, key string, maxRunes int) string {
	raw := fields[key]
	if len(raw) == 0 {
		return ""
	}
	var value string
	_ = json.Unmarshal(raw, &value)
	return Bound(value, maxRunes)
}

func sourceText(fields map[string]json.RawMessage, key string) string {
	value := text(fields, key, 255)
	if len(value) > 255 {
		value = strings.ToValidUTF8(value[:255], "")
	}

	return value
}

func object(body []byte) map[string]json.RawMessage {
	var fields map[string]json.RawMessage
	if len(body) > 0 && len(body) <= event.MaxStoredEnvelopeBytes {
		_ = json.Unmarshal(body, &fields)
	}

	return fields
}

// Project tolerates arbitrary JSON shapes. Findings use catalog-authored prose.
func Project(envelope event.Envelope) (Summary, []Finding, []string) {
	summary := Summary{
		ID:   Bound(envelope.ID, 32),
		Time: envelope.Time.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
		Seq:  envelope.Seq,
		Sensor: event.SensorRef{
			ID:     Bound(envelope.Sensor.ID, 64),
			Kind:   Bound(envelope.Sensor.Kind, 32),
			Listen: Bound(envelope.Sensor.Listen, 256),
		},
		Classification: Bound(envelope.Classification, 32),
		RuleIDs:        []string{},
	}

	observation := object(envelope.Observation)
	summary.Source = sourceText(observation, "remote_host")
	summary.Summary = observationSummary(summary.Sensor.Kind, envelope.Classification, observation)
	findings := []Finding{}
	related := []string{}
	if envelope.Classification == event.ClassificationCorrelationSignal {
		summary.Source = sourceText(observation, "source_key")
		id := text(observation, "rule_id", 32)
		if rule, ok := rulecatalog.Lookup(id); ok && rule.Family == rulecatalog.FamilyCorrelation {
			summary.RuleIDs = append(summary.RuleIDs, id)
		}
		var ids []json.RawMessage
		if raw := observation["source_event_ids"]; len(raw) > 0 && json.Unmarshal(raw, &ids) == nil {
			for _, raw := range ids[:min(len(ids), 64)] {
				var id string
				if json.Unmarshal(raw, &id) == nil && ValidID(id) {
					related = append(related, id)
				}
			}
		}
	} else {
		detection := object(observation["detection"])
		action := text(detection, "action", 16)
		switch action {
		case "observe", "tag", "throttle", "isolate", "refuse":
			summary.Action = action
		}
		var rawFindings []json.RawMessage
		if raw := detection["findings"]; len(raw) > 0 && json.Unmarshal(raw, &rawFindings) == nil {
			seen := map[string]bool{}
			for _, raw := range rawFindings[:min(len(rawFindings), 128)] {
				finding := object(raw)
				id := text(finding, "rule_id", 32)
				if (id == "HT-001" || id == "AGT-001") && len(summary.TokenIDs) < 128 {
					token := text(finding, "token_id", 64)
					if token != "" {
						summary.TokenIDs = unique(summary.TokenIDs, token)
					}
				}
				rule, ok := rulecatalog.Lookup(id)
				if !ok || rule.Family != rulecatalog.FamilyDetection || seen[id] {
					continue
				}
				seen[id] = true
				summary.RuleIDs = append(summary.RuleIDs, id)
				if Rank(rule.Severity) > Rank(summary.Severity) {
					summary.Severity = rule.Severity
				}
				confidence := text(finding, "confidence", 16)
				switch confidence {
				case "low", "medium", "high":
				default:
					confidence = ""
				}
				findings = append(findings, Finding{
					RuleID:     id,
					Severity:   rule.Severity,
					Confidence: confidence,
					Reason:     rule.Summary,
				})
			}
		}
	}

	summary.Summary = Bound(summary.Summary, 160)
	return summary, findings, related
}
