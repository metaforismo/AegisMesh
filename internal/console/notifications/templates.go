// Package notifications keeps a bounded, per-tenant, in-console inbox derived
// from evidence already in the index and from console state. Nothing is sent
// anywhere: there is no egress, webhook or mail path in this package.
//
// Items persist structured facts only (closed-vocabulary kinds and reasons,
// catalog rule ids, counts, and identifiers that pass strict grammars). Titles
// and summaries are rendered from fixed templates at read time, so attacker-
// controlled observation text (paths, tool names, user agents, campaign labels)
// can never reach them. See ADR-0027.
package notifications

import (
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/metaforismo/aegismesh/internal/rulecatalog"
)

// Stable notification kinds.
const (
	KindCritical   = "critical_observation"
	KindHoneytoken = "honeytoken_replay"
	KindCanary     = "agent_canary"
	KindCampaign   = "new_campaign"
	KindPosture    = "posture_attention"
	KindAccount    = "account_security"
	KindAssignment = "assignment"
)

// Severities, lowest first.
const (
	SeverityInfo     = "info"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Link routes (closed set) the console can open for an item.
const (
	RouteSession       = "session"
	RouteCampaign      = "campaign"
	RouteEvent         = "event"
	RoutePosture       = "posture"
	RouteSettings      = "settings"
	RouteInvestigation = "investigation"
)

// Reasons refine a kind; each is a closed vocabulary word.
const (
	ReasonAttention      = "attention"
	ReasonExpiring       = "expiring"
	ReasonKeyCreated     = "key_created"
	ReasonKeyRevoked     = "key_revoked"
	ReasonRoleChanged    = "role_changed"
	ReasonSessionRevoked = "session_revoked"
	ReasonAssigned       = "assigned"
)

var kinds = []string{KindCritical, KindHoneytoken, KindCanary, KindCampaign, KindPosture, KindAccount, KindAssignment}

// Kinds returns every kind in display order.
func Kinds() []string { return append([]string{}, kinds...) }

// ValidKind reports whether kind is one of the stable kinds.
func ValidKind(kind string) bool {
	for _, known := range kinds {
		if known == kind {
			return true
		}
	}
	return false
}

// Rank orders severities; unknown values rank zero.
func Rank(severity string) int {
	switch severity {
	case SeverityInfo:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	}
	return 0
}

var (
	rulePattern          = regexp.MustCompile(`^[A-Z]{2,4}-[0-9]{3}$`)
	campaignPattern      = regexp.MustCompile(`^cmp_[0-9a-f]{12}$`)
	checkPattern         = regexp.MustCompile(`^POS-[0-9]{3}$`)
	investigationPattern = regexp.MustCompile(`^inv_[A-Za-z0-9_-]{43}$`)
	sessionPattern       = regexp.MustCompile(`^[0-9a-f]{32}$`)
	eventPattern         = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	// Source keys are observed peer addresses (IPv4, IPv6, host:port shapes).
	sourcePattern = regexp.MustCompile(`^[0-9A-Za-z.:\[\]%_-]{1,64}$`)
	// Sensor and node ids come from configuration or the fleet registry.
	sensorPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// SafeSource returns a source key that may appear in rendered text, or "".
// Keys outside the strict address grammar are never interpolated.
func SafeSource(value string) string {
	if sourcePattern.MatchString(value) {
		return value
	}
	return ""
}

// SafeSensor returns a sensor id that may appear in rendered text, or "".
func SafeSensor(value string) string {
	if sensorPattern.MatchString(value) {
		return value
	}
	return ""
}

// SafeRule returns a rule id only when the trusted catalog knows it.
func SafeRule(value string) string {
	if _, ok := rulecatalog.Lookup(value); ok && rulePattern.MatchString(value) {
		return value
	}
	return ""
}

// Facts are the only per-item values persisted besides counts and times. Every
// field is either a closed-vocabulary word, a strict-grammar identifier or a
// count; Valid rejects anything else.
type Facts struct {
	// RuleID is a catalog rule id.
	RuleID string `json:"rule_id,omitempty"`
	// Source is an observed source key that passed SafeSource.
	Source string `json:"source,omitempty"`
	// Sensor is a sensor id that passed SafeSensor.
	Sensor string `json:"sensor,omitempty"`
	// Campaign is a campaign id.
	Campaign string `json:"campaign,omitempty"`
	// Sessions and Sources count campaign members at first sight.
	Sessions int `json:"sessions,omitempty"`
	Sources  int `json:"sources,omitempty"`
	// Check is a posture check id.
	Check string `json:"check,omitempty"`
	// Until is an acceptance expiry (RFC 3339, UTC).
	Until string `json:"until,omitempty"`
	// Investigation is an investigation id.
	Investigation string `json:"investigation,omitempty"`
	// Reason refines the kind (closed vocabulary).
	Reason string `json:"reason,omitempty"`
	// ByOther is true when someone other than the affected principal acted.
	ByOther bool `json:"by_other,omitempty"`
	// Overflow marks the per-kind item that absorbs rate-limited candidates.
	Overflow bool `json:"overflow,omitempty"`
}

// Valid reports whether every present fact satisfies its grammar.
func (f Facts) Valid() bool {
	check := func(value string, valid func(string) bool) bool { return value == "" || valid(value) }
	if !check(f.RuleID, func(v string) bool { return SafeRule(v) != "" }) ||
		!check(f.Source, func(v string) bool { return SafeSource(v) != "" }) ||
		!check(f.Sensor, func(v string) bool { return SafeSensor(v) != "" }) ||
		!check(f.Campaign, campaignPattern.MatchString) ||
		!check(f.Check, checkPattern.MatchString) ||
		!check(f.Investigation, investigationPattern.MatchString) {
		return false
	}
	if f.Until != "" {
		if _, err := time.Parse(time.RFC3339, f.Until); err != nil {
			return false
		}
	}
	if f.Sessions < 0 || f.Sources < 0 || f.Sessions > 1<<20 || f.Sources > 1<<20 {
		return false
	}
	switch f.Reason {
	case "", ReasonAttention, ReasonExpiring, ReasonKeyCreated, ReasonKeyRevoked, ReasonRoleChanged,
		ReasonSessionRevoked, ReasonAssigned:
		return true
	}
	return false
}

func validLink(link Link) bool {
	if link.Node != "" && !eventPattern.MatchString(link.Node) {
		return false
	}
	switch link.Route {
	case RouteEvent:
		return eventPattern.MatchString(link.ID)
	case RouteSession:
		return sessionPattern.MatchString(link.ID)
	case RouteCampaign:
		return campaignPattern.MatchString(link.ID)
	case RoutePosture:
		return link.ID == "" || checkPattern.MatchString(link.ID)
	case RouteSettings:
		return link.ID == "" || link.ID == "keys" || link.ID == "sessions" || link.ID == "profile"
	case RouteInvestigation:
		return investigationPattern.MatchString(link.ID)
	}
	return false
}

func plural(count int, one, many string) string {
	if count == 1 {
		return "1 " + one
	}
	return strconv.Itoa(count) + " " + many
}

func orUnknown(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// kindLabel is the fixed noun used in overflow summaries.
func kindLabel(kind string) string {
	switch kind {
	case KindCritical:
		return "high-severity finding"
	case KindHoneytoken:
		return "decoy credential"
	case KindCanary:
		return "agent canary"
	case KindCampaign:
		return "new campaign"
	}
	return "other"
}

// Render composes the title and summary of an item from fixed templates. Only
// validated facts and integer counts are interpolated.
func Render(kind, severity string, facts Facts, count int) (string, string) {
	if !facts.Valid() {
		return "Notification", "This notification could not be rendered."
	}
	source := orUnknown(facts.Source, "an unrecognised source")
	sensor := orUnknown(facts.Sensor, "an unnamed sensor")
	rule := orUnknown(facts.RuleID, "a catalog rule")
	if facts.Overflow {
		return "More notifications than the inbox limit",
			fmt.Sprintf("%s were folded into this item because more than %d new notifications per minute were derived for this tenant. The observations remain in the event list.",
				plural(count, kindLabel(kind)+" notification", kindLabel(kind)+" notifications"), ObservationBudget)
	}
	observations := plural(count, "observation", "observations")
	switch kind {
	case KindCritical:
		title := "High-severity finding: " + rule
		if severity == SeverityCritical {
			title = "Critical finding: " + rule
		}
		return title, fmt.Sprintf("%s matched %s from source %s on sensor %s. Repeats from the same source within 10 minutes are counted here.",
			rule, observations, source, sensor)
	case KindHoneytoken:
		title := "Planted decoy credential seen inbound"
		if facts.RuleID == "COR-008" {
			title = "Planted key replayed on a second sensor"
		}
		return title, fmt.Sprintf("%s matched %s from source %s on sensor %s. The marker is operator-owned; its use is an observation, not proof of who used it.",
			rule, observations, source, sensor)
	case KindCanary:
		return "Agent canary marker observed", fmt.Sprintf("%s matched %s from source %s on sensor %s. This does not prove an LLM client.",
			rule, observations, source, sensor)
	case KindCampaign:
		return "New campaign observed", fmt.Sprintf("Campaign %s groups %s from %s that share a step sequence. Shared behaviour does not prove a shared operator.",
			orUnknown(facts.Campaign, "(unknown)"), plural(facts.Sessions, "session", "sessions"), plural(facts.Sources, "source", "sources"))
	case KindPosture:
		check := orUnknown(facts.Check, "A posture check")
		if facts.Reason == ReasonExpiring {
			return "Posture acceptance expires soon", fmt.Sprintf("The accepted risk for %s expires at %s; the check returns to attention after that unless it is accepted again.",
				check, orUnknown(facts.Until, "an unknown time"))
		}
		return "Posture check needs attention", fmt.Sprintf("%s is newly in attention. Review the posture page for the recommendation.", check)
	case KindAccount:
		actor := "You"
		if facts.ByOther {
			actor = "An administrator"
		}
		tail := " If you did not expect this, contact an administrator."
		switch facts.Reason {
		case ReasonKeyCreated:
			return "API key created for your account", actor + " created an API key for your account." + tail
		case ReasonKeyRevoked:
			return "API key revoked on your account", actor + " revoked an API key of your account; sessions opened with it have ended." + tail
		case ReasonRoleChanged:
			return "Your role was changed", actor + " changed the role or access of your account; your existing sessions have ended." + tail
		case ReasonSessionRevoked:
			return "One of your sessions was ended", actor + " ended one of your console sessions." + tail
		}
		return "Account change", actor + " changed your account." + tail
	case KindAssignment:
		return "Investigation assigned to you", fmt.Sprintf("Investigation %s was assigned to you. Its activity log lists who changed what.",
			orUnknown(facts.Investigation, "(unknown)"))
	}
	return "Notification", "This notification could not be rendered."
}
