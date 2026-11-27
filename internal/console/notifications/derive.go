package notifications

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/evidenceview"
	"github.com/metaforismo/aegismesh/internal/rulecatalog"
)

// MaxPerObservation bounds candidates derived from one observation.
const MaxPerObservation = 3

// sourceGroup keys grouping by source without persisting the raw key: a
// source outside the strict grammar still groups, but only as a digest.
func sourceGroup(source string) string {
	digest := sha256.Sum256([]byte(source))
	return hex.EncodeToString(digest[:8])
}

// Observation derives at most MaxPerObservation candidates from one indexed
// observation: honeytoken_replay for HT-001/COR-008, agent_canary for AGT-001,
// and critical_observation for any other catalog rule of severity high or
// critical. Only catalog ids, the source key and the sensor id (each after a
// strict grammar check) and the event id reach the candidate.
func Observation(summary evidenceindex.Summary) []Candidate {
	at := evidenceview.Time(summary)
	if at.IsZero() || !evidenceindex.ValidID(summary.ID) {
		return nil
	}
	link := Link{Route: RouteEvent, ID: summary.ID}
	if summary.Node != nil {
		link.Node = summary.Node.ID
	}
	facts := Facts{Source: SafeSource(summary.Source), Sensor: SafeSensor(summary.Sensor.ID)}
	out := []Candidate{}
	for _, rule := range summary.RuleIDs {
		if len(out) == MaxPerObservation {
			break
		}
		entry, ok := rulecatalog.Lookup(rule)
		if !ok || SafeRule(rule) == "" {
			continue
		}
		kind, severity := "", ""
		switch {
		case rule == "HT-001" || rule == "COR-008":
			kind, severity = KindHoneytoken, SeverityCritical
		case rule == "AGT-001":
			kind, severity = KindCanary, SeverityHigh
		case entry.Severity == SeverityHigh || entry.Severity == SeverityCritical:
			kind, severity = KindCritical, entry.Severity
		default:
			continue
		}
		ruleFacts := facts
		ruleFacts.RuleID = rule
		out = append(out, Candidate{
			Kind: kind, Severity: severity, At: at, Link: link, Facts: ruleFacts, Perm: PermEvidence, Limited: true,
			GroupKey: kind + "|" + rule + "|" + sourceGroup(summary.Source),
		})
	}
	return out
}

// Campaign derives a new_campaign candidate for a campaign seen for the first time.
func Campaign(campaign evidenceview.Campaign, at time.Time) Candidate {
	return Candidate{
		Kind: KindCampaign, Severity: SeverityMedium, At: at, Perm: PermEvidence, Limited: true,
		GroupKey: KindCampaign + "|" + campaign.ID,
		Link:     Link{Route: RouteCampaign, ID: campaign.ID},
		Facts:    Facts{Campaign: campaign.ID, Sessions: campaign.SessionCount, Sources: campaign.SourceCount},
	}
}

// PostureAttention derives an item for a check newly in attention.
func PostureAttention(check string, at time.Time) Candidate {
	return Candidate{
		Kind: KindPosture, Severity: SeverityMedium, At: at, Perm: PermAnalysis,
		GroupKey: KindPosture + "|" + check + "|" + ReasonAttention,
		Link:     Link{Route: RoutePosture, ID: check},
		Facts:    Facts{Check: check, Reason: ReasonAttention},
	}
}

// PostureExpiring derives an item for an acceptance expiring within 7 days.
func PostureExpiring(check, until string, at time.Time) Candidate {
	return Candidate{
		Kind: KindPosture, Severity: SeverityMedium, At: at, Perm: PermAnalysis,
		GroupKey: KindPosture + "|" + check + "|" + ReasonExpiring + "|" + until,
		Link:     Link{Route: RoutePosture, ID: check},
		Facts:    Facts{Check: check, Reason: ReasonExpiring, Until: until},
	}
}

// Account derives an account_security item for the affected principal only.
func Account(recipient, reason string, byOther bool, at time.Time) Candidate {
	route := "keys"
	if reason == ReasonRoleChanged {
		route = "profile"
	} else if reason == ReasonSessionRevoked {
		route = "sessions"
	}
	return Candidate{
		Kind: KindAccount, Severity: SeverityHigh, At: at, Recipient: recipient,
		GroupKey: KindAccount + "|" + recipient + "|" + reason,
		Link:     Link{Route: RouteSettings, ID: route},
		Facts:    Facts{Reason: reason, ByOther: byOther},
	}
}

// Assignment derives an item for the principal an investigation was assigned to.
func Assignment(recipient, investigation string, at time.Time) Candidate {
	return Candidate{
		Kind: KindAssignment, Severity: SeverityMedium, At: at, Recipient: recipient,
		GroupKey: KindAssignment + "|" + recipient + "|" + investigation,
		Link:     Link{Route: RouteInvestigation, ID: investigation},
		Facts:    Facts{Investigation: investigation, Reason: ReasonAssigned},
	}
}
