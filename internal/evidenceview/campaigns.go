package evidenceview

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

// Campaign grouping bounds and rule. See docs/ai-threat-detection.md#campaigns
// and ADR-0024; change both together.
const (
	// MinCampaignSteps is the shortest collapsed step sequence a session needs to join a campaign.
	MinCampaignSteps = 3
	// CampaignPrefixSteps is how many leading collapsed steps form the fingerprint.
	// Sessions with at most this many steps must match exactly.
	CampaignPrefixSteps = 8
	// MinCampaignSources is the number of distinct source keys a campaign needs.
	MinCampaignSources = 2
	// CampaignSessionLimit caps sessions scanned, newest last-seen first.
	CampaignSessionLimit = 4096
	// CampaignListLimit caps campaigns returned by a list.
	CampaignListLimit = 100
	// CampaignSourceLimit caps the sources listed per campaign.
	CampaignSourceLimit = 20
	// CampaignSessionRefLimit caps session IDs and detail sessions per campaign.
	CampaignSessionRefLimit = 50
)

// Basis codes explain why sessions were grouped.
const (
	BasisSameSequence = "same_step_sequence"
	BasisSamePrefix   = "same_step_prefix"
	BasisSameClient   = "same_client_family"
)

// CampaignCaveats are fixed statements included in every campaign detail.
var CampaignCaveats = []string{
	"Shared behaviour does not prove a shared operator; common tools and public scanners produce identical sequences.",
	"Steps are normalised from retained, redacted summaries; identifiers, numbers and long tokens are collapsed, so different requests can share a shape.",
	"Grouping covers only the newest retained analysis sample of this tenant; evicted or older sessions are not compared.",
	"A source key is an observed peer address; NAT, proxies and shared egress can merge or split real clients.",
}

// Campaign groups sessions from different sources whose collapsed step
// sequences share a fingerprint. It is an observation, never attribution.
type Campaign struct {
	ID                  string         `json:"id"`
	Label               string         `json:"label"`
	Basis               []string       `json:"basis"`
	FingerprintSteps    int            `json:"fingerprint_steps"`
	SourceCount         int            `json:"source_count"`
	Sources             []string       `json:"sources"`
	SourcesTruncated    bool           `json:"sources_truncated"`
	SessionCount        int            `json:"session_count"`
	SessionIDs          []string       `json:"session_ids"`
	SessionIDsTruncated bool           `json:"session_ids_truncated"`
	EventCount          int            `json:"event_count"`
	FirstSeen           string         `json:"first_seen"`
	LastSeen            string         `json:"last_seen"`
	SensorKinds         []string       `json:"sensor_kinds"`
	RuleIDs             []string       `json:"rule_ids"`
	MaxSeverity         string         `json:"max_severity"`
	Stages              []string       `json:"stages"`
	ClientFamilies      []string       `json:"client_families"`
	AutomationCounts    map[string]int `json:"automation_counts"`
	members             []Session
}

// CampaignStep is one position of the campaign's representative sequence.
type CampaignStep struct {
	Index      int    `json:"index"`
	SensorKind string `json:"sensor_kind"`
	Shape      string `json:"shape"`
	Stage      string `json:"stage"`
	Sessions   int    `json:"sessions"`
}

// StepMark places one representative step on a member session's timeline.
type StepMark struct {
	Index    int     `json:"index"`
	OffsetMS float64 `json:"offset_ms"`
}

// CampaignSession is a session summary plus the representative steps it performed.
type CampaignSession struct {
	Session
	StepMarks []StepMark `json:"step_marks"`
}

// CampaignDetail adds the representative steps and member session summaries.
type CampaignDetail struct {
	Campaign
	Steps             []CampaignStep    `json:"steps"`
	StepsTruncated    bool              `json:"steps_truncated"`
	Sessions          []CampaignSession `json:"sessions"`
	SessionsTruncated bool              `json:"sessions_truncated"`
	Caveats           []string          `json:"caveats"`
}

// CampaignSet is the full deterministic grouping of one tenant's sessions.
type CampaignSet struct {
	Campaigns       []Campaign
	ScannedSessions int
	// SessionsTruncated reports that more sessions existed than CampaignSessionLimit.
	SessionsTruncated bool
}

// Campaigns groups sessions (as returned by Sessions, newest first). The
// tenant is part of every campaign ID, so equal behaviour in two tenants never
// yields the same identifier, and sessions are never combined across calls.
func Campaigns(tenant string, sessions []Session) CampaignSet {
	set := CampaignSet{Campaigns: []Campaign{}, ScannedSessions: min(len(sessions), CampaignSessionLimit), SessionsTruncated: len(sessions) > CampaignSessionLimit}
	groups := map[string][]Session{}
	order := []string{}
	for _, session := range sessions[:set.ScannedSessions] {
		if len(session.steps) < MinCampaignSteps {
			continue
		}
		key := fingerprint(session.steps)
		if _, seen := groups[key]; !seen {
			order = append(order, key)
		}
		groups[key] = append(groups[key], session)
	}
	for _, key := range order {
		members := groups[key]
		sources := map[string]bool{}
		for _, member := range members {
			sources[member.Source] = true
		}
		if len(sources) < MinCampaignSources {
			continue
		}
		set.Campaigns = append(set.Campaigns, buildCampaign(tenant, key, members, keys(sources)))
	}
	sort.Slice(set.Campaigns, func(i, j int) bool {
		a, b := set.Campaigns[i], set.Campaigns[j]
		if a.LastSeen != b.LastSeen {
			return a.LastSeen > b.LastSeen
		}
		return a.ID < b.ID
	})
	return set
}

// fingerprint is the canonical JSON of the first CampaignPrefixSteps kind/shape pairs.
func fingerprint(steps []step) string {
	pairs := make([][2]string, 0, CampaignPrefixSteps)
	for _, s := range steps[:min(len(steps), CampaignPrefixSteps)] {
		pairs = append(pairs, [2]string{s.kind, s.shape})
	}
	body, _ := json.Marshal(pairs)
	return string(body)
}

// CampaignID derives the stable public identifier for a tenant and fingerprint.
func CampaignID(tenant, key string) string {
	body, _ := json.Marshal([]string{tenant, key})
	digest := sha256.Sum256(body)
	return "cmp_" + hex.EncodeToString(digest[:6])
}

func buildCampaign(tenant, key string, members []Session, sources []string) Campaign {
	c := Campaign{
		ID:               CampaignID(tenant, key),
		FingerprintSteps: min(len(members[0].steps), CampaignPrefixSteps),
		SourceCount:      len(sources),
		Sources:          sources[:min(len(sources), CampaignSourceLimit)],
		SourcesTruncated: len(sources) > CampaignSourceLimit,
		SessionCount:     len(members),
		SessionIDs:       []string{},
		AutomationCounts: map[string]int{AssessmentAgent: 0, AssessmentAutomated: 0, AssessmentHuman: 0, AssessmentInconclusive: 0},
		members:          members,
	}
	kinds, rules, stages, clients := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	sameSequence, sameClient := true, true
	for i, member := range members {
		if i < CampaignSessionRefLimit {
			c.SessionIDs = append(c.SessionIDs, member.ID)
		}
		c.EventCount += member.EventCount
		if c.FirstSeen == "" || member.FirstSeen < c.FirstSeen {
			c.FirstSeen = member.FirstSeen
		}
		if member.LastSeen > c.LastSeen {
			c.LastSeen = member.LastSeen
		}
		for _, kind := range member.SensorKinds {
			kinds[kind] = true
		}
		for _, id := range member.RuleIDs {
			rules[id] = true
		}
		if evidenceindex.Rank(member.MaxSeverity) > evidenceindex.Rank(c.MaxSeverity) {
			c.MaxSeverity = member.MaxSeverity
		}
		for _, s := range member.steps {
			stages[s.stage] = true
		}
		c.AutomationCounts[member.Actor.Assessment]++
		if !sameSteps(member.steps, members[0].steps) {
			sameSequence = false
		}
		if member.client == "" || member.client != members[0].client {
			sameClient = false
		}
		if member.client != "" {
			clients[member.client] = true
		}
	}
	c.SessionIDsTruncated = len(members) > CampaignSessionRefLimit
	c.SensorKinds, c.RuleIDs, c.ClientFamilies = keys(kinds), keys(rules), keys(clients)
	c.Stages = orderedStages(stages)
	c.Basis = []string{BasisSamePrefix}
	if sameSequence {
		c.Basis = []string{BasisSameSequence}
	}
	if sameClient && members[0].client != evidenceindex.ClientOther {
		c.Basis = append(c.Basis, BasisSameClient)
	}
	c.Label = campaignLabel(members[0].steps[:c.FingerprintSteps])
	return c
}

func sameSteps(a, b []step) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].kind != b[i].kind || a[i].shape != b[i].shape {
			return false
		}
	}
	return true
}

var stageOrder = []string{"discovery", "ai_service_abuse", "credential_access", "decoy_credential_replay"}

func orderedStages(present map[string]bool) []string {
	out := []string{}
	for _, stage := range stageOrder {
		if present[stage] {
			out = append(out, stage)
		}
	}
	return out
}

// campaignLabel names the first steps; it is attacker-influenced shape text.
func campaignLabel(steps []step) string {
	parts := []string{}
	for _, s := range steps[:min(len(steps), 3)] {
		parts = append(parts, s.shape)
	}
	label := strings.Join(parts, " → ")
	if len(steps) > 3 {
		label += " → …"
	}
	return evidenceindex.Bound(label, 200)
}

// Detail derives the representative step sequence: for each index, the most
// common kind/shape among members long enough to have it (ties: lexical order).
func (c Campaign) Detail() CampaignDetail {
	d := CampaignDetail{Campaign: c, Steps: []CampaignStep{}, Sessions: []CampaignSession{}, Caveats: append([]string{}, CampaignCaveats...)}
	longest := 0
	for _, member := range c.members {
		longest = max(longest, len(member.steps))
		d.StepsTruncated = d.StepsTruncated || member.stepsTruncated
	}
	for i := 0; i < longest; i++ {
		counts := map[[2]string]int{}
		stage := map[[2]string]string{}
		for _, member := range c.members {
			if i >= len(member.steps) {
				continue
			}
			pair := [2]string{member.steps[i].kind, member.steps[i].shape}
			if counts[pair] == 0 {
				stage[pair] = member.steps[i].stage
			}
			counts[pair]++
		}
		var best [2]string
		for pair, count := range counts {
			if count > counts[best] || count == counts[best] && (pair[0]+"\x00"+pair[1]) < (best[0]+"\x00"+best[1]) {
				best = pair
			}
		}
		d.Steps = append(d.Steps, CampaignStep{Index: i, SensorKind: best[0], Shape: best[1], Stage: stage[best], Sessions: counts[best]})
	}
	for _, member := range c.members[:min(len(c.members), CampaignSessionRefLimit)] {
		item := CampaignSession{Session: member, StepMarks: []StepMark{}}
		for i, s := range member.steps {
			if i < len(d.Steps) && s.kind == d.Steps[i].SensorKind && s.shape == d.Steps[i].Shape {
				offset := float64(s.at.Sub(member.steps[0].at)) / float64(time.Millisecond)
				item.StepMarks = append(item.StepMarks, StepMark{Index: i, OffsetMS: offset})
			}
		}
		d.Sessions = append(d.Sessions, item)
	}
	d.SessionsTruncated = len(c.members) > CampaignSessionRefLimit
	return d
}

// assignCampaigns sets CampaignID on every member of a qualifying campaign.
func assignCampaigns(tenant string, sessions []Session) {
	index := map[string]int{}
	for i := range sessions {
		index[sessions[i].ID] = i
	}
	for _, campaign := range Campaigns(tenant, sessions).Campaigns {
		id := campaign.ID
		for _, member := range campaign.members {
			value := id
			sessions[index[member.ID]].CampaignID = &value
		}
	}
}
