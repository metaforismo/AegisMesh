// Package permission is the fixed, versioned console permission catalogue and
// the permission sets of the built-in roles. Every console route declares one
// permission (or none, for routes any authenticated principal may call); a
// principal's role resolves to a set of these ids on every request.
//
// The catalogue is compiled in. Nothing request-supplied adds ids, and custom
// roles may only combine ids listed here.
package permission

import (
	"slices"
	"sort"
)

// Version identifies the catalogue; it changes only when ids are added or split.
const Version = 1

// Risk levels. High means the permission can grant access or change behaviour.
const (
	RiskLow      = "low"
	RiskElevated = "elevated"
	RiskHigh     = "high"
)

// Stable permission ids.
const (
	EvidenceRead        = "evidence.read"
	AnalysisRead        = "analysis.read"
	EvidenceExport      = "evidence.export"
	ReportsDownload     = "reports.download"
	InvestigationsRead  = "investigations.read"
	InvestigationsWrite = "investigations.write"
	AuditRead           = "audit.read"
	AuditExport         = "audit.export"
	FleetRead           = "fleet.read"
	FleetManage         = "fleet.manage"
	AccountsRead        = "accounts.read"
	AccountsManage      = "accounts.manage"
	RolesManage         = "roles.manage"
	SessionsManage      = "sessions.manage"
	SettingsRead        = "settings.read"
	SettingsManage      = "settings.manage"
	SystemRead          = "system.read"
	KeysSelf            = "keys.self"
)

// Built-in role ids. They double as the role names config operators and OIDC
// role mappings use.
const (
	Viewer  = "viewer"
	Analyst = "analyst"
	Admin   = "admin"
)

// Info describes one catalogue entry.
type Info struct {
	ID    string `json:"id"`
	Group string `json:"group"`
	Label string `json:"label"`
	Risk  string `json:"risk"`
}

var catalogue = []Info{
	{EvidenceRead, "Evidence", "Read events, sources, sensors, sessions, campaigns, decoys and node status", RiskLow},
	{AnalysisRead, "Evidence", "Read digest, posture, coverage and recommendations", RiskLow},
	{EvidenceExport, "Evidence", "Download event and indicator exports", RiskElevated},
	{ReportsDownload, "Evidence", "Download session and investigation reports", RiskElevated},
	{InvestigationsRead, "Investigations", "Read investigations and their notes", RiskLow},
	{InvestigationsWrite, "Investigations", "Create and edit investigations, notes and attached evidence", RiskElevated},
	{AuditRead, "Audit", "Read and verify the audit trail", RiskElevated},
	{AuditExport, "Audit", "Download the audit trail", RiskElevated},
	{FleetRead, "Fleet", "Read fleet status and enrolled nodes", RiskLow},
	{FleetManage, "Fleet", "Revoke nodes and manage enrollment tokens", RiskHigh},
	{AccountsRead, "Administration", "List accounts, roles and sessions of every principal", RiskElevated},
	{AccountsManage, "Administration", "Create and change managed accounts and their API keys", RiskHigh},
	{RolesManage, "Administration", "Create, change and delete custom roles", RiskHigh},
	{SessionsManage, "Administration", "End any principal's session", RiskHigh},
	{SettingsRead, "Administration", "Read effective settings and their change history", RiskElevated},
	{SettingsManage, "Administration", "Change console-editable settings and accept posture risks", RiskHigh},
	{SystemRead, "Administration", "Read component and build status", RiskElevated},
	{KeysSelf, "Self-service", "Manage one's own API keys (managed accounts only)", RiskLow},
}

var viewerSet = []string{EvidenceRead, AnalysisRead, InvestigationsRead, FleetRead, KeysSelf}

var analystSet = append(slices.Clone(viewerSet), EvidenceExport, ReportsDownload, InvestigationsWrite)

// Catalogue returns a copy of every permission in catalogue order.
func Catalogue() []Info { return slices.Clone(catalogue) }

// Valid reports whether id is in the catalogue.
func Valid(id string) bool {
	for _, info := range catalogue {
		if info.ID == id {
			return true
		}
	}
	return false
}

// HighRisk reports whether id can grant access or change behaviour.
func HighRisk(id string) bool {
	for _, info := range catalogue {
		if info.ID == id {
			return info.Risk == RiskHigh
		}
	}
	return false
}

// IsBuiltin reports whether role names one of the fixed built-in roles.
func IsBuiltin(role string) bool { return role == Viewer || role == Analyst || role == Admin }

// Builtin returns the sorted permission set of a built-in role, or nil.
func Builtin(role string) []string {
	var set []string
	switch role {
	case Viewer:
		set = viewerSet
	case Analyst:
		set = analystSet
	case Admin:
		set = make([]string, 0, len(catalogue))
		for _, info := range catalogue {
			set = append(set, info.ID)
		}
	default:
		return nil
	}
	return Normalize(set)
}

// Normalize returns a sorted copy without duplicates.
func Normalize(ids []string) []string {
	out := slices.Clone(ids)
	sort.Strings(out)
	return slices.Compact(out)
}

// Administers reports whether a set can both manage accounts and roles: the
// capability the last-administrator guard preserves.
func Administers(ids []string) bool {
	return slices.Contains(ids, AccountsManage) && slices.Contains(ids, RolesManage)
}

// Coherent reports whether a custom permission set respects the combination
// rules: roles.manage and settings.manage require accounts.manage, so a role
// that can change behaviour can also see who holds which access; and
// accounts.manage and sessions.manage require accounts.read, so a role never
// changes principals it cannot list.
func Coherent(ids []string) bool {
	has := func(id string) bool { return slices.Contains(ids, id) }
	if (has(RolesManage) || has(SettingsManage)) && !has(AccountsManage) {
		return false
	}
	if (has(AccountsManage) || has(SessionsManage)) && !has(AccountsRead) {
		return false
	}
	return !has(SettingsManage) || has(SettingsRead)
}
