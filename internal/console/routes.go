package console

import (
	"net/http"

	"github.com/metaforismo/aegismesh/internal/console/permission"
)

// Route access sentinels besides catalogue permission ids.
const (
	// permPublic marks routes that need no authentication.
	permPublic = ""
	// permAuthenticated marks routes any authenticated principal may call,
	// whatever its role grants: its own session, profile and preferences.
	permAuthenticated = "authenticated"
)

// routeSpec declares one route. perm is a catalogue permission id or one of
// the sentinels above; local additionally requires membership of local_tenant
// (instance administration).
type routeSpec struct {
	pattern string
	perm    string
	group   string
	local   bool
	handle  func(*Server, http.ResponseWriter, *http.Request, caller)
}

func (s *Server) routeTable() []routeSpec {
	return append(s.fleetRoutes(), []routeSpec{
		{pattern: "GET /api/v1/export/events", perm: permission.EvidenceExport, group: "event-export", handle: (*Server).exportEvents},
		{pattern: "GET /api/v1/digest", perm: permission.AnalysisRead, group: "digest", handle: (*Server).digest},
		{pattern: "GET /api/v1/decoys", perm: permission.EvidenceRead, group: "decoys", handle: (*Server).decoys},
		{pattern: "GET /api/v1/honeytokens", perm: permission.EvidenceRead, group: "honeytokens", handle: (*Server).honeytokens},
		{pattern: "GET /api/v1/sessions", perm: permission.EvidenceRead, group: "attacker-sessions", handle: (*Server).attackerSessions},
		{pattern: "GET /api/v1/sessions/{id}", perm: permission.EvidenceRead, group: "attacker-sessions", handle: (*Server).attackerSession},
		{pattern: "GET /api/v1/campaigns", perm: permission.EvidenceRead, group: "campaigns", handle: (*Server).campaigns},
		{pattern: "GET /api/v1/campaigns/{id}", perm: permission.EvidenceRead, group: "campaigns", handle: (*Server).campaign},
		{pattern: "POST /api/v1/campaigns/{id}/investigation", perm: permission.InvestigationsWrite, group: "investigations", handle: (*Server).campaignCase},
		{pattern: "POST /api/v1/sessions/{id}/investigation", perm: permission.InvestigationsWrite, group: "investigations", handle: (*Server).sessionCase},
		{pattern: "GET /api/v1/notifications", perm: permAuthenticated, group: "notifications", handle: (*Server).listNotifications},
		{pattern: "POST /api/v1/notifications/read", perm: permAuthenticated, group: "notifications", handle: (*Server).readNotifications},
		{pattern: "GET /api/v1/notifications/stream", perm: permAuthenticated, group: "notification-stream", handle: (*Server).notificationStream},
		{pattern: "GET /api/v1/me/notification-preferences", perm: permAuthenticated, group: "me", handle: (*Server).getNotificationPreferences},
		{pattern: "PUT /api/v1/me/notification-preferences", perm: permAuthenticated, group: "me", handle: (*Server).putNotificationPreferences},
		{pattern: "GET /api/v1/posture", perm: permission.AnalysisRead, group: "posture", handle: (*Server).posture},
		{pattern: "GET /api/v1/coverage", perm: permission.AnalysisRead, group: "coverage", handle: (*Server).coverage},
		{pattern: "GET /api/v1/export/indicators", perm: permission.EvidenceExport, group: "indicator-export", handle: (*Server).exportIndicators},
		{pattern: "GET /api/v1/sessions/{id}/report", perm: permission.ReportsDownload, group: "reports", handle: (*Server).sessionReport},
		{pattern: "GET /api/v1/investigations/{id}/report", perm: permission.ReportsDownload, group: "reports", handle: (*Server).investigationReport},
		{pattern: "GET /api/v1/auth/oidc/login", group: "oidc", handle: (*Server).oidcLogin},
		{pattern: "GET /api/v1/auth/oidc/callback", group: "oidc", handle: (*Server).oidcCallback},
		{pattern: "POST /api/v1/session/tenant", perm: permAuthenticated, group: "session", handle: (*Server).switchTenant},
		{pattern: "GET /api/v1/me", perm: permAuthenticated, group: "me", handle: (*Server).me},
		{pattern: "GET /api/v1/me/preferences", perm: permAuthenticated, group: "me", handle: (*Server).getPreferences},
		{pattern: "PUT /api/v1/me/preferences", perm: permAuthenticated, group: "me", handle: (*Server).putPreferences},
		{pattern: "GET /api/v1/me/sessions", perm: permAuthenticated, group: "me", handle: (*Server).mySessions},
		{pattern: "DELETE /api/v1/me/sessions/{handle}", perm: permAuthenticated, group: "me", handle: (*Server).revokeMySession},
		{pattern: "GET /api/v1/me/keys", perm: permission.KeysSelf, group: "me", handle: (*Server).myKeys},
		{pattern: "POST /api/v1/me/keys", perm: permission.KeysSelf, group: "me", handle: (*Server).createMyKey},
		{pattern: "DELETE /api/v1/me/keys/{key_id}", perm: permission.KeysSelf, group: "me", handle: (*Server).revokeMyKey},
		{pattern: "GET /api/v1/admin/accounts", perm: permission.AccountsRead, group: "admin", handle: (*Server).listAccounts},
		{pattern: "POST /api/v1/admin/accounts", perm: permission.AccountsManage, group: "admin", handle: (*Server).createAccount},
		{pattern: "GET /api/v1/admin/accounts/{id}", perm: permission.AccountsRead, group: "admin", handle: (*Server).getAccount},
		{pattern: "PATCH /api/v1/admin/accounts/{id}", perm: permission.AccountsManage, group: "admin", handle: (*Server).patchAccount},
		{pattern: "POST /api/v1/admin/accounts/{id}/keys", perm: permission.AccountsManage, group: "admin", handle: (*Server).createAccountKey},
		{pattern: "DELETE /api/v1/admin/accounts/{id}/keys/{key_id}", perm: permission.AccountsManage, group: "admin", handle: (*Server).revokeAccountKey},
		{pattern: "GET /api/v1/admin/sessions", perm: permission.AccountsRead, group: "admin", handle: (*Server).adminSessions},
		{pattern: "DELETE /api/v1/admin/sessions/{handle}", perm: permission.SessionsManage, group: "admin", handle: (*Server).revokeAdminSession},
		{pattern: "GET /api/v1/admin/settings", perm: permission.SettingsRead, group: "admin", handle: (*Server).settings},
		{pattern: "GET /api/v1/admin/settings/history", perm: permission.SettingsRead, group: "admin", handle: (*Server).settingsHistory},
		{pattern: "PUT /api/v1/admin/settings/{key}", perm: permission.SettingsManage, group: "admin", handle: (*Server).putSetting},
		{pattern: "DELETE /api/v1/admin/settings/{key}", perm: permission.SettingsManage, group: "admin", handle: (*Server).deleteSetting},
		{pattern: "GET /api/v1/admin/roles", perm: permission.AccountsRead, group: "admin", handle: (*Server).listRoles},
		{pattern: "POST /api/v1/admin/roles", perm: permission.RolesManage, group: "admin", handle: (*Server).createRole},
		{pattern: "GET /api/v1/admin/roles/{id}", perm: permission.AccountsRead, group: "admin", handle: (*Server).getRole},
		{pattern: "PATCH /api/v1/admin/roles/{id}", perm: permission.RolesManage, group: "admin", handle: (*Server).patchRole},
		{pattern: "DELETE /api/v1/admin/roles/{id}", perm: permission.RolesManage, group: "admin", handle: (*Server).deleteRole},
		{pattern: "POST /api/v1/posture/{check_id}/accept", perm: permission.SettingsManage, group: "admin", handle: (*Server).acceptPosture},
		{pattern: "DELETE /api/v1/posture/{check_id}/accept", perm: permission.SettingsManage, group: "admin", handle: (*Server).unacceptPosture},
		{pattern: "GET /api/v1/permissions", perm: permAuthenticated, group: "permissions", handle: (*Server).permissionCatalogue},
		{pattern: "GET /api/v1/admin/audit/export", perm: permission.AuditExport, group: "admin", handle: (*Server).exportAudit},
		{pattern: "GET /api/v1/system", perm: permission.SystemRead, group: "system", handle: (*Server).system},
		{pattern: "GET /api/v1/meta", perm: permPublic, group: "meta", handle: (*Server).meta},
		{pattern: "POST /api/v1/session", perm: permPublic, group: "session", handle: (*Server).login},
		{pattern: "GET /api/v1/session", perm: permAuthenticated, group: "session", handle: (*Server).session},
		{pattern: "DELETE /api/v1/session", perm: permAuthenticated, group: "session", handle: (*Server).logout},
		{pattern: "GET /api/v1/overview", perm: permission.EvidenceRead, group: "overview", handle: (*Server).overview},
		{pattern: "GET /api/v1/events", perm: permission.EvidenceRead, group: "events", handle: (*Server).events},
		{pattern: "GET /api/v1/events/stream", perm: permission.EvidenceRead, group: "stream", handle: (*Server).stream},
		{pattern: "GET /api/v1/events/{id}", perm: permission.EvidenceRead, group: "event", handle: (*Server).eventDetail},
		{pattern: "GET /api/v1/sources", perm: permission.EvidenceRead, group: "sources", handle: (*Server).sources},
		{pattern: "GET /api/v1/sources/{source}", perm: permission.EvidenceRead, group: "source", handle: (*Server).source},
		{pattern: "GET /api/v1/sensors", perm: permission.EvidenceRead, group: "sensors", handle: (*Server).sensors},
		{pattern: "GET /api/v1/rules", perm: permission.EvidenceRead, group: "rules", handle: (*Server).ruleList},
		{pattern: "GET /api/v1/recommendations", perm: permission.AnalysisRead, group: "recommendations", handle: (*Server).recommendations},
		{pattern: "GET /api/v1/node", perm: permission.EvidenceRead, group: "node", handle: (*Server).node},
		{pattern: "GET /api/v1/investigations", perm: permission.InvestigationsRead, group: "investigations", handle: (*Server).listCases},
		{pattern: "POST /api/v1/investigations", perm: permission.InvestigationsWrite, group: "investigations", handle: (*Server).createCase},
		{pattern: "GET /api/v1/investigations/assignees", perm: permission.InvestigationsWrite, group: "investigations", handle: (*Server).assignees},
		{pattern: "GET /api/v1/investigations/{id}", perm: permission.InvestigationsRead, group: "investigations", handle: (*Server).getCase},
		{pattern: "PATCH /api/v1/investigations/{id}", perm: permission.InvestigationsWrite, group: "investigations", handle: (*Server).patchCase},
		{pattern: "POST /api/v1/investigations/{id}/notes", perm: permission.InvestigationsWrite, group: "investigations", handle: (*Server).noteCase},
		{pattern: "PUT /api/v1/investigations/{id}/events/{event_id}", perm: permission.InvestigationsWrite, group: "investigations", handle: (*Server).attachCase},
		{pattern: "DELETE /api/v1/investigations/{id}/events/{event_id}", perm: permission.InvestigationsWrite, group: "investigations", handle: (*Server).attachCase},
		{pattern: "GET /api/v1/audit", perm: permission.AuditRead, group: "audit", handle: (*Server).readAudit},
		{pattern: "GET /api/v1/audit/verify", perm: permission.AuditRead, group: "audit", handle: (*Server).verifyAudit},
	}...)
}

func (s *Server) routes() {
	for _, route := range s.routeTable() {
		s.route(route)
	}

	s.mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		s.requests.Inc("unknown")
		fail(w, 404, "not_found", "API route not found")
	})
	s.mux.HandleFunc("/", s.static)
}
