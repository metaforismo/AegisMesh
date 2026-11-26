package console

import (
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console/accounts"
	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/console/permission"
	"github.com/metaforismo/aegismesh/internal/console/settings"
	"github.com/metaforismo/aegismesh/internal/posture"
)

// PostureFacts derives the secret-free posture snapshot from the validated
// effective configuration once. Token values, digests, URLs and secret
// references are reduced to booleans, counts and identifiers here.
func PostureFacts(cfg *config.Config) posture.Facts {
	decoys, markers := DecoyCatalog(cfg)
	families := map[string][]string{}
	for _, decoy := range decoys {
		families[decoy.ID] = decoy.SurfaceFamilies
	}
	facts := posture.Facts{
		Sensors:               []posture.Sensor{},
		Honeytokens:           []posture.Token{},
		ConsoleEnabled:        cfg.Console.Enabled,
		ConsoleListen:         cfg.Console.Listen,
		ConsoleTLS:            cfg.Console.TLSCertFile != "",
		TokenLogin:            cfg.Console.TokenEnabled(),
		OIDC:                  cfg.Console.OIDC.Enabled,
		OperatorRoles:         map[string]int{},
		AllowPublicBind:       cfg.Security.AllowPublicBind,
		AllowPrivilegedPorts:  cfg.Security.AllowPrivilegedPorts,
		AllowPrivateLLMEgress: cfg.Security.AllowPrivateLLMEgress,
		LLMProvider:           cfg.LLM.Provider,
		LLMEndpointLoopback:   loopbackURL(cfg.LLM.BaseURL),
		DetectionEnabled:      cfg.Detection.IsEnabled(),
		DetectionDisabled:     append([]string{}, cfg.Detection.DisabledRules...),
		Actions: map[string]string{
			"info": cfg.Detection.Actions.Info, "low": cfg.Detection.Actions.Low,
			"medium": cfg.Detection.Actions.Medium, "high": cfg.Detection.Actions.High,
		},
		CorrelationEnabled:  cfg.Correlation.IsEnabled(),
		CorrelationDisabled: append([]string{}, cfg.Correlation.DisabledRules...),
		Webhook:             cfg.Webhook.IsEnabled(),
		FleetForwarding:     cfg.Fleet.Agent.Enabled && cfg.Fleet.Agent.ForwardEvidence.Enabled,
		FleetHubCAPinned:    cfg.Fleet.Agent.HubCAFile != "",
		EncryptionAtRest:    cfg.Storage.Encryption != nil && cfg.Storage.Encryption.Enabled,
		SettingsEditing:     cfg.Console.WithDefaults().SettingsEditing,
	}
	for _, operator := range cfg.Console.Operators {
		facts.OperatorRoles[operator.Role]++
	}
	for _, sensor := range cfg.Sensors {
		bodyFiles := false
		for _, rule := range sensor.Rules {
			bodyFiles = bodyFiles || rule.BodyFile != ""
		}
		facts.Sensors = append(facts.Sensors, posture.Sensor{
			ID: sensor.ID, Kind: sensor.Kind, Listen: sensor.Listen,
			SurfaceFamilies: append([]string{}, families[sensor.ID]...),
			MCPEnvironment:  sensor.Environment != nil,
			LLMFallback:     sensor.Fallback != nil && sensor.Fallback.Enabled,
			BodyFiles:       bodyFiles,
		})
	}
	for _, marker := range markers {
		facts.Honeytokens = append(facts.Honeytokens, posture.Token{ID: marker.ID, Kind: marker.Kind, Planted: len(marker.SensorIDs) > 0})
	}
	return facts
}

func loopbackURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return false
	}
	host := parsed.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Reasons a posture check cannot currently be accepted in the console.
const (
	acceptPermissionDenied   = "permission_denied"
	acceptEditingDisabled    = "editing_disabled"
	acceptOverlayUnavailable = "overlay_unavailable"
	acceptAlreadyAccepted    = "already_accepted"
	acceptNotAttention       = "not_attention"
)

// PostureCheck is a posture check plus whether this caller can accept its risk now.
type PostureCheck struct {
	posture.Check
	// Acceptable is true when POST /api/v1/posture/{id}/accept by this caller
	// would be admitted now (a valid reason and expiry still required).
	Acceptable bool `json:"acceptable"`
	// AcceptableReason is "" when Acceptable, otherwise one fixed code:
	// permission_denied, editing_disabled, overlay_unavailable,
	// already_accepted or not_attention, checked in that order.
	AcceptableReason string `json:"acceptable_reason"`
}

// PostureResponse is the GET /api/v1/posture body: posture.Report with
// per-check acceptability, fields in the same order.
type PostureResponse struct {
	GeneratedAt string          `json:"generated_at"`
	Scope       string          `json:"scope"`
	Summary     posture.Summary `json:"summary"`
	Checks      []PostureCheck  `json:"checks"`
	Disclaimer  string          `json:"disclaimer"`
	Acceptances string          `json:"acceptances"`
}

func (s *Server) posture(w http.ResponseWriter, r *http.Request, credentials caller) {
	if _, ok := query(w, r); !ok {
		return
	}
	boundedJSON(w, s.postureResponse(s.postureReport(), credentials.session.Principal))
}

// postureResponse adds acceptability with the same gates acceptPosture applies:
// permission, editing, overlay, then the local view's unaccepted status, since
// acceptances are instance-wide and checked against the local configuration.
func (s *Server) postureResponse(report posture.Report, principal auth.Principal) PostureResponse {
	out := PostureResponse{
		GeneratedAt: report.GeneratedAt, Scope: report.Scope, Summary: report.Summary,
		Checks: make([]PostureCheck, 0, len(report.Checks)), Disclaimer: report.Disclaimer, Acceptances: report.Acceptances,
	}
	gate := ""
	switch {
	case !s.grants(principal).has(permission.SettingsManage):
		gate = acceptPermissionDenied
	case !s.editing():
		gate = acceptEditingDisabled
	case s.overlay.Problem() != "":
		gate = acceptOverlayUnavailable
	}
	raw := map[string]string{}
	if gate == "" {
		for _, check := range s.views[s.cfg.LocalTenant].rawPosture().Checks {
			raw[check.ID] = check.Status
		}
	}
	for _, check := range report.Checks {
		reason := gate
		if reason == "" && check.Status == posture.StatusAccepted {
			reason = acceptAlreadyAccepted
		}
		if reason == "" && raw[check.ID] != posture.StatusAttention {
			reason = acceptNotAttention
		}
		out.Checks = append(out.Checks, PostureCheck{Check: check, Acceptable: reason == "", AcceptableReason: reason})
	}
	return out
}

// postureReport evaluates this view's posture with live account, role and
// overlay facts, then applies unexpired acceptances.
func (s *Server) postureReport() posture.Report {
	return posture.Accept(s.rawPosture(), s.acceptances())
}

func (s *Server) rawPosture() posture.Report {
	facts := s.postureFacts
	if facts != nil {
		// Copy the static snapshot and add live facts from the account store and overlay.
		copied := *facts
		copied.ManagedKnown, copied.ManagedAdmins = true, s.accounts.UsableAdmins()
		copied.SettingsManagers, copied.ServiceGrants, copied.ServiceAdmins = s.roleFacts()
		copied.OverlayIgnored, copied.OverlayProblem = s.live.ignoredAtStartup(), s.overlay.Problem()
		facts = &copied
	}
	return posture.Evaluate(facts, posture.FromSnapshot(s.index.SharedAnalysis()), time.Now())
}

// acceptances returns the unexpired acceptances that apply; none while editing is off.
func (s *Server) acceptances() map[string]posture.Acceptance {
	out := map[string]posture.Acceptance{}
	if !s.editing() {
		return out
	}
	for id, acceptance := range s.overlay.Accepted() {
		out[id] = posture.Acceptance{
			By: acceptance.By, ByName: acceptance.ByName, Reason: acceptance.Reason,
			Until: acceptance.Until.UTC().Format(time.RFC3339),
		}
	}
	return out
}

// roleFacts names the roles granting settings.manage and the active service
// accounts whose role grants a high-risk permission.
func (s *Server) roleFacts() ([]string, []string, int) {
	managers := []string{permission.Admin}
	for _, role := range s.accounts.Roles() {
		if slices.Contains(role.Permissions, permission.SettingsManage) {
			managers = append(managers, role.Name)
		}
	}
	grants, admins := []string{}, 0
	for _, account := range s.accounts.List() {
		if account.Kind != "service" || account.Status != accounts.StatusActive {
			continue
		}
		if account.Role == permission.Admin {
			admins++
			continue
		}
		if permission.IsBuiltin(account.Role) {
			continue
		}
		granted := s.grants(auth.Principal{Role: account.Role})
		if slices.ContainsFunc(granted.perms, permission.HighRisk) {
			grants = append(grants, account.Name+" ("+granted.name+")")
		}
	}
	return managers, grants, admins
}

type acceptRequest struct {
	Reason string `json:"reason"`
	Until  string `json:"until"`
}

// postureGate refuses acceptance changes while editing is off or the overlay is unavailable.
func (s *Server) postureGate(w http.ResponseWriter, r *http.Request, principal auth.Principal, action string) (string, bool) {
	id := r.PathValue("check_id")
	if !settings.ValidCheckID(id) || !slices.Contains(posture.IDs(), id) {
		fail(w, 404, "not_found", "posture check not found")
		return "", false
	}
	if !s.editing() {
		if s.recordLocal(r, principal, action, id, "denied", "editing_disabled") != nil {
			fail(w, 503, "unavailable", "audit trail is unavailable")
			return "", false
		}
		fail(w, 409, "editing_disabled", "console.settings_editing is off; posture risks cannot be accepted in the console")
		return "", false
	}
	if problem := s.overlay.Problem(); problem != "" {
		fail(w, 503, "unavailable", "settings overlay unavailable: "+problem)
		return "", false
	}
	return id, true
}

func (s *Server) acceptPosture(w http.ResponseWriter, r *http.Request, credentials caller) {
	var body acceptRequest
	if !strictBody(w, r, &body) {
		return
	}
	principal := credentials.session.Principal
	id, ok := s.postureGate(w, r, principal, "posture.accept")
	if !ok {
		return
	}
	if !validReason(body.Reason) {
		fail(w, 400, "invalid_argument", "reason is required: 1..200 printable characters")
		return
	}
	until, err := time.Parse(time.RFC3339, body.Until)
	now := s.now().UTC()
	if err != nil || !until.After(now) || until.Sub(now) > settings.MaxAcceptDays*24*time.Hour {
		fail(w, 400, "invalid_argument", "until must be an RFC 3339 time in the future, at most 180 days ahead")
		return
	}
	// Acceptances are instance-wide; the local view holds the configuration facts.
	var current *posture.Check
	for _, check := range s.views[s.cfg.LocalTenant].rawPosture().Checks {
		if check.ID == id {
			copied := check
			current = &copied
		}
	}
	if current == nil {
		fail(w, 404, "not_found", "posture check not found")
		return
	}
	if current.Status != posture.StatusAttention {
		fail(w, 409, "conflict", "only checks that currently need attention can be accepted")
		return
	}
	acceptance, _, err := s.overlay.Accept(id, body.Reason, until, settings.Actor{ID: principal.ID, Name: truncate(principal.Name, 80)})
	detail := "until=" + until.UTC().Format(time.RFC3339) + " reason=" + quoteDetail(body.Reason, 120)
	if !s.settingAudited(w, r, principal, "posture.accept", id, err, detail) {
		return
	}
	current.Status = posture.StatusAccepted
	current.Accepted = &posture.Acceptance{
		By: acceptance.By, ByName: acceptance.ByName, Reason: acceptance.Reason,
		Until: acceptance.Until.UTC().Format(time.RFC3339),
	}
	send(w, 200, current)
}

func (s *Server) unacceptPosture(w http.ResponseWriter, r *http.Request, credentials caller) {
	principal := credentials.session.Principal
	id, ok := s.postureGate(w, r, principal, "posture.unaccept")
	if !ok {
		return
	}
	_, err := s.overlay.Unaccept(id, settings.Actor{ID: principal.ID, Name: truncate(principal.Name, 80)})
	if !s.settingAudited(w, r, principal, "posture.unaccept", id, err, "") {
		return
	}
	w.WriteHeader(204)
}
