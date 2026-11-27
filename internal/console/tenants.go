package console

import (
	"crypto/rand"
	"errors"
	"net/http"
	"slices"

	"github.com/metaforismo/aegismesh/internal/console/tenant"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
)

// scopedServer is constructed once from trusted partition names. Request state
// can select an existing value only; it cannot construct stores, paths or configuration.
func (s *Server) scopedServer(name string, opts Options, dir string) (*Server, error) {
	index := opts.Index
	if name != tenant.Local(s.cfg.LocalTenant) {
		var err error
		index = opts.TenantIndexes[name]
		if index == nil {
			index, err = evidenceindex.New(s.cfg.IndexMaxEvents, opts.Meter)
		}
		if err != nil {
			return nil, err
		}
	}
	view := &Server{
		decoyCatalog:    s.decoyCatalog,
		tokenCatalog:    s.tokenCatalog,
		postureFacts:    s.postureFacts,
		unassignedAudit: s.unassignedAudit, cfg: s.cfg, tenantID: name, instanceID: s.instanceID, views: s.views, auth: s.auth, oidc: s.oidc,
		index: index, runtime: s.runtime, rules: s.rules, fleetStatus: s.fleetStatus,
		fleetHub: s.fleetHub.ForTenant(name), listener: s.listener,
		done: s.done, slots: s.slots, streams: s.streams, inboxStreams: s.inboxStreams, clients: s.clients,
		requests: s.requests, failures: s.failures, key: s.key,
		accounts: s.accounts, overlay: s.overlay, live: s.live, log: s.log, security: s.security, settingSources: s.settingSources, startedAt: s.startedAt,
		certExpiry: s.certExpiry, now: s.now, assets: s.assets,
	}
	if _, err := rand.Read(view.key[:]); err != nil {
		return nil, err
	}
	if name != tenant.Local(s.cfg.LocalTenant) {
		view.runtime = absentRuntime{}
		view.rules = []Rule{}
		view.decoyCatalog = []Decoy{}
		view.tokenCatalog = []Honeytoken{}
		view.postureFacts = nil
		view.fleetStatus = func() protocol.Status {
			status := protocol.Status{}
			if view.fleetHub != nil {
				status.Hub.Enabled = true
				status.Hub.AcceptEvidence = view.fleetHub.EvidenceEnabled()
			}
			return status
		}
	}
	if err := view.openState(dir); err != nil {
		view.closeState()
		return nil, err
	}
	return view, nil
}

type absentRuntime struct{}

func (absentRuntime) ConsoleNode() (Node, error) {
	return Node{}, errors.New("local runtime is absent")
}
func (absentRuntime) ConsoleSensors() []Sensor { return []Sensor{} }

func (s *Server) switchTenant(w http.ResponseWriter, r *http.Request, credentials caller) {
	var input struct {
		Tenant string `json:"tenant"`
	}
	if !strictBody(w, r, &input) {
		return
	}
	if !credentials.cookie {
		fail(w, 400, "invalid_argument", "tenant switching requires a browser session")
		return
	}
	if !slices.Contains(credentials.session.Principal.Tenants, input.Tenant) || s.views[input.Tenant] == nil {
		_ = s.record(r, credentials.session.Principal, "session.tenant_switch", "", "denied")
		fail(w, 404, "not_found", "tenant not found")
		return
	}
	id, session, err := s.auth.Switch(credentials.id, input.Tenant)
	if err != nil {
		fail(w, 401, "unauthenticated", "session unavailable")
		return
	}
	// Record the transition only in the departing tenant; the target's audit never
	// receives another tenant's activities. Reauthentication preserves stable identity.
	if s.record(r, credentials.session.Principal, "session.tenant_switch", "", "ok") != nil {
		s.auth.Logout(id)
		fail(w, 503, "unavailable", "audit trail is unavailable")
		return
	}
	s.setSession(w, r, id, session)
	send(w, 200, session)
}

func (s *Server) closeState() {
	if s.cases != nil {
		_ = s.cases.Close()
	}
	if s.inbox != nil {
		_ = s.inbox.Close()
	}
	if s.audit != nil {
		_ = s.audit.Close()
	}
}
