package console

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console/accounts"
	"github.com/metaforismo/aegismesh/internal/console/audit"
	"github.com/metaforismo/aegismesh/internal/eventexport"
	"github.com/metaforismo/aegismesh/internal/fleet/protocol"
)

// SourceRuntime marks observed facts (usage, occupancy, readiness) that are not settings.
const SourceRuntime = "runtime"

const (
	noteRestart = "Change in the config file and restart."
	noteBuiltIn = "Built-in limit; not configurable."
	noteRuntime = "Observed at runtime; not a setting."
)

// settingItem is one read-only, secret-free effective value.
type settingItem struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Value    string `json:"value"`
	Kind     string `json:"kind"`
	Source   string `json:"source"`
	Editable bool   `json:"editable"`
	Note     string `json:"note"`
}

type settingSection struct {
	ID    string        `json:"id"`
	Title string        `json:"title"`
	Items []settingItem `json:"items"`
}

func (s *Server) settingSource(key string) string {
	if s.settingSources == nil {
		return config.SourceConfig
	}
	if source, ok := s.settingSources[key]; ok {
		return source
	}
	return config.SourceDefault
}

// item builds a configurable setting with provenance and a fixed change note.
func (s *Server) item(key, label, value, kind string) settingItem {
	note := noteRestart
	if env := config.SettingSourceKeys[key]; env != "" {
		note = "Change in the config file or the " + env + " environment variable, then restart."
	}
	return settingItem{Key: key, Label: label, Value: value, Kind: kind, Source: s.settingSource(key), Note: note}
}

func fixed(key, label, value, kind string) settingItem {
	return settingItem{Key: key, Label: label, Value: value, Kind: kind, Source: config.SourceDefault, Note: noteBuiltIn}
}

func observed(key, label, value, kind string) settingItem {
	return settingItem{Key: key, Label: label, Value: value, Kind: kind, Source: SourceRuntime, Note: noteRuntime}
}

func onOff(value bool) string {
	if value {
		return "on"
	}
	return "off"
}

// duration renders whole seconds compactly: 8h, 30m, 1h30m, 90s; zero is "off".
func duration(seconds int) string {
	if seconds == 0 {
		return "off"
	}
	text := (time.Duration(seconds) * time.Second).String()
	if strings.HasSuffix(text, "m0s") {
		text = strings.TrimSuffix(text, "0s")
	}
	if strings.HasSuffix(text, "h0m") {
		text = strings.TrimSuffix(text, "0m")
	}
	return text
}

func byteSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return strconv.FormatInt(bytes, 10) + " B"
	}
	value, suffix := float64(bytes), ""
	for _, next := range []string{"KiB", "MiB", "GiB", "TiB"} {
		value /= unit
		suffix = next
		if value < unit {
			break
		}
	}
	return fmt.Sprintf("%.1f %s", value, suffix)
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request, _ caller) {
	if _, ok := query(w, r); !ok {
		return
	}
	// Local configuration and runtime facts live only in the local view.
	local := s.views[s.cfg.LocalTenant]
	cfg := s.cfg
	roles := map[string]int{}
	for _, operator := range s.auth.Operators() {
		roles[operator.Role]++
	}
	managed := s.accounts.List()
	sections := []settingSection{
		{ID: "access", Title: "Access and sessions", Items: []settingItem{
			s.item("console.token_login", "Token sign-in and bearer API keys", onOff(cfg.TokenEnabled()), "boolean"),
			s.item("console.session_ttl_seconds", "Session lifetime", duration(cfg.SessionTTLSeconds), "duration"),
			s.item("console.session_idle_seconds", "Idle timeout", duration(cfg.IdleSeconds()), "duration"),
			fixed("console.login_throttle", "Sign-in throttling", "10 attempts per address per minute", "text"),
			fixed("console.session_capacity", "Session capacity", "1024 per tenant, 32768 in total", "text"),
			s.item("console.operators", "Config-file operators", fmt.Sprintf("%d (%d admin, %d analyst, %d viewer)",
				len(s.auth.Operators()), roles["admin"], roles["analyst"], roles["viewer"]), "count"),
			observed("accounts.managed", "Managed accounts", fmt.Sprintf("%d of %d", len(managed), accounts.MaxAccounts), "count"),
			fixed("accounts.key_lifetime", "API key lifetime", fmt.Sprintf("1..%d days, default %d",
				accounts.MaxKeyDays, accounts.DefaultKeyDays), "text"),
		}},
		{ID: "sso", Title: "Single sign-on", Items: s.ssoItems()},
		{ID: "tenants", Title: "Tenants", Items: []settingItem{
			s.item("console.tenants", "Declared tenants", strings.Join(cfg.Tenants, ", "), "list"),
			s.item("console.local_tenant", "Local tenant", cfg.LocalTenant, "text"),
		}},
		{ID: "listener", Title: "Listener", Items: s.listenerItems()},
		{ID: "evidence", Title: "Evidence", Items: s.evidenceItems(local)},
		{ID: "detection", Title: "Detection", Items: s.detectionItems(local)},
		{ID: "fleet", Title: "Fleet", Items: s.fleetItems(local)},
		{ID: "exports", Title: "Exports", Items: []settingItem{
			fixed("exports.events", "Event export formats", "cef, syslog-rfc5424, otlp-json, ecs; "+
				byteSize(eventexport.MaxBytes)+" per download", "text"),
			fixed("exports.indicators", "Indicator export formats", "stix, csv, txt; proposed for review, never applied", "text"),
			fixed("exports.audit", "Audit export formats", fmt.Sprintf("jsonl, csv; %d records per download",
				audit.MaxExportRecords), "text"),
		}},
	}
	send(w, 200, map[string]any{
		"generated_at": s.now().UTC().Format(time.RFC3339Nano),
		"sections":     sections,
		"editable":     false,
		"note":         "Settings are read-only in the console; the config file stays authoritative.",
	})
}

func (s *Server) ssoItems() []settingItem {
	oidc := s.cfg.OIDC
	items := []settingItem{s.item("console.oidc.enabled", "OIDC sign-in", onOff(oidc.Enabled), "boolean")}
	if !oidc.Enabled {
		return items
	}
	host := ""
	if parsed, err := url.Parse(oidc.Issuer); err == nil {
		host = parsed.Host
	}
	secret := "none (public client with PKCE)"
	switch {
	case oidc.ClientSecretFile != "":
		secret = "file reference (value not shown)"
	case oidc.ClientSecretEnv != "":
		secret = "environment variable (value not shown)"
	}
	discovery := "pending or failing"
	if s.oidc != nil && s.oidc.Ready() {
		discovery = "ready"
	}
	return append(items,
		s.item("console.oidc.issuer", "Issuer host", host, "text"),
		s.item("console.oidc.client_id", "Client ID", oidc.ClientID, "text"),
		s.item("console.oidc.client_secret", "Client secret", secret, "text"),
		s.item("console.oidc.role_claim", "Role claim", oidc.RoleClaim, "text"),
		s.item("console.oidc.tenant_claim", "Tenant claim", oidc.TenantClaim, "text"),
		s.item("console.oidc.role_mapping", "Role mappings", strconv.Itoa(len(oidc.RoleMapping)), "count"),
		s.item("console.oidc.tenant_mapping", "Tenant mappings", strconv.Itoa(len(oidc.TenantMapping)), "count"),
		observed("console.oidc.discovery", "Issuer discovery", discovery, "text"),
	)
}

func (s *Server) listenerItems() []settingItem {
	items := []settingItem{
		s.item("console.listen", "Console address", s.Addr(), "text"),
		s.item("console.tls_cert_file", "TLS", onOff(s.cfg.TLSCertFile != ""), "boolean"),
	}
	if !s.certExpiry.IsZero() {
		items = append(items, observed("console.tls_certificate_expiry", "TLS certificate expires",
			s.certExpiry.Format(time.RFC3339), "timestamp"))
	}
	return append(items,
		s.item("security.allow_public_bind", "Public bind opt-in", onOff(s.security.AllowPublicBind), "boolean"))
}

func (s *Server) evidenceItems(local *Server) []settingItem {
	items := []settingItem{}
	if local != nil && local.runtime != nil {
		if node, err := local.runtime.ConsoleNode(); err == nil {
			items = append(items,
				observed("storage.usage", "Evidence on disk",
					fmt.Sprintf("%s in %d segment(s)", byteSize(node.Storage.Bytes), node.Storage.Segments), "bytes"),
				s.item("storage.encryption", "Encryption at rest", onOff(node.Storage.Encrypted), "boolean"),
				s.item("storage.retention.max_events", "Retention (events)", strconv.Itoa(node.Storage.Retention.MaxEvents), "count"),
				s.item("storage.retention.max_age_days", "Retention (days)", strconv.Itoa(node.Storage.Retention.MaxAgeDays), "count"),
			)
		} else {
			items = append(items, observed("storage.usage", "Evidence on disk", "unavailable", "text"))
		}
	}
	stats := s.index.Stats()
	if local != nil {
		stats = local.index.Stats()
	}
	return append(items,
		s.item("console.index_max_events", "Console index capacity", strconv.Itoa(s.cfg.IndexMaxEvents), "count"),
		observed("console.index_occupancy", "Console index occupancy",
			fmt.Sprintf("%d indexed; history %s", stats.Events, stats.History), "text"),
	)
}

func (s *Server) detectionItems(local *Server) []settingItem {
	if local == nil || local.postureFacts == nil {
		return []settingItem{}
	}
	facts := local.postureFacts
	actions := []string{}
	for severity, action := range facts.Actions {
		if action == "" {
			action = "observe"
		}
		actions = append(actions, severity+"="+action)
	}
	sort.Strings(actions)
	enabled := 0
	for _, rule := range local.rules {
		if rule.Enabled {
			enabled++
		}
	}
	return []settingItem{
		s.item("detection.enabled", "Detection rules", onOff(facts.DetectionEnabled), "boolean"),
		s.item("correlation.enabled", "Correlation rules", onOff(facts.CorrelationEnabled), "boolean"),
		s.item("detection.actions", "Actions by severity", strings.Join(actions, ", "), "text"),
		observed("detection.rules_enabled", "Rules enabled", fmt.Sprintf("%d of %d", enabled, len(local.rules)), "count"),
	}
}

func (s *Server) fleetItems(local *Server) []settingItem {
	status := protocol.Status{}
	if local != nil && local.fleetStatus != nil {
		status = local.fleetStatus()
	}
	return []settingItem{
		s.item("fleet.hub.enabled", "Fleet hub", onOff(status.Hub.Enabled), "boolean"),
		s.item("fleet.hub.accept_evidence", "Hub accepts forwarded evidence", onOff(status.Hub.AcceptEvidence), "boolean"),
		s.item("fleet.agent.enabled", "Fleet agent", onOff(status.Agent.Enabled), "boolean"),
		s.item("fleet.agent.forward_evidence", "Agent forwards evidence", onOff(status.Agent.Forwarding.Enabled), "boolean"),
	}
}
