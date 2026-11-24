package console

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console/audit"
	"github.com/metaforismo/aegismesh/internal/version"
)

type component struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type systemResponse struct {
	Version       string      `json:"version"`
	Commit        string      `json:"commit"`
	BuildDate     string      `json:"build_date"`
	GoVersion     string      `json:"go_version"`
	StartedAt     string      `json:"started_at"`
	UptimeSeconds int64       `json:"uptime_seconds"`
	ConfigSchema  string      `json:"config_schema"`
	Components    []component `json:"components"`
	LicensesURL   string      `json:"licenses_url"`
}

// system reports build metadata and component status derived from live state.
// It reveals no host details beyond what /api/v1/node already returns.
func (s *Server) system(w http.ResponseWriter, r *http.Request, _ caller) {
	if _, ok := query(w, r); !ok {
		return
	}
	local := s.views[s.cfg.LocalTenant]
	build := version.Get()
	now := s.now().UTC()
	response := systemResponse{
		Version: build.Version, Commit: build.Commit, BuildDate: build.BuildDate, GoVersion: build.GoVersion,
		StartedAt: s.startedAt.Format(time.RFC3339Nano), UptimeSeconds: int64(now.Sub(s.startedAt) / time.Second),
		ConfigSchema: config.APIVersionV1Alpha1, Components: []component{},
	}
	if _, ok := s.assets["/licenses"]; ok {
		response.LicensesURL = "/licenses"
	}

	consoleStatus := component{ID: "console", Status: "ok",
		Detail: fmt.Sprintf("serving; %d live session(s)", len(s.auth.Sessions("", "")))}
	if local == nil || !local.audit.Ready() {
		consoleStatus.Status, consoleStatus.Detail = "degraded", "audit trail requires inspection and restart"
	}
	response.Components = append(response.Components, consoleStatus)

	storage := component{ID: "storage", Status: "degraded", Detail: "storage metadata is unreadable"}
	sensors := component{ID: "sensors", Status: "off", Detail: "no sensors configured"}
	index := component{ID: "index", Status: "ok"}
	if local != nil {
		if node, err := local.runtime.ConsoleNode(); err == nil {
			// The runtime start time predates the console listener; prefer it when known.
			if _, err := time.Parse(time.RFC3339Nano, node.StartedAt); err == nil {
				response.StartedAt, response.UptimeSeconds = node.StartedAt, node.UptimeSeconds
			}
			storage.Status = "ok"
			storage.Detail = fmt.Sprintf("%s in %d segment(s); encryption %s",
				byteSize(node.Storage.Bytes), node.Storage.Segments, onOff(node.Storage.Encrypted))
			if !node.Storage.Healthy {
				storage.Status = "degraded"
				storage.Detail = "storage reports an unhealthy append path; check the service log"
			}
			stats := local.index.Stats()
			index.Detail = fmt.Sprintf("%d of %d events; history %s", stats.Events, stats.Capacity, stats.History)
			if stats.History == "unavailable" && !node.Storage.Encrypted {
				index.Status = "degraded"
				index.Detail += " (unreadable history was skipped)"
			}
		}
		list := local.runtime.ConsoleSensors()
		if len(list) > 0 {
			running, failed := 0, 0
			for _, sensor := range list {
				switch sensor.State {
				case "running":
					running++
				case "failed":
					failed++
				}
			}
			sensors.Status = "ok"
			sensors.Detail = fmt.Sprintf("%d of %d running", running, len(list))
			if running != len(list) || failed > 0 {
				sensors.Status = "degraded"
			}
		}
	}
	response.Components = append(response.Components, storage, index, sensors, s.fleetComponent(local), s.oidcComponent(),
		s.settingsComponent())
	send(w, 200, response)
}

func (s *Server) fleetComponent(local *Server) component {
	fleet := component{ID: "fleet", Status: "off", Detail: "hub and agent disabled"}
	if local == nil || local.fleetStatus == nil {
		return fleet
	}
	status := local.fleetStatus()
	parts := []string{}
	if status.Hub.Enabled {
		parts = append(parts, "hub enabled")
	}
	if status.Agent.Enabled {
		agent := "agent enrolled"
		if !status.Agent.Enrolled {
			agent = "agent not enrolled"
		}
		parts = append(parts, agent)
	}
	if len(parts) == 0 {
		return fleet
	}
	fleet.Status, fleet.Detail = "ok", strings.Join(parts, "; ")
	if status.Agent.Enabled && (status.Agent.LastError != "" || !status.Agent.Enrolled) {
		fleet.Status = "degraded"
		if status.Agent.LastError != "" {
			// LastError is a fixed safe category, never hub-authored text.
			fleet.Detail += "; last delivery error: " + status.Agent.LastError
		}
	}
	return fleet
}

func (s *Server) oidcComponent() component {
	switch {
	case !s.cfg.OIDC.Enabled:
		return component{ID: "oidc", Status: "off", Detail: "OIDC sign-in is not configured"}
	case s.oidc != nil && s.oidc.Ready():
		return component{ID: "oidc", Status: "ok", Detail: "issuer discovery succeeded"}
	default:
		return component{ID: "oidc", Status: "degraded", Detail: "issuer discovery pending or failing; token sign-in unaffected"}
	}
}

// settingsComponent reports whether the settings overlay applies.
func (s *Server) settingsComponent() component {
	_, overridden := s.live.snapshot()
	switch {
	case !s.editing():
		return component{ID: "settings", Status: "off", Detail: "settings editing is off; the config file is the only source"}
	case s.overlay.Problem() != "":
		return component{ID: "settings", Status: "degraded", Detail: "overlay not applied: " + s.overlay.Problem()}
	case len(s.live.ignoredAtStartup()) > 0:
		return component{ID: "settings", Status: "degraded", Detail: fmt.Sprintf(
			"%d stored override(s) ignored at startup: %s", len(s.live.ignoredAtStartup()),
			strings.Join(s.live.ignoredAtStartup(), ", "))}
	default:
		return component{ID: "settings", Status: "ok", Detail: fmt.Sprintf("editing on; %d override(s) applied", len(overridden))}
	}
}

// csvCell neutralises spreadsheet formula injection: cells starting with
// = + - @ TAB or CR are prefixed with an apostrophe.
func csvCell(value string) string {
	if value != "" && strings.ContainsRune("=+-@\t\r", rune(value[0])) {
		return "'" + value
	}
	return value
}

var auditCSVHeader = []string{
	"seq", "time", "actor", "actor_id", "role", "action", "target", "outcome", "remote", "detail",
	"issuer", "subject", "prev_hash", "hash",
}

func (s *Server) exportAudit(w http.ResponseWriter, r *http.Request, credentials caller) {
	values, ok := query(w, r, "format", "since")
	if !ok {
		return
	}
	format := values.Get("format")
	if format == "" {
		format = "jsonl"
	}
	var since time.Time
	if raw := values.Get("since"); raw != "" {
		parsed, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			invalid(w)
			return
		}
		since = parsed
	}
	if format != "jsonl" && format != "csv" {
		invalid(w)
		return
	}
	// The disclosure is appended to the exported chain before any byte is sent.
	if s.recordDetail(r, credentials.session.Principal, "audit.export", "", "ok", "format="+format) != nil {
		fail(w, 503, "unavailable", "audit trail is unavailable")
		return
	}
	records, more, err := s.audit.Collect(since, audit.MaxExportRecords)
	if err != nil {
		fail(w, 503, "unavailable", "audit trail is unreadable")
		return
	}
	contentType, extension := "application/x-ndjson", "jsonl"
	if format == "csv" {
		contentType, extension = "text/csv; charset=utf-8", "csv"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="aegismesh-audit-`+s.tenantID+"."+extension+`"`)
	w.Header().Set("X-AegisMesh-Export-Records", strconv.Itoa(len(records)))
	w.Header().Set("X-AegisMesh-Export-Truncated", strconv.FormatBool(more))
	w.WriteHeader(200)
	if format == "jsonl" {
		// Records are re-encoded canonically, so the exported chain verifies like the stored one.
		for _, record := range records {
			line, err := json.Marshal(record)
			if err != nil {
				return
			}
			if _, err = w.Write(append(line, '\n')); err != nil {
				return
			}
		}
		return
	}
	writer := csv.NewWriter(w)
	_ = writer.Write(auditCSVHeader)
	for i, record := range records {
		row := []string{
			strconv.FormatUint(record.Seq, 10), record.Time, record.Actor, record.ActorID, record.Role,
			record.Action, record.Target, record.Outcome, record.Remote, record.Detail, record.Issuer,
			record.Subject, record.PrevHash, record.Hash,
		}
		for j := range row {
			row[j] = csvCell(row[j])
		}
		if writer.Write(row) != nil {
			return
		}
		if i%256 == 255 {
			writer.Flush()
		}
	}
	writer.Flush()
}
