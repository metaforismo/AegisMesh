package console

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/metaforismo/aegismesh/internal/config"
	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/console/settings"
)

var settingLabels = map[string]string{
	settings.SessionTTL:       "Session lifetime",
	settings.SessionIdle:      "Idle timeout",
	settings.KeyMaxDays:       "Maximum API key lifetime",
	settings.KeyDefaultDays:   "Default API key lifetime",
	settings.SignInBanner:     "Sign-in banner",
	settings.OrganizationName: "Organization name",
	settings.DefaultWindow:    "Default time window",
	settings.PostureAccepted:  "Accepted posture risks",
}

var settingKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)

// display renders a canonical value for people.
func display(definition settings.Definition, value string) string {
	switch definition.Kind {
	case settings.KindSeconds:
		seconds, _ := strconv.Atoi(value)
		return duration(seconds)
	case settings.KindDays:
		return value + " days"
	case settings.KindText:
		if value == "" {
			return "none"
		}
	}
	return value
}

func constraints(definition settings.Definition, maxDays int) map[string]any {
	switch definition.Kind {
	case settings.KindSeconds:
		out := map[string]any{"min": definition.Min, "max": definition.Max, "unit": "s"}
		if definition.AllowZero {
			out["allow_zero"] = true
		}
		return out
	case settings.KindDays:
		upper := definition.Max
		if definition.Key == settings.KeyDefaultDays {
			upper = min(upper, maxDays)
		}
		return map[string]any{"min": definition.Min, "max": upper, "unit": "days"}
	case settings.KindText:
		return map[string]any{"max_len": definition.MaxRunes, "multiline": definition.Multiline}
	default:
		return map[string]any{"enum": slices.Clone(definition.Enum)}
	}
}

// editableItem renders one allowlisted setting with its effective and file values.
func (s *Server) editableItem(key string) settingItem {
	definition, _ := settings.Lookup(key)
	effective, overridden := s.live.snapshot()
	file := settings.FileValues(s.cfg)
	kind := map[string]string{settings.KindSeconds: "duration", settings.KindDays: "count"}[definition.Kind]
	if kind == "" {
		kind = "text"
	}
	item := s.item(key, settingLabels[key], display(definition, effective[key]), kind)
	maxDays, _ := strconv.Atoi(effective[settings.KeyMaxDays])
	item.Effective, item.FileValue = effective[key], file[key]
	item.Constraints = constraints(definition, maxDays)
	item.Constraints["reason_max_len"] = settings.MaxReasonRunes
	item.Applies = "live"
	item.Editable = s.editing() && s.overlay.Problem() == ""
	item.Overridden = slices.Contains(overridden, key)
	if item.Overridden {
		item.Source = SourceConsole
	}
	switch {
	case item.Editable:
		item.Note = "Editable here with settings.manage; reverting restores the config file value."
	case s.editing():
		item.Note = "The settings overlay is unavailable; change the config file and restart."
	default:
		item.Note = "Change in the config file and restart, or set console.settings_editing: console to edit it here."
	}
	return item
}

// acceptedItem summarises accepted posture risks; they are edited through
// POST/DELETE /api/v1/posture/{check_id}/accept, not through PUT.
func (s *Server) acceptedItem() settingItem {
	accepted := []string{}
	if s.editing() {
		for id := range s.overlay.Accepted() {
			accepted = append(accepted, id)
		}
	}
	sort.Strings(accepted)
	value := "none"
	if len(accepted) > 0 {
		value = strconv.Itoa(len(accepted)) + " accepted"
	}
	item := s.item(settings.PostureAccepted, settingLabels[settings.PostureAccepted], value, "list")
	item.Source = config.SourceDefault
	if len(accepted) > 0 {
		item.Source = SourceConsole
	}
	item.Effective, item.FileValue = strings.Join(accepted, ","), ""
	item.Overridden = len(accepted) > 0
	item.Constraints = map[string]any{"max_days": settings.MaxAcceptDays, "reason_max_len": settings.MaxReasonRunes}
	item.Applies = "live"
	item.Editable = s.editing() && s.overlay.Problem() == ""
	item.Note = "Accept or withdraw on the posture review (POST/DELETE /api/v1/posture/{check_id}/accept)."
	return item
}

type settingPut struct {
	Value  json.RawMessage `json:"value"`
	Reason string          `json:"reason"`
}

// settingGate refuses edits while editing is off or for keys outside the
// allowlist; it returns the definition and the audit target.
func (s *Server) settingGate(w http.ResponseWriter, r *http.Request, principal auth.Principal, action string) (settings.Definition, bool) {
	key := r.PathValue("key")
	target := ""
	if settingKeyPattern.MatchString(key) {
		target = key
	}
	refuse := func(status int, code, message string) {
		if s.recordLocal(r, principal, action, target, "denied", code) != nil {
			fail(w, 503, "unavailable", "audit trail is unavailable")
			return
		}
		fail(w, status, code, message)
	}
	if !s.editing() {
		refuse(409, "editing_disabled", "console.settings_editing is off; change the config file and restart")
		return settings.Definition{}, false
	}
	definition, ok := settings.Lookup(key)
	if !ok {
		message := "only the console allowlist can be edited; change this in the config file and restart"
		if key == settings.PostureAccepted {
			message = "accept posture risks with POST /api/v1/posture/{check_id}/accept"
		}
		refuse(409, "not_editable", message)
		return settings.Definition{}, false
	}
	if problem := s.overlay.Problem(); problem != "" {
		fail(w, 503, "unavailable", "settings overlay unavailable: "+problem)
		return settings.Definition{}, false
	}
	return definition, true
}

func (s *Server) putSetting(w http.ResponseWriter, r *http.Request, credentials caller) {
	var body settingPut
	if !strictBody(w, r, &body) {
		return
	}
	principal := credentials.session.Principal
	definition, ok := s.settingGate(w, r, principal, "settings.update")
	if !ok {
		return
	}
	value, err := definition.Parse(body.Value)
	if err != nil {
		fail(w, 400, "invalid_argument", "value must be a JSON integer for numeric settings and a string otherwise")
		return
	}
	if !validReason(body.Reason) {
		fail(w, 400, "invalid_argument", "reason is required: 1..200 printable characters")
		return
	}
	effective, _ := s.live.snapshot()
	maxDays, _ := strconv.Atoi(effective[settings.KeyMaxDays])
	defaultDays, _ := strconv.Atoi(effective[settings.KeyDefaultDays])
	if definition.Check(value, maxDays) != nil {
		fail(w, 400, "invalid_argument", "value is outside the allowed range; see constraints")
		return
	}
	if number, _ := strconv.Atoi(value); definition.Key == settings.KeyMaxDays && number < defaultDays {
		fail(w, 400, "invalid_argument", "key_max_days cannot be below key_default_days; lower the default first")
		return
	}
	from := effective[definition.Key]
	change, err := s.overlay.Set(definition.Key, value, from, body.Reason, settings.Actor{ID: principal.ID, Name: truncate(principal.Name, 80)})
	if err == nil {
		err = s.applySettings(false)
	}
	detail := "from=" + quoteDetail(from, 48) + " to=" + quoteDetail(value, 48) + " seq=" +
		strconv.FormatUint(change.Seq, 10) + " reason=" + quoteDetail(body.Reason, 80)
	if !s.settingAudited(w, r, principal, "settings.update", definition.Key, err, detail) {
		return
	}
	send(w, 200, s.editableItem(definition.Key))
}

func (s *Server) deleteSetting(w http.ResponseWriter, r *http.Request, credentials caller) {
	principal := credentials.session.Principal
	definition, ok := s.settingGate(w, r, principal, "settings.revert")
	if !ok {
		return
	}
	effective, _ := s.live.snapshot()
	file := settings.FileValues(s.cfg)
	from, to := effective[definition.Key], file[definition.Key]
	change, changed, err := s.overlay.Revert(definition.Key, from, to, settings.Actor{ID: principal.ID, Name: truncate(principal.Name, 80)})
	if err == nil {
		err = s.applySettings(false)
	}
	detail := "unchanged"
	if changed {
		detail = "from=" + quoteDetail(from, 48) + " to=" + quoteDetail(to, 48) + " seq=" + strconv.FormatUint(change.Seq, 10)
	}
	if !s.settingAudited(w, r, principal, "settings.revert", definition.Key, err, detail) {
		return
	}
	send(w, 200, s.editableItem(definition.Key))
}

func (s *Server) settingsHistory(w http.ResponseWriter, r *http.Request, _ caller) {
	if _, ok := query(w, r); !ok {
		return
	}
	send(w, 200, map[string]any{"items": s.overlay.History(), "limits": map[string]int{"max_items": settings.MaxHistory}})
}

func validReason(text string) bool {
	return text != "" && strings.TrimSpace(text) == text && len([]rune(text)) <= settings.MaxReasonRunes &&
		!strings.ContainsFunc(text, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// settingAudited records a settings or posture acceptance mutation on the local chain.
func (s *Server) settingAudited(w http.ResponseWriter, r *http.Request, principal auth.Principal, action, target string, err error, detail string) bool {
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	if s.recordLocal(r, principal, action, target, outcome, detail) != nil {
		if err == nil {
			fail(w, 503, "unavailable", "state saved but audit append failed; inspect state before retrying")
		} else {
			fail(w, 503, "unavailable", "audit trail is unavailable")
		}
		return false
	}
	switch {
	case err == nil:
		return true
	case errors.Is(err, settings.ErrInvalid):
		fail(w, 400, "invalid_argument", "invalid value, reason or expiry")
	case errors.Is(err, settings.ErrNotFound):
		fail(w, 404, "not_found", "no acceptance recorded for this check")
	case errors.Is(err, settings.ErrModified):
		fail(w, 503, "unavailable", "settings overlay changed outside this process; restart the console")
	default:
		fail(w, 503, "unavailable", "settings overlay could not be persisted")
	}
	return false
}
