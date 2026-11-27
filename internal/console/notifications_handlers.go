package console

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/metaforismo/aegismesh/internal/console/auth"
	"github.com/metaforismo/aegismesh/internal/console/notifications"
	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/evidenceview"
	"github.com/metaforismo/aegismesh/internal/posture"
)

// Deriver scheduling. Campaign grouping reuses the per-generation analysis
// memo, so it is checked at most every campaignInterval while evidence
// arrives; posture at most every postureInterval.
var (
	campaignInterval = 15 * time.Second
	postureInterval  = time.Minute
	flushInterval    = time.Second
	// expiringWithin is the acceptance horizon for posture_attention items.
	expiringWithin = 7 * 24 * time.Hour
)

// deriver is one tenant view's notification derivation cursor.
type deriver struct {
	mu sync.Mutex
	// ordinal is the newest index append ordinal already examined.
	ordinal uint64
	// start is the persisted high-water mark loaded at start-up: retained
	// observations at or before it were derived by an earlier run.
	start       *notifications.Mark
	campaignGen uint64
	campaignAt  time.Time
	postureAt   time.Time
	flushAt     time.Time
}

func (s *Server) newDeriver() {
	s.derive = &deriver{start: s.inbox.Derive().HighWater}
}

// viewer resolves a principal's permissions at call time for inbox filtering.
func (s *Server) viewer(principal auth.Principal) notifications.Viewer {
	granted := s.grants(principal)
	return notifications.Viewer{ID: principal.ID, Can: granted.has}
}

// runDeriver derives notifications after appends and on a 1 s tick until
// shutdown. It never reads observation payloads, only index summaries.
func (s *Server) runDeriver() {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	s.derivePass(true)
	for {
		select {
		case <-s.done:
			return
		case <-s.index.Appends():
			s.derivePass(false)
		case <-ticker.C:
			s.derivePass(false)
		}
	}
}

func chronological(events []evidenceindex.Summary) {
	sort.SliceStable(events, func(i, j int) bool {
		a, b := evidenceview.Time(events[i]), evidenceview.Time(events[j])
		if !a.Equal(b) {
			return a.Before(b)
		}
		return evidenceview.EventKey(events[i]) < evidenceview.EventKey(events[j])
	})
}

// derivePass examines new appends, then (when due or forced) campaigns and
// posture, and flushes dirty state at most once per flushInterval.
func (s *Server) derivePass(force bool) {
	d := s.derive
	if d == nil || s.inbox == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	wall := s.now().UTC()
	tick := time.Now()

	// At most the analysis bound per pass: a burst beyond it is not derived.
	appended, next := s.index.Appended(d.ordinal, evidenceindex.AnalysisLimit)
	d.ordinal = next
	if len(appended) > 0 {
		chronological(appended)
		state := s.inbox.Derive()
		changed := false
		for _, summary := range appended {
			at, key := evidenceview.Time(summary), evidenceview.EventKey(summary)
			if !d.start.After(at, key) {
				continue
			}
			for _, candidate := range notifications.Observation(summary) {
				s.inbox.Add(candidate, wall)
			}
			if state.HighWater.After(at, key) {
				state.HighWater = &notifications.Mark{Time: at.UTC(), Key: key}
				changed = true
			}
		}
		if changed {
			s.inbox.SetDerive(state)
		}
	}

	if generation := s.index.Generation(); generation != d.campaignGen &&
		(force || tick.Sub(d.campaignAt) >= campaignInterval) {
		d.campaignGen, d.campaignAt = generation, tick
		s.deriveCampaigns(wall)
	}
	if force || tick.Sub(d.postureAt) >= postureInterval {
		d.postureAt = tick
		s.derivePosture(wall)
	}
	if s.inbox.Dirty() && (force || tick.Sub(d.flushAt) >= flushInterval) {
		d.flushAt = tick
		if err := s.inbox.Flush(); err != nil {
			s.log.Warn("console notifications: state not persisted; derived items stay in memory", "tenant", s.tenantID)
		}
	}
}

// deriveCampaigns notifies campaign ids not seen before, oldest first.
func (s *Server) deriveCampaigns(wall time.Time) {
	set := s.analysis().Campaigns()
	state := s.inbox.Derive()
	seen := map[string]bool{}
	for _, id := range state.Campaigns {
		seen[id] = true
	}
	changed := false
	for i := len(set.Campaigns) - 1; i >= 0; i-- {
		campaign := set.Campaigns[i]
		if seen[campaign.ID] {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, campaign.LastSeen)
		if err != nil || at.After(wall) {
			at = wall
		}
		s.inbox.Add(notifications.Campaign(campaign, at), wall)
		state.Campaigns = append(state.Campaigns, campaign.ID)
		seen[campaign.ID], changed = true, true
	}
	if changed {
		s.inbox.SetDerive(state)
	}
}

// derivePosture notifies checks newly in attention (every attention check on
// the first evaluation) and acceptances expiring within seven days.
func (s *Server) derivePosture(wall time.Time) {
	report := s.postureReport()
	state := s.inbox.Derive()
	previous := map[string]bool{}
	for _, id := range state.Attention {
		previous[id] = true
	}
	notified := map[string]bool{}
	for _, key := range state.Expiring {
		notified[key] = true
	}
	attention := []string{}
	for _, check := range report.Checks {
		if check.Status == posture.StatusAttention {
			attention = append(attention, check.ID)
			if !previous[check.ID] {
				s.inbox.Add(notifications.PostureAttention(check.ID, wall), wall)
			}
		}
		if check.Accepted == nil {
			continue
		}
		until, err := time.Parse(time.RFC3339, check.Accepted.Until)
		key := check.ID + "@" + check.Accepted.Until
		if err == nil && until.After(wall) && until.Sub(wall) <= expiringWithin && !notified[key] {
			s.inbox.Add(notifications.PostureExpiring(check.ID, until.UTC().Format(time.RFC3339), wall), wall)
			state.Expiring = append(state.Expiring, key)
		}
	}
	if !state.PostureKnown || !slices.Equal(attention, state.Attention) || len(state.Expiring) != len(notified) {
		state.PostureKnown, state.Attention = true, attention
		s.inbox.SetDerive(state)
	}
}

// notify adds an action-driven item (account_security, assignment) to the
// tenant views the recipient belongs to and persists it at once.
func (s *Server) notify(tenants []string, candidate notifications.Candidate) {
	for _, name := range tenants {
		view := s.views[name]
		if view == nil || view.inbox == nil {
			continue
		}
		view.inbox.Add(candidate, s.now().UTC())
		if err := view.inbox.Flush(); err != nil {
			s.log.Warn("console notifications: state not persisted; item stays in memory", "tenant", name)
		}
	}
}

// accountTenants returns the tenant memberships of a principal id.
func (s *Server) accountTenants(id string) []string {
	for _, info := range s.principals() {
		if info.ID == id {
			return info.Tenants
		}
	}
	return nil
}

func (s *Server) listNotifications(w http.ResponseWriter, r *http.Request, credentials caller) {
	values, ok := query(w, r, "unread", "cursor", "limit", "kind", "severity")
	if !ok {
		return
	}
	filter := notifications.Filter{Kind: values.Get("kind"), Severity: values.Get("severity")}
	switch values.Get("unread") {
	case "", "0", "false":
	case "1", "true":
		filter.Unread = true
	default:
		invalid(w)
		return
	}
	limit, err := limit(values, 50, 200)
	if err != nil || filter.Kind != "" && !notifications.ValidKind(filter.Kind) ||
		filter.Severity != "" && notifications.Rank(filter.Severity) == 0 {
		invalid(w)
		return
	}
	filter.Limit = limit
	if cursor := values.Get("cursor"); cursor != "" {
		seq, valid := notifications.DecodeCursor(cursor)
		if !valid {
			invalid(w)
			return
		}
		filter.Cursor = seq
	}
	page := s.inbox.List(s.viewer(credentials.session.Principal), filter)
	send(w, 200, struct {
		notifications.Page
		Limits map[string]int `json:"limits"`
	}{page, map[string]int{
		"max_items": notifications.MaxItems, "per_minute": notifications.ObservationBudget,
		"per_wall_minute": notifications.WallBudget, "group_window_seconds": int(notifications.GroupWindow / time.Second),
	}})
}

func (s *Server) readNotifications(w http.ResponseWriter, r *http.Request, credentials caller) {
	var body struct {
		IDs    []string `json:"ids"`
		All    bool     `json:"all"`
		Before *string  `json:"before"`
	}
	if !strictBody(w, r, &body) {
		return
	}
	principal := credentials.session.Principal
	now := s.now().UTC()
	viewer := s.viewer(principal)
	var unread int
	var err error
	detail := ""
	switch {
	case body.All && body.IDs == nil:
		before := now
		if body.Before != nil {
			before, err = time.Parse(time.RFC3339Nano, *body.Before)
			if err != nil {
				invalid(w)
				return
			}
		}
		detail = "all before=" + before.UTC().Format(time.RFC3339)
		unread, err = s.inbox.MarkAllRead(viewer, before, now)
	case !body.All && body.Before == nil && len(body.IDs) > 0:
		detail = "ids=" + strconv.Itoa(len(body.IDs))
		unread, err = s.inbox.MarkRead(viewer, body.IDs, now)
	default:
		invalid(w)
		return
	}
	if err == notifications.ErrInvalid {
		invalid(w)
		return
	}
	if !s.inboxAudited(w, r, principal, "notification.read", err, detail) {
		return
	}
	send(w, 200, map[string]int{"unread": unread})
}

// inboxAudited records a read-state or preference change; like audited, it
// answers 503 when either the change or its audit record failed.
func (s *Server) inboxAudited(w http.ResponseWriter, r *http.Request, principal auth.Principal, action string, err error, detail string) bool {
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	if s.recordDetail(r, principal, action, principal.ID, outcome, detail) != nil {
		if err == nil {
			fail(w, 503, "unavailable", "state saved but audit append failed; inspect state before retrying")
		} else {
			fail(w, 503, "unavailable", "audit trail is unavailable")
		}
		return false
	}
	if err != nil {
		fail(w, 503, "unavailable", "notification state could not be persisted")
		return false
	}
	return true
}

func (s *Server) getNotificationPreferences(w http.ResponseWriter, _ *http.Request, credentials caller) {
	send(w, 200, s.inbox.Preferences(credentials.session.Principal.ID))
}

func (s *Server) putNotificationPreferences(w http.ResponseWriter, r *http.Request, credentials caller) {
	var body struct {
		Kinds       map[string]bool `json:"kinds"`
		MinSeverity *string         `json:"min_severity"`
	}
	if !strictBody(w, r, &body) {
		return
	}
	principal := credentials.session.Principal
	next := s.inbox.Preferences(principal.ID)
	for kind, on := range body.Kinds {
		if !notifications.ValidKind(kind) {
			fail(w, 400, "invalid_argument", "unknown notification kind")
			return
		}
		next.Kinds[kind] = on
	}
	if body.MinSeverity != nil {
		next.MinSeverity = *body.MinSeverity
	}
	if notifications.Rank(next.MinSeverity) == 0 || !next.Kinds[notifications.KindAccount] {
		fail(w, 400, "invalid_argument", "unknown severity, or account_security disabled (it cannot be turned off)")
		return
	}
	err := s.inbox.SetPreferences(principal.ID, next, s.now())
	if err == notifications.ErrInvalid {
		invalid(w)
		return
	}
	enabled := 0
	for _, on := range next.Kinds {
		if on {
			enabled++
		}
	}
	if !s.inboxAudited(w, r, principal, "notification.preferences", err,
		fmt.Sprintf("kinds_enabled=%d min_severity=%s", enabled, next.MinSeverity)) {
		return
	}
	send(w, 200, next)
}

// notificationFrame is the SSE `notification` payload.
type notificationFrame struct {
	ID         string             `json:"id"`
	Kind       string             `json:"kind"`
	Severity   string             `json:"severity"`
	Title      string             `json:"title"`
	Summary    string             `json:"summary"`
	CreatedAt  string             `json:"created_at"`
	Link       notifications.Link `json:"link"`
	GroupCount int                `json:"group_count"`
}

// notificationStream is a sibling of the event stream carrying only inbox
// changes: `notification` frames for new visible items, `unread` counts and
// heartbeats. Every frame re-verifies the credential like the event stream;
// item visibility re-resolves the role, so a removed permission stops
// delivery of the items it gated at once.
func (s *Server) notificationStream(w http.ResponseWriter, r *http.Request, credentials caller) {
	if _, valid := query(w, r); !valid {
		return
	}
	select {
	case s.inboxStreams <- struct{}{}:
		defer func() { <-s.inboxStreams }()
	default:
		fail(w, 503, "unavailable", "16 concurrent notification streams maximum")
		return
	}
	feed, cancel, ok := s.inbox.Subscribe()
	if !ok {
		fail(w, 503, "unavailable", "notification stream capacity reached")
		return
	}
	defer cancel()
	s.clients.Add(1)
	defer s.clients.Add(-1)

	controller := http.NewResponseController(w)
	if controller.SetWriteDeadline(time.Now().Add(5*time.Second)) != nil {
		fail(w, 503, "unavailable", "stream deadlines unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)

	write := func(kind string, value any) bool {
		body, err := json.Marshal(value)
		if err != nil || controller.SetWriteDeadline(time.Now().Add(5*time.Second)) != nil {
			return false
		}
		if _, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", kind, body); err != nil {
			return false
		}
		return controller.Flush() == nil
	}
	current := func() (notifications.Viewer, bool) {
		principal, ok := s.streamPrincipal(credentials)
		return s.viewer(principal), ok && principal.ID == credentials.session.Principal.ID
	}
	viewer, ok := current()
	if !ok || !write("unread", map[string]int{"unread": s.inbox.Unread(viewer)}) {
		return
	}

	heartbeat := time.NewTicker(streamHeartbeat)
	defer heartbeat.Stop()
	var expired <-chan time.Time
	var timer *time.Timer
	switch {
	case credentials.cookie:
		timer = time.NewTimer(time.Until(credentials.session.ExpiresAt))
	case !credentials.expires.IsZero():
		timer = time.NewTimer(time.Until(credentials.expires))
	}
	if timer != nil {
		defer timer.Stop()
		expired = timer.C
	}
	for {
		select {
		case <-s.done:
			return
		case <-r.Context().Done():
			return
		case <-expired:
			return
		case event, open := <-feed:
			if !open {
				return
			}
			if viewer, ok = current(); !ok {
				return
			}
			switch {
			case event.Item != nil && s.inbox.Visible(viewer, event.Item):
				view := notifications.Project(*event.Item, false)
				if !write("notification", notificationFrame{
					ID: view.ID, Kind: view.Kind, Severity: view.Severity, Title: view.Title, Summary: view.Summary,
					CreatedAt: view.CreatedAt, Link: view.Link, GroupCount: view.GroupCount,
				}) || !write("unread", map[string]int{"unread": s.inbox.Unread(viewer)}) {
					return
				}
			case event.Item == nil && event.Principal == viewer.ID:
				if !write("unread", map[string]int{"unread": s.inbox.Unread(viewer)}) {
					return
				}
			}
		case tick := <-heartbeat.C:
			if _, ok = current(); !ok {
				return
			}
			if !write("heartbeat", map[string]string{"time": tick.UTC().Format(time.RFC3339Nano)}) {
				return
			}
		}
	}
}
