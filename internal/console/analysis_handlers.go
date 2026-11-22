package console

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/metaforismo/aegismesh/internal/evidenceindex"
	"github.com/metaforismo/aegismesh/internal/evidenceview"
	"github.com/metaforismo/aegismesh/internal/indicatorexport"
)

type sessionCursor struct {
	Scope  string `json:"s"`
	Digest string `json:"d"`
	Offset int    `json:"o"`
	AsOf   string `json:"t"`
}

func analysisDigest(snapshot evidenceindex.Snapshot, source, window string) string {
	body, _ := json.Marshal(struct {
		Events []evidenceindex.Summary
		Source string
		Window string
	}{snapshot.Events, source, window})
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:16])
}

func (s *Server) attackerSessions(w http.ResponseWriter, r *http.Request, _ caller) {
	values, ok := query(w, r, "window", "source", "limit", "cursor")
	if !ok {
		return
	}
	duration, _, err := evidenceindex.Window(values.Get("window"))
	count, limitErr := limit(values, 50, 200)
	source := values.Get("source")
	if err != nil || limitErr != nil || len(source) > 255 || !utf8.ValidString(source) {
		invalid(w)
		return
	}

	window := values.Get("window")
	if window == "" {
		window = "24h"
	}
	snapshot := s.index.Analysis()
	digest := analysisDigest(snapshot, source, strconv.FormatInt(int64(duration), 10))
	cursor := sessionCursor{Scope: "attacker_sessions", Digest: digest, AsOf: time.Now().UTC().Format(time.RFC3339Nano)}
	if value := values.Get("cursor"); value != "" {
		raw, valid := s.unsign(value)
		if !valid || json.Unmarshal([]byte(raw), &cursor) != nil || cursor.Scope != "attacker_sessions" || cursor.Digest != digest || cursor.Offset < 0 {
			invalid(w)
			return
		}
	}
	asOf, err := time.Parse(time.RFC3339Nano, cursor.AsOf)
	if err != nil {
		invalid(w)
		return
	}

	matched := []evidenceview.Session{}
	for _, session := range evidenceview.Sessions(s.tenantID, snapshot.Events) {
		last, _ := time.Parse(time.RFC3339Nano, session.LastSeen)
		first, _ := time.Parse(time.RFC3339Nano, session.FirstSeen)
		if !last.Before(asOf.Add(-duration)) && !first.After(asOf) && (source == "" || session.Source == source) {
			matched = append(matched, session)
		}
	}
	if cursor.Offset > len(matched) {
		invalid(w)
		return
	}
	end := min(cursor.Offset+count, len(matched))
	next := ""
	if end < len(matched) {
		nextCursor := cursor
		nextCursor.Offset = end
		body, _ := json.Marshal(nextCursor)
		next = s.sign(string(body))
	}
	boundedJSON(w, map[string]any{
		"sessions": matched[cursor.Offset:end], "total_matched": len(matched),
		"next_cursor": next, "as_of": cursor.AsOf, "window": window,
		"bounds": snapshot,
	})
}

func (s *Server) findAttackerSession(w http.ResponseWriter, id string) (evidenceview.Session, evidenceindex.Snapshot, bool) {
	if !evidenceindex.ValidID(id) {
		invalid(w)
		return evidenceview.Session{}, evidenceindex.Snapshot{}, false
	}
	snapshot := s.index.Analysis()
	for _, session := range evidenceview.Sessions(s.tenantID, snapshot.Events) {
		if session.ID == id {
			return session, snapshot, true
		}
	}
	fail(w, 404, "not_found", "session is no longer indexed")
	return evidenceview.Session{}, snapshot, false
}

func (s *Server) attackerSession(w http.ResponseWriter, r *http.Request, _ caller) {
	if _, ok := query(w, r); !ok {
		return
	}
	session, snapshot, ok := s.findAttackerSession(w, r.PathValue("id"))
	if !ok {
		return
	}
	boundedJSON(w, struct {
		evidenceview.Detail
		Bounds evidenceindex.Snapshot `json:"bounds"`
	}{evidenceview.SessionDetail(session), snapshot})
}

func (s *Server) coverage(w http.ResponseWriter, r *http.Request, _ caller) {
	values, ok := query(w, r, "window")
	if !ok {
		return
	}
	duration, _, err := evidenceindex.Window(values.Get("window"))
	if err != nil {
		invalid(w)
		return
	}
	now := time.Now().UTC()
	snapshot := s.index.Analysis()
	boundedJSON(w, map[string]any{
		"frameworks": evidenceview.Coverage(snapshot.Events, now.Add(-duration), now),
		"bounds":     snapshot, "since": now.Add(-duration).Format(time.RFC3339Nano),
		"until":          now.Format(time.RFC3339Nano),
		"interpretation": "Editorial rule relations and retained observations; not technique execution or completeness.",
	})
}

func boundedJSON(w http.ResponseWriter, value any) {
	body, err := json.Marshal(value)
	if err != nil || len(body)+1 > indicatorexport.MaxBytes {
		fail(w, 503, "unavailable", "derived response exceeds 2 MiB; narrow scope or reduce limit")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(200)
	_, _ = w.Write(append(body, '\n'))
}
