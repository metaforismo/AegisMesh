package console

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

func (s *Server) events(w http.ResponseWriter, r *http.Request, _ caller) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		invalid(w)
		return
	}

	filter, err := evidenceindex.ParseFilter(values)
	if err != nil {
		invalid(w)
		return
	}

	filter.CursorScope = "events"
	page, err := s.index.Query(filter)
	if err != nil {
		invalid(w)
		return
	}

	send(w, 200, page)
}

func (s *Server) eventDetail(w http.ResponseWriter, r *http.Request, _ caller) {
	id := r.PathValue("id")
	if !evidenceindex.ValidID(id) {
		invalid(w)
		return
	}

	summary, envelope, findings, related, ok := s.index.Get(id)
	if !ok {
		fail(w, 404, "not_found", "event is no longer indexed")
		return
	}

	verified := envelope.VerifyIntegrity() == nil
	errText := ""
	if !verified {
		errText = "observation payload hash mismatch"
	}

	cases := []map[string]string{}
	for _, investigation := range s.cases.List("") {
		for _, eventID := range investigation.EventIDs {
			if eventID == id {
				cases = append(cases, map[string]string{
					"id":     investigation.ID,
					"title":  investigation.Title,
					"status": investigation.Status,
				})
			}
		}
	}

	send(w, 200, map[string]any{
		"summary":  summary,
		"envelope": envelope,
		"findings": findings,
		"related":  related,
		"integrity": map[string]any{
			"verified":  verified,
			"algorithm": "sha256",
			"error":     errText,
		},
		"investigations": cases,
	})
}

func (s *Server) stream(w http.ResponseWriter, r *http.Request, credentials caller) {
	if _, ok := query(w, r); !ok {
		return
	}

	select {
	case s.streams <- struct{}{}:
		defer func() {
			<-s.streams
		}()
	default:
		fail(w, 503, "unavailable", "16 concurrent streams maximum")
		return
	}

	observations, cancel, ok := s.index.Subscribe()
	if !ok {
		fail(w, 503, "unavailable", "stream capacity reached")
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
	if controller.Flush() != nil {
		return
	}

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	var expired <-chan time.Time
	var timer *time.Timer
	if credentials.cookie {
		timer = time.NewTimer(time.Until(credentials.session.ExpiresAt))
		defer timer.Stop()
		expired = timer.C
	}

	write := func(kind string, value any) bool {
		body, observation := json.Marshal(value)
		if observation != nil {
			return false
		}
		if controller.SetWriteDeadline(time.Now().Add(5*time.Second)) != nil {
			return false
		}
		if _, observation = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", kind, body); observation != nil {
			return false
		}
		return controller.Flush() == nil
	}

	for {
		select {
		case <-s.done:
			return
		case <-r.Context().Done():
			return
		case <-expired:
			return
		case observation, ok := <-observations:
			if !ok {
				return
			}
			if credentials.cookie {
				if _, ok := s.auth.Session(credentials.id); !ok {
					return
				}
			}
			if !write("observation", observation) {
				return
			}
		case tick := <-heartbeat.C:
			if credentials.cookie {
				if _, ok := s.auth.Session(credentials.id); !ok {
					return
				}
			}
			if !write("heartbeat", map[string]string{"time": tick.UTC().Format(time.RFC3339Nano)}) {
				return
			}
		}
	}
}
