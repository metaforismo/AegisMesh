package console

import (
	"net/http"
	"time"

	"github.com/metaforismo/aegismesh/internal/evidenceindex"
)

func (s *Server) sources(w http.ResponseWriter, r *http.Request, _ caller) {
	values, ok := query(w, r, "window", "limit")
	if !ok {
		return
	}

	duration, _, err := evidenceindex.Window(values.Get("window"))
	count, limitErr := limit(values, 50, 200)
	if err != nil || limitErr != nil {
		invalid(w)
		return
	}

	now := time.Now().UTC()
	sources := s.index.Sources(now.Add(-duration), now)
	if len(sources) > count {
		sources = sources[:count]
	}

	send(w, 200, map[string]any{"sources": sources})
}

func (s *Server) source(w http.ResponseWriter, r *http.Request, _ caller) {
	source := r.PathValue("source")
	if len(source) == 0 || len(source) > 255 {
		invalid(w)
		return
	}

	values, ok := query(w, r, "limit", "cursor")
	if !ok {
		return
	}

	values.Set("source", source)
	filter, err := evidenceindex.ParseFilter(values)
	if err != nil {
		invalid(w)
		return
	}

	filter.CursorScope = "source"
	page, err := s.index.Query(filter)
	if err != nil {
		invalid(w)
		return
	}

	summary := s.index.Source(source, time.Time{}, time.Now().Add(time.Second))

	if summary == nil {
		fail(w, 404, "not_found", "source is no longer indexed")
		return
	}

	send(w, 200, map[string]any{
		"source":      summary,
		"events":      page.Events,
		"next_cursor": page.NextCursor,
	})
}
