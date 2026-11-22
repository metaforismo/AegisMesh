package console

import (
	"net/http"
	"unicode/utf8"

	"github.com/metaforismo/aegismesh/internal/eventexport"
)

func (s *Server) exportEvents(w http.ResponseWriter, r *http.Request, credentials caller) {
	values, ok := query(w, r, "session", "source", "investigation", "window", "format")
	if !ok {
		return
	}
	format := values.Get("format")
	if !eventexport.ValidFormat(format) || !validExportScope(values) {
		invalid(w)
		return
	}
	snapshot, events, ok := s.exportScope(w, r)
	if !ok {
		return
	}
	records, err := s.index.ExportEvidence(events)
	if err != nil {
		fail(w, 503, "unavailable", "selected evidence changed or exceeds export limits; retry with narrower scope")
		return
	}
	body, err := eventexport.Render(records, format)
	if err != nil {
		fail(w, 503, "unavailable", "event export exceeds limits or evidence is invalid; narrow scope")
		return
	}
	target := values.Get("session")
	if target == "" {
		target = values.Get("investigation")
	}
	if s.record(r, credentials.session.Principal, "export.events", target, "ok") != nil {
		fail(w, 503, "unavailable", "audit trail is unavailable")
		return
	}
	setBoundsHeaders(w, snapshot)
	contentType, extension := "text/plain; charset=utf-8", "log"
	if format == "ecs" {
		contentType = "application/x-ndjson"
		extension = "ndjson"
	}
	if format == "otlp-json" {
		contentType = "application/json"
		extension = "json"
	}
	attachment(w, body, contentType, "aegismesh-events-"+format+"."+extension)
}

func validExportScope(values map[string][]string) bool {
	count := 0
	for _, key := range []string{"session", "source", "investigation", "window"} {
		if v, ok := values[key]; ok {
			if len(v) != 1 || v[0] == "" {
				return false
			}
			count++
		}
	}
	source := ""
	if len(values["source"]) > 0 {
		source = values["source"][0]
	}
	return count == 1 && len(source) <= 255 && utf8.ValidString(source)
}
