package console

import (
	"net/http"

	"github.com/metaforismo/aegismesh/internal/version"
)

func (s *Server) sensors(w http.ResponseWriter, _ *http.Request, _ caller) {
	sensors := s.runtime.ConsoleSensors()
	summaries := s.index.Summaries()
	for i := range sensors {
		sensor := &sensors[i]
		sensor.ByClassification = map[string]int{}
		for _, summary := range summaries {
			if summary.Sensor.ID == sensor.ID {
				sensor.EventsTotal++
				sensor.ByClassification[summary.Classification]++
				if summary.Time > sensor.LastEventAt {
					sensor.LastEventAt = summary.Time
				}
			}
		}
	}

	send(w, 200, map[string]any{"sensors": sensors})
}

func (s *Server) node(w http.ResponseWriter, _ *http.Request, _ caller) {
	node, err := s.runtime.ConsoleNode()
	if err != nil {
		fail(w, 503, "unavailable", "storage metadata is unreadable or exceeds the 65536-entry query limit")
		return
	}

	node.Index = s.index.Stats()
	node.Console = NodeConsole{
		Listen:            s.Addr(),
		TLS:               s.cfg.TLSCertFile != "",
		SessionTTLSeconds: s.cfg.SessionTTLSeconds,
	}

	send(w, 200, node)
}

func (s *Server) meta(w http.ResponseWriter, _ *http.Request, _ caller) {
	send(w, 200, map[string]string{
		"product":     "AegisMesh",
		"api_version": "v1",
		"version":     version.Version,
	})
}

func (s *Server) ruleList(w http.ResponseWriter, _ *http.Request, _ caller) {
	send(w, 200, map[string]any{"rules": s.rules})
}
